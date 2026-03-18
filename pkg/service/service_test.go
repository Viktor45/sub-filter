package service

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sub-filter/internal/validator"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
)

// Простой пропускной процессор, используемый в модульных тестах для избежания необходимости реальных
// обработчиков протоколов. Он принимает любую строку и возвращает ее неизменной.
type passthroughProcessor struct{}

func (passthroughProcessor) Matches(_ string) bool             { return true }
func (passthroughProcessor) Process(s string) (string, string) { return s, "" }

func TestNewService(t *testing.T) {
	// Создаем тестовую конфигурацию
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         8080,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
		Cache: config.CacheConfig{
			Directory: "/tmp/test-cache",
			TTL:       30 * time.Minute,
		},
	}

	// Создаем тестовый логгер
	log := logger.NewDefault(logger.ParseLevel("info"))

	// Пустые опции и процессоры
	opts := &ServiceOptions{
		Sources: make(map[string]*config.SafeSource),
		Rules:   make(map[string]validator.Validator),
	}
	// Создаем сервис
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	if svc == nil {
		t.Fatal("Service is nil")
	}

	// Проверяем поля
	if svc.cfg != cfg {
		t.Error("Config not set correctly")
	}
	if svc.logger != log {
		t.Error("Logger not set correctly")
	}
	if svc.regexCache == nil {
		t.Error("Regex cache not initialized")
	}
	if svc.server == nil {
		t.Error("HTTP server not created")
	}
}

func makeSimpleService(t *testing.T) *Service {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: os.TempDir(),
			TTL:       30 * time.Minute,
		},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))
	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator)}
	// Включаем простой пропускной процессор, чтобы Filter/Merge возвращали реальный контент
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	return svc
}

func TestService_GetLimiter(t *testing.T) {
	svc := makeSimpleService(t)

	// Получаем limiter для IP
	limiter := svc.GetLimiter("192.168.1.1")
	if limiter == nil {
		t.Error("Limiter is nil")
	}

	// Получаем тот же limiter еще раз
	limiter2 := svc.GetLimiter("192.168.1.1")
	if limiter != limiter2 {
		t.Error("Same IP should return same limiter")
	}
}

func TestService_IsValidUserAgent(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Validation: config.ValidationConfig{
			AllowedUserAgents: []string{"test-agent"},
		},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))
	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator)}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Тесты валидных User-Agent
	valid := []string{"clash", "happ", "test-agent"}
	for _, ua := range valid {
		if !svc.isValidUserAgent(ua) {
			t.Errorf("User-Agent '%s' should be valid", ua)
		}
	}

	// Тесты невалидных User-Agent
	invalid := []string{"", "invalid", "bad-agent"}
	for _, ua := range invalid {
		if svc.isValidUserAgent(ua) {
			t.Errorf("User-Agent '%s' should be invalid", ua)
		}
	}
}

func TestService_BufferPool(t *testing.T) {
	svc := makeSimpleService(t)

	// Получаем буфер из pool
	buf1 := svc.GetBuffer()
	if buf1 == nil {
		t.Fatal("Buffer is nil")
	}

	// Пишем в буфер
	buf1.WriteString("test data")

	// Возвращаем буфер в pool
	svc.PutBuffer(buf1)

	// Получаем буфер снова - должен быть пустым
	buf2 := svc.GetBuffer()
	if buf2.Len() != 0 {
		t.Errorf("Buffer should be empty after PutBuffer, got length %d", buf2.Len())
	}

	svc.PutBuffer(buf2)
}

func TestService_FilterAndMerge(t *testing.T) {
	// Устанавливаем простой HTTP сервер, который служит ровно одной валидной SS прокси-ссылкой
	// Мы конструируем минимальный userinfo ("cipher:password") закодированный в base64.
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	content := "#comment\nss://" + userinfo + "@example.com:8388#my-server\n#ignored\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, content)
	}))
	defer ts.Close()

	svc := makeSimpleService(t)
	// Добавляем источник
	svc.sources["a"] = &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}

	// Фильтруем без лимита
	res, err := svc.Filter("a", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res), "ss://") || !strings.Contains(string(res), "example.com") {
		t.Errorf("unexpected filter output: %s", string(res))
	}

	// limit=2 должен ограничить максимум двумя неколичественными записями; у нас только
	// одна прокси-ссылка, поэтому ожидаем одну строку назад.
	res2, err := svc.Filter("a", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(res2)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line after limit, got %d", len(lines))
	}

	// Слияние двух источников
	svc.sources["b"] = &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}
	merged, err := svc.Merge([]string{"a", "b"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), "ss://") {
		t.Errorf("unexpected merge output: %s", string(merged))
	}

	// Слияние с лимитом
	merged2, err := svc.Merge([]string{"a", "b"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimSpace(string(merged2)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line after merge limit, got %d", len(lines))
	}
}

func BenchmarkService_BufferPool(b *testing.B) {
	cfg := &config.Config{}
	log := logger.NewDefault(logger.ParseLevel("info"))
	opts := &ServiceOptions{
		Sources:      make(map[string]*config.SafeSource),
		Rules:        make(map[string]validator.Validator),
		BadWordRules: []config.BadWordRule{},
	}
	svc, _ := NewService(cfg, log, opts)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := svc.bufferPool.Get().(*strings.Builder)
		buf.WriteString("test data")
		buf.Reset()
		svc.bufferPool.Put(buf)
	}
}

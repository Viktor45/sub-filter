package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"sub-filter/internal/utils"
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

func TestService_BadWordReplaceAction(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: os.TempDir(),
			TTL:       30 * time.Minute,
		},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))
	opts := &ServiceOptions{
		Sources: make(map[string]*config.SafeSource),
		Rules:   make(map[string]validator.Validator),
		BadWordRules: []config.BadWordRule{
			{Pattern: "fp=chrome", Action: "replace", Replacement: "fp=firefox"},
		},
	}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test")) + "@example.com:8388#fp=chrome"
	matched := false
	for _, processor := range svc.proxyProcessors {
		if processor.Matches(link) {
			matched = true
			processed, reason := processor.Process(link)
			if reason != "" {
				t.Fatalf("processor rejected link: %s", reason)
			}
			if !strings.Contains(processed, "fp=firefox") {
				t.Fatalf("expected fragment replacement, got %q", processed)
			}
			break
		}
	}
	if !matched {
		t.Fatal("expected a processor to match ss:// link")
	}
}

// TestService_ProcessSource_CountryFilter проверяет, что CLI-путь (processSource)
// фильтрует серверы по странам так же, как HTTP-путь (generateProfile).
func TestService_ProcessSource_CountryFilter(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	content := "ss://" + userinfo + "@example.com:8388#Andorra Node\n" +
		"ss://" + userinfo + "@example2.com:8388#France Node\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, content)
	}))
	defer ts.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: t.TempDir(),
			TTL:       30 * time.Minute,
		},
	}
	log := logger.NewDefault(logger.ParseLevel("error"))
	opts := &ServiceOptions{
		Sources: map[string]*config.SafeSource{
			"x": {URL: ts.URL, IP: net.ParseIP("127.0.0.1")},
		},
		Rules: make(map[string]validator.Validator),
		Countries: map[string]utils.CountryInfo{
			"AD": {CCA3: "AND", Flag: "🇦🇩", Name: "Andorra", Native: "Andorra|Principat d'Andorra"},
		},
	}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	result, err := svc.processSource("x", true, []string{"AD"})
	if err != nil {
		t.Fatalf("processSource failed: %v", err)
	}
	if !strings.Contains(result, "Andorra Node") {
		t.Errorf("expected Andorra server to be kept, got:\n%s", result)
	}
	if strings.Contains(result, "France Node") {
		t.Errorf("expected France server to be filtered out, got:\n%s", result)
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
	res, err := svc.Filter("a", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res), "ss://") || !strings.Contains(string(res), "example.com") {
		t.Errorf("unexpected filter output: %s", string(res))
	}

	// limit=2 должен ограничить максимум двумя неколичественными записями; у нас только
	// одна прокси-ссылка, поэтому ожидаем одну строку назад.
	res2, err := svc.Filter("a", nil, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(res2)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line after limit, got %d", len(lines))
	}

	// Слияние двух источников
	svc.sources["b"] = &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}
	merged, err := svc.Merge([]string{"a", "b"}, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), "ss://") {
		t.Errorf("unexpected merge output: %s", string(merged))
	}

	// Слияние с лимитом
	merged2, err := svc.Merge([]string{"a", "b"}, nil, 1, 0)
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
		buf := svc.bufferPool.Get().(*bytes.Buffer)
		buf.WriteString("test data")
		buf.Reset()
		svc.bufferPool.Put(buf)
	}
}

// TestFormatContent_Plain проверяет форматирование без изменений (default behavior)
func TestFormatContent_Plain(t *testing.T) {
	content := []byte("ss://example.com:8388\nvless://example.com:443")
	formatted, contentType, err := formatContent(content, "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if string(formatted) != string(content) {
		t.Errorf("Expected plain content unchanged, got %s", string(formatted))
	}
	if contentType != "text/plain; charset=utf-8" {
		t.Errorf("Expected text/plain content-type, got %s", contentType)
	}
}

// TestFormatContent_YAML проверяет форматирование в YAML
func TestFormatContent_YAML(t *testing.T) {
	content := []byte("ss://dXNlcjpwYXNz@example.com:8388\nvless://uuid@example.com:443?sni=example.com")
	formatted, contentType, err := formatContent(content, "yaml")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(string(formatted), "proxies:") {
		t.Errorf("Expected YAML format with 'proxies:', got %s", string(formatted))
	}
	if !strings.Contains(string(formatted), "type: ss") {
		t.Errorf("Expected SS proxy block in YAML output")
	}
	if !strings.Contains(string(formatted), "type: vless") {
		t.Errorf("Expected VLESS proxy block in YAML output")
	}
	if contentType != "application/x-yaml; charset=utf-8" {
		t.Errorf("Expected application/x-yaml content-type, got %s", contentType)
	}
}

// TestFormatContent_Base64 проверяет кодирование в base64
func TestFormatContent_Base64(t *testing.T) {
	content := []byte("ss://example.com:8388")
	formatted, contentType, err := formatContent(content, "base64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Декодируем и проверяем
	decoded, err := base64.StdEncoding.DecodeString(string(formatted))
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}
	if string(decoded) != string(content) {
		t.Errorf("Decoded content doesn't match original. Got %s, expected %s", string(decoded), string(content))
	}
	if contentType != "application/octet-stream" {
		t.Errorf("Expected application/octet-stream content-type, got %s", contentType)
	}
}

// TestFormatContent_YAMLAndBase64 проверяет комбинированное форматирование
func TestFormatContent_YAMLAndBase64(t *testing.T) {
	content := []byte("ss://dXNlcjpwYXNz@example.com:8388")
	formatted, contentType, err := formatContent(content, "yaml+base64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Декодируем base64
	decoded, err := base64.StdEncoding.DecodeString(string(formatted))
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Проверяем, что это YAML
	if !strings.Contains(string(decoded), "proxies:") {
		t.Errorf("Expected YAML in base64 decoded output")
	}
	if contentType != "application/octet-stream" {
		t.Errorf("Expected application/octet-stream for combined format, got %s", contentType)
	}
}

// TestFormatContent_Invalid проверяет отклонение недопустимых значений format
func TestFormatContent_Invalid(t *testing.T) {
	content := []byte("ss://example.com:8388")
	for _, format := range []string{"json", "xml", "yaml,base64", "yaml+json"} {
		if _, _, err := formatContent(content, format); err == nil {
			t.Errorf("Expected error for format %q, got nil", format)
		}
	}
}

// TestFormatContent_SpaceSeparated проверяет, что разделитель-пробел принимается
// (в query-строке "+" декодируется как пробел, поэтому оба варианта эквивалентны).
func TestFormatContent_SpaceSeparated(t *testing.T) {
	content := []byte("ss://dXNlcjpwYXNz@example.com:8388")
	formatted, contentType, err := formatContent(content, "yaml base64")
	if err != nil {
		t.Fatalf("Unexpected error for space-separated format: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(formatted))
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}
	if !strings.Contains(string(decoded), "proxies:") {
		t.Errorf("Expected YAML in base64 decoded output")
	}
	if contentType != "application/octet-stream" {
		t.Errorf("Expected application/octet-stream, got %s", contentType)
	}
}

// TestContentToYAML проверяет преобразование в YAML и игнорирование комментариев
func TestContentToYAML(t *testing.T) {
	// Тестируем с комментариями и пустыми строками; ссылки в нормализованном виде
	ssLink := "ss://" + utils.EncodeRawURBase64([]byte("2022-blake3-aes-256-gcm:password")) + "@example.com:8388#proxy1"
	content := []byte("# Комментарий\n" + ssLink + "\n\n# Еще комментарий\nvless://uuid@example.com:443?security=tls&sni=example.com#proxy2\n\n")
	yaml := contentToYAML(content)
	yamlStr := string(yaml)

	// Проверяем, что комментарии не включены
	if strings.Contains(yamlStr, "Комментарий") {
		t.Error("Comments should be ignored in YAML output")
	}

	// Проверяем, что YAML содержит заголовок
	if !strings.Contains(yamlStr, "proxies:") {
		t.Error("Expected 'proxies:' key in YAML")
	}

	// Проверяем, что типы прокси указаны правильно
	if !strings.Contains(yamlStr, "type: ss") {
		t.Error("Expected SS proxy type in YAML")
	}
	if !strings.Contains(yamlStr, "type: vless") {
		t.Error("Expected VLESS proxy type in YAML")
	}

	// Проверяем параметры
	if !strings.Contains(yamlStr, "server:") {
		t.Error("Expected server field in YAML")
	}
	if !strings.Contains(yamlStr, "port:") {
		t.Error("Expected port field in YAML")
	}
}

// TestContentToYAML_Empty проверяет минимальный YAML при отсутствии прокси
func TestContentToYAML_Empty(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
	}{
		{"пустой контент", []byte("")},
		{"только комментарии", []byte("# comment\n# another")},
		{"неподдерживаемые схемы", []byte("http://example.com\nftp://example.com")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(contentToYAML(tt.content)); got != "proxies: []" {
				t.Errorf("Expected 'proxies: []', got %q", got)
			}
		})
	}
}

// TestParseProxyToYAML_SS проверяет парсинг нормализованной Shadowsocks ссылки
// (userinfo закодирован в base64, как выдает ss/ss.go)
func TestParseProxyToYAML_SS(t *testing.T) {
	link := "ss://" + utils.EncodeRawURBase64([]byte("2022-blake3-aes-256-gcm:mypassword")) + "@example.com:8388"
	yaml := parseProxyToYAML(link, 0)

	if !strings.Contains(yaml, "type: ss") {
		t.Error("Expected SS type")
	}
	if !strings.Contains(yaml, "server: \"example.com\"") {
		t.Error("Expected correct server")
	}
	if !strings.Contains(yaml, "port: 8388") {
		t.Error("Expected correct port")
	}
	if !strings.Contains(yaml, "cipher: \"2022-blake3-aes-256-gcm\"") {
		t.Errorf("Expected correct cipher, got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "password: \"mypassword\"") {
		t.Errorf("Expected correct password, got:\n%s", yaml)
	}
}

// TestParseProxyToYAML_VLESS проверяет парсинг VLESS прокси с TLS
func TestParseProxyToYAML_VLESS(t *testing.T) {
	link := "vless://myuuid@example.com:443?type=tcp&security=tls&sni=example.com"
	yaml := parseProxyToYAML(link, 0)

	if !strings.Contains(yaml, "type: vless") {
		t.Error("Expected VLESS type")
	}
	if !strings.Contains(yaml, "uuid: \"myuuid\"") {
		t.Error("Expected UUID")
	}
	if !strings.Contains(yaml, "server: \"example.com\"") {
		t.Error("Expected server")
	}
	if !strings.Contains(yaml, "network: \"tcp\"") {
		t.Error("Expected network parameter")
	}
	if !strings.Contains(yaml, "tls: true") {
		t.Error("Expected TLS enabled")
	}
	if !strings.Contains(yaml, "servername: \"example.com\"") {
		t.Error("Expected SNI")
	}
}

// TestParseProxyToYAML_VLESS_Reality проверяет перенос параметров REALITY и ws-транспорта
func TestParseProxyToYAML_VLESS_Reality(t *testing.T) {
	link := "vless://myuuid@example.com:443?security=reality&sni=example.com&pbk=pubkey123&sid=abcd&fp=chrome&type=ws&path=%2Fws&host=cdn.example.com&flow=xtls-rprx-vision"
	yaml := parseProxyToYAML(link, 0)

	for _, want := range []string{
		"tls: true",
		"reality-opts:",
		"public-key: \"pubkey123\"",
		"short-id: \"abcd\"",
		"client-fingerprint: \"chrome\"",
		"network: \"ws\"",
		"ws-opts:",
		"path: \"/ws\"",
		"Host: \"cdn.example.com\"",
		"flow: \"xtls-rprx-vision\"",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("Expected %q in YAML, got:\n%s", want, yaml)
		}
	}
}

// TestParseProxyToYAML_VLESS_GRPC проверяет перенос grpc-транспорта
func TestParseProxyToYAML_VLESS_GRPC(t *testing.T) {
	link := "vless://myuuid@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=grpcsvc"
	yaml := parseProxyToYAML(link, 0)

	for _, want := range []string{"network: \"grpc\"", "grpc-opts:", "grpc-service-name: \"grpcsvc\""} {
		if !strings.Contains(yaml, want) {
			t.Errorf("Expected %q in YAML, got:\n%s", want, yaml)
		}
	}
}

// TestParseProxyToYAML_VMess проверяет парсинг нормализованной VMess ссылки
// (base64-encoded JSON payload, как выдает vmess/vmess.go)
func TestParseProxyToYAML_VMess(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"v": "2", "ps": "test", "add": "example.com", "port": "443",
		"id": "myuuid", "aid": "0", "scy": "auto", "net": "ws",
		"tls": "tls", "sni": "example.com", "path": "/ws", "host": "cdn.example.com",
	})
	if err != nil {
		t.Fatalf("Failed to marshal VMess payload: %v", err)
	}
	link := "vmess://" + base64.StdEncoding.EncodeToString(payload)
	yaml := parseProxyToYAML(link, 0)

	for _, want := range []string{
		"type: vmess",
		"server: \"example.com\"",
		"port: 443",
		"uuid: \"myuuid\"",
		"alterId: 0",
		"cipher: \"auto\"",
		"network: \"ws\"",
		"tls: true",
		"servername: \"example.com\"",
		"ws-opts:",
		"path: \"/ws\"",
		"Host: \"cdn.example.com\"",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("Expected %q in YAML, got:\n%s", want, yaml)
		}
	}
}

// TestParseProxyToYAML_VMess_Invalid проверяет, что невалидный payload пропускается
func TestParseProxyToYAML_VMess_Invalid(t *testing.T) {
	if got := parseProxyToYAML("vmess://!!!not-base64!!!", 0); got != "" {
		t.Errorf("Expected empty result for invalid VMess payload, got:\n%s", got)
	}
}

// TestParseProxyToYAML_Trojan проверяет парсинг Trojan прокси
func TestParseProxyToYAML_Trojan(t *testing.T) {
	link := "trojan://mypassword@example.com:443?sni=example.com&skip-cert-verify=0"
	yaml := parseProxyToYAML(link, 0)

	if !strings.Contains(yaml, "type: trojan") {
		t.Error("Expected Trojan type")
	}
	if !strings.Contains(yaml, "password: \"mypassword\"") {
		t.Error("Expected password")
	}
	if !strings.Contains(yaml, "sni: \"example.com\"") {
		t.Error("Expected SNI")
	}
	if !strings.Contains(yaml, "skip-cert-verify: false") {
		t.Error("Expected cert verification enabled")
	}
}

// TestParseProxyToYAML_Trojan_WS проверяет перенос ws-транспорта для Trojan
func TestParseProxyToYAML_Trojan_WS(t *testing.T) {
	link := "trojan://mypassword@example.com:443?sni=example.com&type=ws&path=%2Fws&host=cdn.example.com"
	yaml := parseProxyToYAML(link, 0)

	for _, want := range []string{"network: \"ws\"", "ws-opts:", "path: \"/ws\"", "Host: \"cdn.example.com\""} {
		if !strings.Contains(yaml, want) {
			t.Errorf("Expected %q in YAML, got:\n%s", want, yaml)
		}
	}
}

// TestParseProxyToYAML_Hysteria2 проверяет парсинг Hysteria2 прокси:
// пароль из obfs-password, sni и insecure переносятся корректно
func TestParseProxyToYAML_Hysteria2(t *testing.T) {
	link := "hy2://@example.com:443?obfs=salamander&obfs-password=obfspass&sni=example.com&insecure=1&up=100&down=200"
	yaml := parseProxyToYAML(link, 0)

	for _, want := range []string{
		"type: hysteria2",
		"server: \"example.com\"",
		"port: 443",
		"password: \"obfspass\"",
		"obfs: \"salamander\"",
		"sni: \"example.com\"",
		"skip-cert-verify: true",
		"up: \"100\"",
		"down: \"200\"",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("Expected %q in YAML, got:\n%s", want, yaml)
		}
	}
	// Тип обфускации не должен попадать в пароль
	if strings.Contains(yaml, "password: \"salamander\"") {
		t.Error("Obfs type must not be used as password")
	}
}

// TestParseProxyToYAML_Hysteria2_Userinfo проверяет пароль из userinfo
func TestParseProxyToYAML_Hysteria2_Userinfo(t *testing.T) {
	link := "hysteria2://userpass@example.com:443?obfs=salamander&obfs-password=obfspass"
	yaml := parseProxyToYAML(link, 0)

	if !strings.Contains(yaml, "password: \"userpass\"") {
		t.Errorf("Expected password from userinfo, got:\n%s", yaml)
	}
}

// TestParseProxyToYAML_UnknownScheme проверяет, что неподдерживаемые схемы пропускаются
func TestParseProxyToYAML_UnknownScheme(t *testing.T) {
	for _, link := range []string{
		"http://example.com:80",
		"ftp://example.com",
		"socks5://user:pass@example.com:1080",
		"not-a-url",
	} {
		if got := parseProxyToYAML(link, 0); got != "" {
			t.Errorf("Expected empty result for %q, got:\n%s", link, got)
		}
	}
}

// TestParseProxyToYAML_YAMLEscaping проверяет экранирование спецсимволов в имени
func TestParseProxyToYAML_YAMLEscaping(t *testing.T) {
	link := "trojan://pass@example.com:443#" + url.QueryEscape(`bad"name\test`)
	yaml := parseProxyToYAML(link, 0)

	if !strings.Contains(yaml, `name: "bad\"name\\test"`) {
		t.Errorf("Expected escaped name in YAML, got:\n%s", yaml)
	}
}

// TestParseProxyToYAML_IgnoreComments проверяет игнорирование комментариев
func TestParseProxyToYAML_IgnoreComments(t *testing.T) {
	tests := []struct {
		input    string
		expected bool // true = должна быть игнорирована
	}{
		{"# Комментарий", true},
		{"#ss://example.com", true},
		{"ss://dXNlcjpwYXNz@example.com:8388", false},
		{"", true}, // пустая строка
	}

	for _, tt := range tests {
		yaml := parseProxyToYAML(tt.input, 0)
		isEmpty := len(strings.TrimSpace(yaml)) == 0

		if isEmpty != tt.expected {
			t.Errorf("For input %q, expected isEmpty=%v but got %v", tt.input, tt.expected, isEmpty)
		}
	}
}

// TestExtractProxyName проверяет извлечение имени прокси
func TestExtractProxyName(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"ss://example.com:8388", "example.com-"},          // Должно содержать пример.com
		{"vless://abc@example.com:443", "example.com-"},    // Должно содержать пример.com
		{"trojan://pass@example.com:443#myname", "myname"}, // Должно использовать фрагмент
	}

	for _, test := range tests {
		u, err := url.Parse(test.url)
		if err != nil {
			t.Fatalf("Failed to parse URL %s: %v", test.url, err)
		}
		name := extractProxyName(u, u.Query(), test.url, strings.ToLower(u.Scheme), 0, nil)
		if !strings.Contains(name, strings.Split(test.expected, "-")[0]) {
			t.Errorf("For URL %s, expected name containing %s, got %s", test.url, test.expected, name)
		}
	}
}

// TestExtractProxyName_VMess проверяет извлечение имени VMess из поля ps JSON payload
func TestExtractProxyName_VMess(t *testing.T) {
	payload, err := json.Marshal(map[string]any{"ps": "my vmess node", "add": "example.com"})
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
	link := "vmess://" + base64.StdEncoding.EncodeToString(payload)

	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	vm := decodeVMESSPayload(link)
	if name := extractProxyName(u, u.Query(), link, "vmess", 3, vm); name != "my vmess node" {
		t.Errorf("Expected name from ps field, got %q", name)
	}

	invalid := "vmess://!!!invalid!!!"
	u2, err := url.Parse(invalid)
	if err != nil {
		t.Fatalf("Failed to parse invalid URL: %v", err)
	}
	if name := extractProxyName(u2, u2.Query(), invalid, "vmess", 3, nil); name != "vmess-3" {
		t.Errorf("Expected fallback name vmess-3, got %q", name)
	}
}

// TestContentToYAML_ValidDocument проверяет, что сгенерированный YAML
// структурно валиден для всех поддерживаемых протоколов
func TestContentToYAML_ValidDocument(t *testing.T) {
	ssLink := "ss://" + utils.EncodeRawURBase64([]byte("aes-256-gcm:secret")) + "@example.com:8388#ss"
	vlessLink := "vless://uuid@example.com:443?security=reality&sni=ex.com&pbk=pbk&sid=ab&fp=chrome&type=ws&path=%2Fws&host=cdn.com&flow=xtls-rprx-vision#vl"
	trojanLink := "trojan://pass@example.com:443?sni=ex.com&type=ws&path=%2Fws#tr"
	hy2Link := "hy2://@example.com:443?obfs=salamander&obfs-password=op&sni=ex.com&insecure=1#hy"
	vmessLink := "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6ImdycGMiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJleC5jb20iLCJzZXJ2aWNlTmFtZSI6InN2YyJ9"

	content := []byte(strings.Join([]string{ssLink, vlessLink, trojanLink, hy2Link, vmessLink}, "\n"))
	out := contentToYAML(content)

	var parsed map[string]any
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("Generated YAML is invalid: %v\n---\n%s", err, out)
	}
	proxies, ok := parsed["proxies"].([]any)
	if !ok {
		t.Fatalf("Expected proxies list, got: %v", parsed)
	}
	if len(proxies) != 5 {
		t.Fatalf("Expected 5 proxies, got %d", len(proxies))
	}

	// Имя VMess-прокси должно браться из поля ps, а не из payload
	first, _ := proxies[4].(map[string]any)
	if name, _ := first["name"].(string); name != "vm" {
		t.Errorf("Expected VMess name 'vm' from ps field, got %q", name)
	}
}

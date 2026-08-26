// pkg/service/merge_base64_test.go — тесты обработки base64-подписок в /merge
package service

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sub-filter/internal/validator"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
)

func TestDecodeIfBase64(t *testing.T) {
	proxyContent := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:test123")) + "@example.com:8388#srv\n"

	// Многострочный base64, как в реальных подписках (переносы строк)
	b64 := base64.StdEncoding.EncodeToString([]byte(proxyContent))
	var wrapped []string
	for i := 0; i < len(b64); i += 16 {
		end := min(i+16, len(b64))
		wrapped = append(wrapped, b64[i:end])
	}

	tests := []struct {
		name   string
		input  []byte
		want   []byte
		wantEq bool // true — ожидаем равенство want, иначе достаточно детекта схемы
	}{
		{
			name:   "обычный текст со схемами не меняется",
			input:  []byte(proxyContent),
			want:   []byte(proxyContent),
			wantEq: true,
		},
		{
			name:  "base64-подписка декодируется",
			input: []byte(b64),
			want:  []byte(proxyContent),
		},
		{
			name:  "многострочный base64 декодируется",
			input: []byte(strings.Join(wrapped, "\n")),
			want:  []byte(proxyContent),
		},
		{
			name:   "не base64 не меняется",
			input:  []byte("hello world!!!"),
			want:   []byte("hello world!!!"),
			wantEq: true,
		},
		{
			name:   "base64 без схем после декодирования не меняется",
			input:  []byte(base64.StdEncoding.EncodeToString([]byte("hello world"))),
			want:   []byte(base64.StdEncoding.EncodeToString([]byte("hello world"))),
			wantEq: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeIfBase64(tt.input)
			if tt.wantEq {
				if string(got) != string(tt.want) {
					t.Errorf("содержимое изменилось: got %q, want %q", got, tt.want)
				}
				return
			}
			if !detectProxyScheme(got) {
				t.Errorf("после декодирования нет прокси-схем: %q", got)
			}
			if string(got) != string(tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// newMergeTestService создает сервис с двумя источниками: обычный текст и base64.
func newMergeTestService(t *testing.T) (*Service, *http.ServeMux, *httptest.Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: t.TempDir(),
			TTL:       30 * time.Minute,
		},
		Validation: config.ValidationConfig{AllowedUserAgents: []string{"test-agent"}},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))

	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator), BadWordRules: []config.BadWordRule{}}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	plainContent := "ss://" + userinfo + "@example.com:8388#plain-1\nss://" + userinfo + "@example2.com:8388#plain-2\n"
	b64Content := base64.StdEncoding.EncodeToString([]byte(
		"ss://" + userinfo + "@example3.com:8388#b64-1\nss://" + userinfo + "@example4.com:8388#b64-2\n"))

	tsPlain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, plainContent)
	}))
	t.Cleanup(tsPlain.Close)
	tsB64 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, b64Content)
	}))
	t.Cleanup(tsB64.Close)

	svc.sources["plain"] = &config.SafeSource{URL: tsPlain.URL, IP: net.ParseIP("127.0.0.1")}
	svc.sources["b64"] = &config.SafeSource{URL: tsB64.URL, IP: net.ParseIP("127.0.0.1")}

	mux := http.NewServeMux()
	svc.registerHandlers(mux)
	return svc, mux, tsPlain, tsB64
}

// countProxyLines считает строки, не являющиеся комментариями или пустыми.
func countProxyLines(body string) int {
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// TestMerge_Base64AndPlainSources: /merge обязан подхватывать все строки,
// когда один источник отдаёт base64, а второй — обычный текст (ветка загрузки).
func TestMerge_Base64AndPlainSources(t *testing.T) {
	_, mux, _, _ := newMergeTestService(t)

	req := httptest.NewRequest("GET", "/merge?ids=plain&ids=b64", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("merge status %d, body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, frag := range []string{"plain-1", "plain-2", "b64-1", "b64-2"} {
		if !strings.Contains(body, frag) {
			t.Errorf("в результате merge нет %q: %s", frag, body)
		}
	}
	if got := countProxyLines(body); got != 4 {
		t.Errorf("ожидалось 4 прокси-строки, получено %d: %s", got, body)
	}
}

// TestMerge_Base64Source_FromCache: если источник уже лежит в кэше в сыром
// base64-виде (например, после /filter), /merge должен декодировать его из кэша.
func TestMerge_Base64Source_FromCache(t *testing.T) {
	_, mux, tsPlain, tsB64 := newMergeTestService(t)

	// /filter заполняет кэш orig_<id>.txt сырым содержимым источников
	for _, id := range []string{"plain", "b64"} {
		req := httptest.NewRequest("GET", "/filter?id="+id, nil)
		req.Header.Set("User-Agent", "test-agent")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("filter %s status %d, body: %s", id, w.Code, w.Body.String())
		}
	}

	// Закрываем серверы: успех merge возможен только из кэша
	tsPlain.Close()
	tsB64.Close()

	req := httptest.NewRequest("GET", "/merge?ids=plain&ids=b64", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("merge status %d, body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, frag := range []string{"plain-1", "plain-2", "b64-1", "b64-2"} {
		if !strings.Contains(body, frag) {
			t.Errorf("в результате merge из кэша нет %q: %s", frag, body)
		}
	}
	if got := countProxyLines(body); got != 4 {
		t.Errorf("ожидалось 4 прокси-строки, получено %d: %s", got, body)
	}
}

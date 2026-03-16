// pkg/service/service_integration_test.go
package service

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub-filter/internal/validator"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
)

func TestService_HealthEndpoint(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: filepath.Join(os.TempDir(), "test-cache"),
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

	// Создаем тестовый HTTP сервер
	mux := http.NewServeMux()
	svc.registerHandlers(mux)

	// Тестируем health endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	handler := mux
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	expected := `{"status":"ok","timestamp":`
	if len(w.Body.String()) < len(expected) {
		t.Errorf("Response too short: %s", w.Body.String())
	}

	// now test filter/merge with a real source
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	content := "#c\nss://" + userinfo + "@example.com:8388#my-server\n#b\nss://" + userinfo + "@example2.com:8388#my-server2\nss://" + userinfo + "@example3.com:8388#my-server3\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, content)
	}))
	defer ts.Close()
	// add source
	svc.sources["x"] = &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}

	// filter without limit
	reqF := httptest.NewRequest("GET", "/filter?id=x", nil)
	reqF.Header.Set("User-Agent", "test-agent")
	wF := httptest.NewRecorder()
	handler.ServeHTTP(wF, reqF)
	if wF.Code != http.StatusOK {
		t.Errorf("filter status %d", wF.Code)
	}
	if !strings.Contains(wF.Body.String(), "ss://") {
		t.Errorf("filter body unexpected: %s", wF.Body.String())
	}

	// filter with limit
	reqF2 := httptest.NewRequest("GET", "/filter?id=x&lim=1", nil)
	reqF2.Header.Set("User-Agent", "test-agent")
	wF2 := httptest.NewRecorder()
	handler.ServeHTTP(wF2, reqF2)
	if wF2.Code != http.StatusOK {
		t.Errorf("filter status %d", wF2.Code)
	}
	lines := strings.Split(strings.TrimSpace(wF2.Body.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line, got %d", len(lines))
	}

	// merge - add another source with overlapping data
	svc.sources["y"] = &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}
	reqM := httptest.NewRequest("GET", "/merge?ids=x&ids=y", nil)
	reqM.Header.Set("User-Agent", "test-agent")
	wM := httptest.NewRecorder()
	handler.ServeHTTP(wM, reqM)
	if wM.Code != http.StatusOK {
		t.Errorf("merge status %d", wM.Code)
	}
	if !strings.Contains(wM.Body.String(), "ss://") {
		t.Errorf("merge body unexpected: %s", wM.Body.String())
	}

	// merge with limit
	reqM2 := httptest.NewRequest("GET", "/merge?ids=x&ids=y&lim=2", nil)
	reqM2.Header.Set("User-Agent", "test-agent")
	wM2 := httptest.NewRecorder()
	handler.ServeHTTP(wM2, reqM2)
	if wM2.Code != http.StatusOK {
		t.Errorf("merge status %d", wM2.Code)
	}
	mlines := strings.Split(strings.TrimSpace(wM2.Body.String()), "\n")
	if len(mlines) != 1 {
		t.Errorf("expected 1 merge line, got %d", len(mlines))
	}
}

func TestService_ValidateClientRequest_Valid(t *testing.T) {
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

	// Создаем тестовый запрос
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "192.168.1.1:12345"

	status, msg := svc.ValidateClientRequest(req)
	if status != 0 {
		t.Errorf("Expected valid request, got status %d: %s", status, msg)
	}
}

func TestService_ValidateClientRequest_InvalidUserAgent(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))

	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator)}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "invalid-agent")
	req.RemoteAddr = "192.168.1.1:12345"

	status, msg := svc.ValidateClientRequest(req)
	if status != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid User-Agent, got %d: %s", status, msg)
	}
}

func TestService_ValidateClientRequest_RateLimit(t *testing.T) {
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

	// Проверяем, что по крайней мереหนึ่ง запрос будет ограничен rate limiter'ом.
	allowed := 0
	limited := 0
	for i := 0; i < 25; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "test-agent")
		req.RemoteAddr = "192.168.1.1:12345"

		status, _ := svc.ValidateClientRequest(req)
		if status == 0 {
			allowed++
		} else if status == http.StatusTooManyRequests {
			limited++
		} else {
			t.Errorf("unexpected status %d on request %d", status, i)
		}
	}
	if allowed == 25 {
		t.Error("expected some requests to be rate limited")
	}
	if limited == 0 {
		t.Error("expected at least one request to be rate limited")
	}
}

func TestService_GetClientIP(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
	}
	log := logger.NewDefault(logger.ParseLevel("info"))

	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator)}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For",
			remoteAddr: "10.0.0.1:12345",
			xff:        "192.168.1.1",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP",
			remoteAddr: "10.0.0.1:12345",
			xri:        "192.168.1.2",
			expected:   "192.168.1.2",
		},
		{
			name:       "Invalid X-Forwarded-For",
			remoteAddr: "192.168.1.1:12345",
			xff:        "invalid",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := svc.getClientIP(req)
			if ip != tt.expected {
				t.Errorf("Expected IP %s, got %s", tt.expected, ip)
			}
		})
	}
}

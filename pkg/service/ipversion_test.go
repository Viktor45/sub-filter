package service

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub-filter/internal/validator"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
)

// TestParseIPVersion проверяет разбор параметра ip: пустое значение —
// поведение по умолчанию, "4"/"6" — форсирование стека, остальное — ошибка.
func TestParseIPVersion(t *testing.T) {
	for in, want := range map[string]int{"": 0, "4": 4, "6": 6} {
		got, err := parseIPVersion(in)
		if err != nil {
			t.Errorf("parseIPVersion(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseIPVersion(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"0", "5", "46", "v4", " 4", "ipv6"} {
		if _, err := parseIPVersion(in); err == nil {
			t.Errorf("parseIPVersion(%q) expected error, got nil", in)
		}
	}
}

// TestSelectIPForVersion проверяет выбор адреса нужного семейства
// с учётом SSRF-проверки (запрещённые адреса пропускаются).
func TestSelectIPForVersion(t *testing.T) {
	publicV4 := net.ParseIP("93.184.216.34")
	publicV6 := net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")

	tests := []struct {
		name    string
		ips     []net.IP
		version int
		want    net.IP
	}{
		{
			name:    "IPv4 из смешанного списка, loopback и private пропускаются",
			ips:     []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1"), publicV6, publicV4},
			version: 4,
			want:    publicV4,
		},
		{
			name:    "IPv6 из смешанного списка, private v6 пропускается",
			ips:     []net.IP{net.ParseIP("fd00::1"), publicV4, publicV6},
			version: 6,
			want:    publicV6,
		},
		{
			name:    "нет IPv4 среди только IPv6-адресов",
			ips:     []net.IP{publicV6},
			version: 4,
			want:    nil,
		},
		{
			name:    "нет IPv6 среди только IPv4-адресов",
			ips:     []net.IP{publicV4},
			version: 6,
			want:    nil,
		},
		{
			name:    "запрещённые адреса нужного семейства не выбираются",
			ips:     []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.1")},
			version: 4,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectIPForVersion(tt.ips, tt.version)
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %s", got)
				}
				return
			}
			if got == nil || !got.Equal(tt.want) {
				t.Errorf("expected %s, got %v", tt.want, got)
			}
		})
	}
}

// TestHandler_IPParam_Invalid проверяет, что /filter и /merge
// отклоняют некорректные значения ip со статусом 400.
func TestHandler_IPParam_Invalid(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache: config.CacheConfig{
			Directory: t.TempDir(),
			TTL:       30 * time.Minute,
		},
		Validation: config.ValidationConfig{AllowedUserAgents: []string{"test-agent"}},
	}
	log := logger.NewDefault(logger.ParseLevel("error"))
	opts := &ServiceOptions{Sources: make(map[string]*config.SafeSource), Rules: make(map[string]validator.Validator)}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	svc.sources["x"] = &config.SafeSource{URL: "http://example.com/sub.txt", IP: net.ParseIP("93.184.216.34")}

	mux := http.NewServeMux()
	svc.registerHandlers(mux)

	for _, path := range []string{
		"/filter?id=x&ip=5",
		"/filter?id=x&ip=v4",
		"/merge?ids=x&ip=abc",
		"/merge?ids=x&ip=46",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("User-Agent", "test-agent")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected status 400, got %d", path, w.Code)
		}
	}
}

// TestFetchSourceContent_IPVersion_SSRF проверяет, что при ip=4/6 повторно
// зарезолвленные адреса проходят SSRF-проверку: loopback-источник отклоняется,
// даже если его IP был зафиксирован в SafeSource.
func TestFetchSourceContent_IPVersion_SSRF(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ss://dXNlcjpwYXNz@example.com:8388\n")
	}))
	defer ts.Close()

	svc := makeSimpleService(t)
	source := &config.SafeSource{URL: ts.URL, IP: net.ParseIP("127.0.0.1")}
	svc.sources["x"] = source

	for _, version := range []int{4, 6} {
		_, err := svc.fetchSourceContent("x", source, filepath.Join(t.TempDir(), "orig.txt"), true, version, nil)
		if err == nil {
			t.Fatalf("ip=%d: expected error for loopback source, got nil", version)
		}
		if !strings.Contains(err.Error(), "IPv") {
			t.Errorf("ip=%d: expected 'no allowed IPvX address' error, got: %v", version, err)
		}
	}
}

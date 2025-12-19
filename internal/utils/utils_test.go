// internal/utils/utils_test.go
package utils

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"plain ASCII", []byte("hello"), true},
		{"with newline", []byte("hello\nworld"), true},
		{"with tab", []byte("hello\tworld"), true},
		{"with null", []byte{0}, false},
		{"binary", []byte{0xFF, 0xD8}, false},
		{"valid range upper", []byte{126}, true},
		{"invalid range lower", []byte{31}, false},
		{"valid range lower", []byte{32}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrintableASCII(tt.input); got != tt.want {
				t.Errorf("IsPrintableASCII() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAutoDecodeBase64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{"not base64", []byte("plain text"), []byte("plain text")},
		{"valid base64", []byte("aGVsbG8="), []byte("hello")},
		{"base64 with spaces", []byte(" aGVs bG8= \t"), []byte("hello")},
		{"binary", []byte{0xFF, 0xD8}, []byte{0xFF, 0xD8}},
		{"base64 raw", []byte("aGVsbG8"), []byte("hello")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AutoDecodeBase64(tt.input); string(got) != string(tt.want) {
				t.Errorf("AutoDecodeBase64() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUserInfo(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"std padded", "dGVzdA==", "test", false},
		{"url safe", "dGVzdA", "test", false},
		{"url safe padded", "dGVzdA==", "test", false},
		{"raw std", "dGVzdA", "test", false},
		{"invalid", "!!!", "", true},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeUserInfo(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeUserInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("DecodeUserInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsValidHost(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"example.com", true},
		{"xn--80akhbyknj4f.com", true},
		{"8.8.8.8", true},
		{"localhost", false},
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"exa..mple.com", false},
		{"2001:db8::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsValidHost(tt.host); got != tt.valid {
				t.Errorf("IsValidHost() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		port  int
		valid bool
	}{
		{80, true},
		{65535, true},
		{0, false},
		{65536, false},
		{-1, false},
		{1, true},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.port), func(t *testing.T) {
			if got := IsValidPort(tt.port); got != tt.valid {
				t.Errorf("IsValidPort() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestFullyDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82", "Привет"},
		{"hello", "hello"},
		{"%2520", " "},
		{"%252520", " "},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := FullyDecode(tt.input); got != tt.want {
				t.Errorf("FullyDecode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantHost string
		wantPort int
		parseErr bool
		wantErr  bool
	}{
		{"valid", "https://example.com:443", "example.com", 443, false, false},
		{"no port", "https://example.com", "", 0, false, true},
		{"port zero", "https://example.com:0", "", 0, false, true},
		{"port out of range", "https://example.com:70000", "", 0, false, true},
		{"invalid host", "https://exa..mple.com:443", "", 0, false, true},
		{"IP host", "https://8.8.8.8:53", "8.8.8.8", 53, false, false},
		{"invalid URL", "://", "", 0, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			if err != nil {
				if !tt.parseErr {
					t.Errorf("url.Parse() failed unexpectedly: %v", err)
				}
				return
			}
			host, port, err := ParseHostPort(u)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("ParseHostPort() = (%q, %d), want (%q, %d)", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestIsPathSafe(t *testing.T) {
	baseDir := "/tmp/safe"
	tests := []struct {
		name string
		path string
		safe bool
	}{
		{"safe", "/tmp/safe/file.txt", true},
		{"subdir", "/tmp/safe/sub/file.txt", true},
		{"traversal", "/tmp/safe/../etc/passwd", false},
		{"absolute traversal", "/etc/passwd", false},
		{"relative traversal", "../secret", false},
		{"current dir", "/tmp/safe/.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPathSafe(tt.path, baseDir); got != tt.safe {
				t.Errorf("IsPathSafe() = %v, want %v", got, tt.safe)
			}
		})
	}
}

// Helper для генерации отсортированного query
func makeSortedQuery(kvs ...string) string {
	if len(kvs) == 0 {
		return ""
	}
	sort.Strings(kvs)
	return strings.Join(kvs, "&")
}

func TestNormalizeLinkKey(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		expectError bool
	}{
		{
			name:  "vless basic",
			input: "vless://uuid@example.com:443?encryption=none&security=tls&sni=example.com",
			want:  "vless://example.com:443?" + makeSortedQuery("encryption=none", "security=tls", "sni=example.com"),
		},
		{
			name:  "vless with path=/",
			input: "vless://uuid@example.com:443/?encryption=none&security=tls&sni=example.com",
			want:  "vless://example.com:443?" + makeSortedQuery("encryption=none", "security=tls", "sni=example.com"),
		},
		{
			name:  "vless with path=/ws",
			input: "vless://uuid@example.com:443/path/ws?encryption=none&security=tls&sni=example.com",
			want:  "vless://example.com:443/path/ws?" + makeSortedQuery("encryption=none", "security=tls", "sni=example.com"),
		},
		{
			name:  "vless with fragment (ignored)",
			input: "vless://uuid@example.com:443?encryption=none&security=tls&sni=example.com#MyServer",
			want:  "vless://example.com:443?" + makeSortedQuery("encryption=none", "security=tls", "sni=example.com"),
		},
		{
			name:  "trojan basic",
			input: "trojan://password@example.com:443",
			want:  "trojan://example.com:443",
		},
		{
			name:  "trojan with grpc",
			input: "trojan://password@example.com:443?type=grpc&serviceName=service1",
			want:  "trojan://example.com:443?" + makeSortedQuery("serviceName=service1", "type=grpc"),
		},
		{
			name:  "hysteria2 basic",
			input: "hysteria2://password@example.com:443?obfs=salamander&obfs-password=secret",
			want:  "hysteria2://example.com:443?obfs=salamander&obfs-password=secret",
		},
		{
			name:  "ss basic",
			input: "ss://YWVzLTI1Ni1nY206dGVzdA==@example.com:8388",
			want:  "ss://example.com:8388",
		},
		{
			name:        "invalid url",
			input:       "not a url",
			expectError: true,
		},
		{
			name:  "https root (with default port 443)",
			input: "https://example.com",
			want:  "https://example.com:443",
		},
		{
			name:  "https with path",
			input: "https://example.com/somepath",
			want:  "https://example.com:443/somepath",
		},
		{
			name:  "http root (with default port 80)",
			input: "http://example.com",
			want:  "http://example.com:80",
		},
		{
			name:  "https with explicit port",
			input: "https://example.com:8443/api",
			want:  "https://example.com:8443/api",
		},
		{
			name:  "https with query",
			input: "https://example.com?a=1&b=2",
			want:  "https://example.com:443?" + makeSortedQuery("a=1", "b=2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeLinkKey(tt.input)
			if (err != nil) != tt.expectError {
				t.Errorf("NormalizeLinkKey() error = %v, wantErr %v", err, tt.expectError)
				return
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeLinkKey()\n\tgot  = %q,\n\twant = %q", got, tt.want)
			}
		})
	}
}

func TestCompareAndSelectBetter(t *testing.T) {
	makeURL := func(host string, port int, params int) string {
		u := &url.URL{
			Scheme: "test",
			Host:   fmt.Sprintf("%s:%d", host, port),
		}
		q := u.Query()
		for i := 0; i < params; i++ {
			q.Set(fmt.Sprintf("param%d", i), fmt.Sprintf("value%d", i))
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	tests := []struct {
		name           string
		currentLine    string
		existingLine   string
		expectedResult string
	}{
		{"current has more params", makeURL("a.com", 80, 3), makeURL("a.com", 80, 1), makeURL("a.com", 80, 3)},
		{"existing has more params", makeURL("a.com", 80, 1), makeURL("a.com", 80, 3), makeURL("a.com", 80, 3)},
		{"equal params, return existing", makeURL("a.com", 80, 2), makeURL("a.com", 80, 2), makeURL("a.com", 80, 2)},
		{"current invalid", "invalid url", makeURL("a.com", 80, 1), makeURL("a.com", 80, 1)},
		{"existing invalid", makeURL("a.com", 80, 1), "invalid url", makeURL("a.com", 80, 1)},
		{"both invalid", "invalid1", "invalid2", "invalid2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareAndSelectBetter(tt.currentLine, tt.existingLine)
			if result != tt.expectedResult {
				t.Errorf("CompareAndSelectBetter(%q, %q) = %q, want %q", tt.currentLine, tt.existingLine, result, tt.expectedResult)
			}
		})
	}
}

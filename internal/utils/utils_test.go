package utils

import (
	"net/url"
	"strconv"
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
		{"base64 with spaces", []byte(" aGVs bG8= \n\t"), []byte("hello")},
		{"binary (should not decode)", []byte{0xFF, 0xD8}, []byte{0xFF, 0xD8}},
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
		name  string
		host  string
		valid bool
	}{
		{"valid domain", "example.com", true},
		{"punycode", "xn--80akhbyknj4f.com", true},
		{"public IP", "8.8.8.8", true},
		{"localhost", "localhost", false},
		{"empty", "", false},
		{"bad domain", "exa..mple.com", false},
		{"ipv6", "2001:db8::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

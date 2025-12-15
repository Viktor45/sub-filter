package main

import (
	"testing"
)

func TestIsValidSourceURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com/sub", true},
		{"http://example.com/sub", true},
		{"https://localhost/sub", false},
		{"https://127.0.0.1/sub", false},
		{"https://192.168.1.1/sub", false},
		{"https://example.local/sub", false},
		{"ftp://example.com", false},
		{"not-a-url", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isValidSourceURL(tt.url); got != tt.valid {
				t.Errorf("isValidSourceURL() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		ip    string
		local bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
		{"invalid", true},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isLocalIP(tt.ip); got != tt.local {
				t.Errorf("isLocalIP() = %v, want %v", got, tt.local)
			}
		})
	}
}

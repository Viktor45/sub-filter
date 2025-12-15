package vless

import (
	"strings"
	"testing"

	"sub-filter/internal/utils"
)

func TestVLESSLink(t *testing.T) {
	badWords := []string{"blocked"}
	checkBadWords := func(fragment string) (bool, string) {
		if fragment == "" {
			return false, ""
		}
		decoded := utils.FullyDecode(fragment)
		lower := strings.ToLower(decoded)
		for _, word := range badWords {
			if word != "" && strings.Contains(lower, word) {
				return true, "bad word"
			}
		}
		return false, ""
	}

	link := NewVLESSLink(badWords, utils.IsValidHost, utils.IsValidPort, checkBadWords)

	tests := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{
			"valid",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=aes-128-gcm#my-server",
			true,
			"",
		},
		{
			"valid with ws",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=aes-128-gcm&type=ws&path=%2Fwebsocket#my-server",
			true,
			"",
		},
		{
			"invalid host",
			"vless://12345678-1234-1234-1234-123456789abc@localhost:443?security=tls&sni=localhost&encryption=none",
			false,
			"invalid host",
		},
		{
			"missing sni",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&encryption=none",
			false,
			"sni is required",
		},
		{
			"bad word in name",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=none#blocked-server",
			false,
			"bad word",
		},
		{
			"security=none",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=none&sni=example.com&encryption=none",
			false,
			"security=none is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := link.Process(tt.input)
			if tt.valid {
				if got == "" {
					t.Errorf("expected valid, got empty result")
				}
			} else {
				if got != "" {
					t.Errorf("expected invalid, got result")
				}
				if !strings.Contains(reason, tt.reason) {
					t.Errorf("reason = %q, want contains %q", reason, tt.reason)
				}
			}
		})
	}
}

func TestVLESSLink_Matches(t *testing.T) {
	link := VLESSLink{}
	if !link.Matches("vless://...") {
		t.Error("Matches() = false, want true")
	}
	if link.Matches("trojan://...") {
		t.Error("Matches() = true, want false")
	}
}

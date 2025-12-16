// Package vmess содержит юнит-тесты для VMess-обработчика.
package vmess

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

func encodeJSON(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// loadTestValidator загружает политику из config/rules.yaml для тестов.
func loadTestValidator(proto string) validator.Validator {
	pwd, _ := filepath.Abs(".")
	rulesPath := filepath.Join(pwd, "..", "config", "rules.yaml")
	rules, err := validator.LoadRules(rulesPath)
	if err != nil {
		panic("Failed to load rules.yaml for tests: " + err.Error())
	}
	if v, ok := rules[proto]; ok {
		return v
	}
	return &validator.GenericValidator{}
}

func TestVMessLink(t *testing.T) {
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
	link := NewVMessLink(badWords, utils.IsValidHost, checkBadWords, loadTestValidator("vmess"))

	// ВАЖНО: JSON без пробелов
	validVMessJSON := `{"v":"2","ps":"my-server","add":"example.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls"}`
	tests := []struct {
		name   string
		json   string
		valid  bool
		reason string
	}{
		{"valid", validVMessJSON, true, ""},
		{"no TLS", strings.Replace(validVMessJSON, `"tls":"tls"`, `"tls":""`, 1), false, "invalid value for tls"},
		{"missing tls", `{"v":"2","ps":"s","add":"e.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","net":"tcp"}`, false, "missing required parameter: tls"},
		{"bad host", strings.Replace(validVMessJSON, `"add":"example.com"`, `"add":"exa..mple.com"`, 1), false, "invalid server host"},
		{"bad word", strings.Replace(validVMessJSON, `"ps":"my-server"`, `"ps":"blocked-server"`, 1), false, "bad word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := "vmess://" + encodeJSON(tt.json)
			got, reason := link.Process(encoded)
			if tt.valid {
				if got == "" {
					t.Errorf("expected valid, got empty result")
				}
			} else {
				if got != "" {
					t.Errorf("expected invalid, got result: %q", got)
				}
				if !strings.Contains(reason, tt.reason) {
					t.Errorf("reason = %q, want contains %q", reason, tt.reason)
				}
			}
		})
	}
}

func TestVMessLink_Matches(t *testing.T) {
	link := VMessLink{}
	if !link.Matches("vmess://...") {
		t.Error("Matches() = false, want true")
	}
}

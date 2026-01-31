// Package vmess содержит юнит-тесты для VMess-обработчика.
package vmess

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

func encodeJSON(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestVMessLink_StripBadWordsEnabled(t *testing.T) {
	badWords := []string{"blocked"}
	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		for _, word := range badWords {
			if word == "" {
				continue
			}
			re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(word))
			if re.MatchString(decoded) {
				cleaned := re.ReplaceAllString(decoded, "")
				return cleaned, false, ""
			}
		}
		return fragment, false, ""
	}
	link := NewVMessLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("vmess"))
	validVMessJSON := `{"v":"2","ps":"blocked-server","add":"example.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls"}`
	encoded := "vmess://" + encodeJSON(validVMessJSON)
	got, reason := link.Process(encoded)
	if got == "" || strings.Contains(got, "blocked") {
		t.Fatalf("expected stripped name and accepted vmess, got: %q reason: %q", got, reason)
	}
}

func loadRuleForTest(proto string) validator.Validator {
	rules := map[string]validator.Rule{
		"hysteria2": {
			RequiredParams: []string{"obfs", "obfs-password"},
			AllowedValues: map[string][]string{
				"obfs": {"salamander"},
			},
		},
		"vless": {
			RequiredParams: []string{"encryption", "sni"},
			ForbiddenValues: map[string][]string{
				"security": {"none"},
			},
			AllowedValues: map[string][]string{
				"security": {"tls", "reality"},
			},
			Conditional: []validator.Condition{
				{When: map[string]string{"security": "reality"}, Require: []string{"pbk"}},
				{When: map[string]string{"type": "grpc"}, Require: []string{"serviceName"}},
				{When: map[string]string{"type": "ws"}, Require: []string{"path"}},
			},
		},
		"vmess": {
			RequiredParams: []string{"tls"},
			AllowedValues: map[string][]string{
				"tls": {"tls"},
			},
		},
		"trojan": {
			Conditional: []validator.Condition{
				{When: map[string]string{"type": "grpc"}, Require: []string{"serviceName"}},
			},
		},
		"ss": {}, // пустое правило
	}
	if rule, ok := rules[proto]; ok {
		return &validator.GenericValidator{Rule: rule}
	}
	return &validator.GenericValidator{}
}

func TestVMessLink(t *testing.T) {
	badWords := []string{"blocked"}
	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		lower := strings.ToLower(decoded)
		for _, word := range badWords {
			if word != "" && strings.Contains(lower, word) {
				return "", true, "bad word"
			}
		}
		return fragment, false, ""
	}
	link := NewVMessLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("vmess"))

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

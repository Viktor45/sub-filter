// package vless
package vless

import (
	"regexp"
	"strings"
	"testing"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

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

func TestVLESSLink_StripBadWordsEnabled(t *testing.T) {
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
	link := NewVLESSLink(badWords, utils.IsValidHost, utils.IsValidPort, checkBadWords, loadRuleForTest("vless"))
	got, reason := link.Process("vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=none#blocked-server")
	if got == "" || strings.Contains(got, "blocked") {
		t.Fatalf("expected stripped name and accepted link, got: %q reason: %q", got, reason)
	}
}

func TestVLESSLink(t *testing.T) {
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
	link := NewVLESSLink(badWords, utils.IsValidHost, utils.IsValidPort, checkBadWords, loadRuleForTest("vless"))
	tests := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{
			"valid with security",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=none#my-server",
			true,
			"",
		},
		{
			"valid with ws and security",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=none&type=ws&path=%2Fwebsocket#my-server",
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
			"missing required parameter: sni",
		},
		{
			"missing encryption",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com",
			false,
			"missing required parameter: encryption",
		},
		{
			"bad word in name",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com&encryption=none#blocked-server",
			false,
			"bad word",
		},
		{
			"explicit security=none",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=none&sni=example.com&encryption=none",
			false,
			"forbidden value for security", // <-- Изменено: ожидаем forbidden, так как forbidden_values теперь раньше
		},
		// --- Новые/Обновлённые тесты ---
		{
			"missing security, default none (should be blocked by forbidden_values)",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?sni=example.com&encryption=none&type=tcp",
			false,
			"forbidden value for security", // Ожидаем, что отфильтруется из-за security=none
		},
		{
			"missing security, default none, with type ws (should be blocked by forbidden_values first)",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?sni=example.com&encryption=none&type=ws", // path отсутствует
			false,
			"forbidden value for security", // forbidden_values сработает первым, так как security=none
		},
		{
			"missing security, default none, with type ws and path (should be blocked by forbidden_values)",
			"vless://12345678-1234-1234-1234-123456789abc@example.com:443?sni=example.com&encryption=none&type=ws&path=%2Fws", // path есть
			false,
			"forbidden value for security", // forbidden_values для security=none сработает
		},
		// --- Конец новых/обновлённых тестов ---
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
					t.Errorf("expected invalid, got result: %q", got)
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

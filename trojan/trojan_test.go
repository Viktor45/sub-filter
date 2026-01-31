package trojan

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

func TestTrojanLink_StripBadWordsEnabled(t *testing.T) {
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
	link := NewTrojanLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("trojan"))
	got, reason := link.Process("trojan://password@example.com:443#blocked-server")
	if got == "" || strings.Contains(got, "blocked") {
		t.Fatalf("expected stripped name and accepted trojan, got: %q reason: %q", got, reason)
	}
}

func TestTrojanLink(t *testing.T) {
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
	link := NewTrojanLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("trojan"))

	tests := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{"valid", "trojan://password@example.com:443#my-server", true, ""},
		{"bad host", "trojan://password@localhost:443", false, "invalid host"},
		{"bad word", "trojan://password@example.com:443#blocked-server", false, "bad word"},
		{"grpc no service", "trojan://password@example.com:443?type=grpc", false, "missing required parameter serviceName"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := link.Process(tt.input)
			if tt.valid {
				if got == "" {
					t.Errorf("expected valid")
				}
			} else {
				if got != "" {
					t.Errorf("expected invalid")
				}
				if !strings.Contains(reason, tt.reason) {
					t.Errorf("reason = %q, want contains %q", reason, tt.reason)
				}
			}
		})
	}
}

func TestTrojanLink_Matches(t *testing.T) {
	link := TrojanLink{}
	if !link.Matches("trojan://...") {
		t.Error("Matches() = false, want true")
	}
}

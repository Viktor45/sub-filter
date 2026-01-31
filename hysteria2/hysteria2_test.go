package hysteria2

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

func TestHysteria2Link_StripBadWordsEnabled(t *testing.T) {
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
	link := NewHysteria2Link(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("hysteria2"))
	got, reason := link.Process("hysteria2://UUID@example.com:443?obfs=salamander&obfs-password=secret#blocked")
	if got == "" || strings.Contains(got, "blocked") {
		t.Fatalf("expected stripped name and accepted hysteria2, got: %q reason: %q", got, reason)
	}
}

func TestHysteria2Link(t *testing.T) {
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
	link := NewHysteria2Link(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("hysteria2"))

	tests := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{
			"valid",
			"hysteria2://UUID@example.com:443?obfs=salamander&obfs-password=secret#my-server",
			true,
			"",
		},
		{
			"hy2 valid",
			"hy2://UUID@example.com:443?obfs=salamander&obfs-password=secret",
			true,
			"",
		},
		{
			"missing obfs",
			"hysteria2://UUID@example.com:443#my-server",
			false,
			"missing required parameter: obfs",
		},
		{
			"bad obfs",
			"hysteria2://UUID@example.com:443?obfs=plain&obfs-password=secret",
			false,
			"invalid value for obfs",
		},
		{
			"bad host",
			"hysteria2://UUID@localhost:443?obfs=salamander&obfs-password=secret",
			false,
			"invalid host",
		},
		{
			"bad word",
			"hysteria2://UUID@example.com:443?obfs=salamander&obfs-password=secret#blocked",
			false,
			"bad word",
		},
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

func TestHysteria2Link_Matches(t *testing.T) {
	link := Hysteria2Link{}
	if !link.Matches("hysteria2://...") {
		t.Error("Matches() = false, want true")
	}
	if !link.Matches("hy2://...") {
		t.Error("Matches() = false, want true for hy2")
	}
	if link.Matches("vless://...") {
		t.Error("Matches() = true, want false")
	}
}

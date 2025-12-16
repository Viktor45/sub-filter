package trojan

import (
	"path/filepath"
	"strings"
	"testing"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

func loadRuleForTest(proto string) validator.Validator {
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

func TestTrojanLink(t *testing.T) {
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

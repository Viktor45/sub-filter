// internal/validator/validator_test.go
package validator

import (
	"strings"
	"testing"
)

func TestGenericValidator_RequiredParams(t *testing.T) {
	rule := Rule{
		RequiredParams: []string{"sni", "encryption"},
	}
	v := &GenericValidator{Rule: rule}
	tests := []struct {
		name   string
		params map[string]string
		valid  bool
		reason string
	}{
		{"all present", map[string]string{"sni": "a.com", "encryption": "none"}, true, ""},
		{"missing sni", map[string]string{"encryption": "none"}, false, "missing required parameter: sni"},
		{"missing encryption", map[string]string{"sni": "a.com"}, false, "missing required parameter: encryption"},
		{"both missing", map[string]string{}, false, "missing required parameter: sni"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.params)
			if result.Valid != tt.valid {
				t.Errorf("Validate() = %v, want %v", result.Valid, tt.valid)
			}
			if !tt.valid && !stringsContains(result.Reason, tt.reason) {
				t.Errorf("reason = %q, want contains %q", result.Reason, tt.reason)
			}
		})
	}
}

func TestGenericValidator_AllowedValues(t *testing.T) {
	rule := Rule{
		AllowedValues: map[string][]string{
			"security": {"tls", "reality"},
			"obfs":     {"salamander"},
		},
	}
	v := &GenericValidator{Rule: rule}
	tests := []struct {
		name   string
		params map[string]string
		valid  bool
		reason string
	}{
		{"valid security", map[string]string{"security": "tls"}, true, ""},
		{"valid obfs", map[string]string{"obfs": "salamander"}, true, ""},
		{"invalid security", map[string]string{"security": "none"}, false, "invalid value for security"},
		{"invalid obfs", map[string]string{"obfs": "plain"}, false, "invalid value for obfs"},
		{"missing param", map[string]string{}, true, ""}, // allowed, not required
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.params)
			if result.Valid != tt.valid {
				t.Errorf("Validate() = %v, want %v", result.Valid, tt.valid)
			}
			if !tt.valid && !stringsContains(result.Reason, tt.reason) {
				t.Errorf("reason = %q, want contains %q", result.Reason, tt.reason)
			}
		})
	}
}

func TestGenericValidator_ForbiddenValues(t *testing.T) {
	rule := Rule{
		ForbiddenValues: map[string][]string{
			"security": {"none"},
		},
	}
	v := &GenericValidator{Rule: rule}
	tests := []struct {
		name   string
		params map[string]string
		valid  bool
		reason string
	}{
		{"allowed", map[string]string{"security": "tls"}, true, ""},
		{"forbidden", map[string]string{"security": "none"}, false, "forbidden value for security"},
		{"missing", map[string]string{}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.params)
			if result.Valid != tt.valid {
				t.Errorf("Validate() = %v, want %v", result.Valid, tt.valid)
			}
			if !tt.valid && !stringsContains(result.Reason, tt.reason) {
				t.Errorf("reason = %q, want contains %q", result.Reason, tt.reason)
			}
		})
	}
}

// TestGenericValidator_ForbiddenValuesPriority проверяет, что forbidden_values имеет приоритет над allowed_values.
func TestGenericValidator_ForbiddenValuesPriority(t *testing.T) {
	// Тест, подтверждающий, что forbidden_values имеет приоритет над allowed_values
	// для одного и того же параметра.
	rule := Rule{
		AllowedValues: map[string][]string{
			"security": {"tls", "reality"},
		},
		ForbiddenValues: map[string][]string{
			"security": {"none"},
		},
	}
	v := &GenericValidator{Rule: rule}
	tests := []struct {
		name   string
		params map[string]string
		valid  bool
		reason string // Ожидаем сообщение от forbidden_values
	}{
		{
			"forbidden value takes precedence over allowed list",
			map[string]string{"security": "none"}, // "none" не в allowed, но ЗАПРЕЩЕНО
			false,
			"forbidden value for security", // forbidden_values срабатывает первым
		},
		{
			"allowed value passes",
			map[string]string{"security": "tls"}, // "tls" разрешено
			true,
			"",
		},
		{
			"disallowed value fails (not forbidden)",
			map[string]string{"security": "quic"}, // "quic" не разрешено
			false,
			"invalid value for security", // allowed_values срабатывает вторым
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.params)
			if result.Valid != tt.valid {
				t.Errorf("Validate() = %v, want %v", result.Valid, tt.valid)
			}
			if !tt.valid && !stringsContains(result.Reason, tt.reason) {
				t.Errorf("reason = %q, want contains %q", result.Reason, tt.reason)
			}
		})
	}
}

func TestGenericValidator_Conditional(t *testing.T) {
	rule := Rule{
		Conditional: []Condition{
			{When: map[string]string{"security": "reality"}, Require: []string{"pbk"}},
			{When: map[string]string{"type": "grpc"}, Require: []string{"serviceName"}},
		},
	}
	v := &GenericValidator{Rule: rule}
	tests := []struct {
		name   string
		params map[string]string
		valid  bool
		reason string
	}{
		{"reality without pbk", map[string]string{"security": "reality"}, false, "missing required parameter pbk"},
		{"reality with pbk", map[string]string{"security": "reality", "pbk": "abc"}, true, ""},
		{"grpc without service", map[string]string{"type": "grpc"}, false, "missing required parameter serviceName"},
		{"grpc with service", map[string]string{"type": "grpc", "serviceName": "s1"}, true, ""},
		{"not reality, no pbk", map[string]string{"security": "tls"}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.params)
			if result.Valid != tt.valid {
				t.Errorf("Validate() = %v, want %v", result.Valid, tt.valid)
			}
			if !tt.valid && !stringsContains(result.Reason, tt.reason) {
				t.Errorf("reason = %q, want contains %q", result.Reason, tt.reason)
			}
		})
	}
}

func stringsContains(s, substr string) bool {
	return substr == "" || strings.Contains(s, substr)
}

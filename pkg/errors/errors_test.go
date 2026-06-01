package errors

import (
	"errors"
	"testing"
	"time"
)

func TestErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		{"Config error", ErrCodeConfig, "config_error"},
		{"Validation error", ErrCodeValidate, "validation_error"},
		{"Network error", ErrCodeNetwork, "network_error"},
		{"HTTP error", ErrCodeHTTP, "http_error"},
		{"Parse error", ErrCodeParse, "parse_error"},
		{"IO error", ErrCodeIO, "io_error"},
		{"File operation error", ErrCodeFileOp, "file_operation_error"},
		{"Logic error", ErrCodeLogic, "logic_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.code) != tt.expected {
				t.Errorf("got %q, want %q", string(tt.code), tt.expected)
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected string
	}{
		{"Info severity", SeverityInfo, "info"},
		{"Warning severity", SeverityWarning, "warning"},
		{"Error severity", SeverityError, "error"},
		{"Critical severity", SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.severity) != tt.expected {
				t.Errorf("got %q, want %q", string(tt.severity), tt.expected)
			}
		})
	}
}

func TestNewFilterError(t *testing.T) {
	code := ErrCodeConfig
	category := "Config"
	message := "configuration failed"

	err := NewFilterError(code, category, message)

	if err.Code != code {
		t.Errorf("Code: got %q, want %q", err.Code, code)
	}
	if err.Category != category {
		t.Errorf("Category: got %q, want %q", err.Category, category)
	}
	if err.Message != message {
		t.Errorf("Message: got %q, want %q", err.Message, message)
	}
	if err.Severity != SeverityError {
		t.Errorf("Severity: got %q, want %q", err.Severity, SeverityError)
	}
	if err.Context == nil {
		t.Error("Context should not be nil")
	}
	if len(err.Context) != 0 {
		t.Errorf("Context: expected empty, got %d items", len(err.Context))
	}
	if err.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestFilterError_Error(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		category string
		message  string
		wrapped  error
		expected string
	}{
		{
			"Without wrapped error",
			ErrCodeConfig,
			"Config",
			"test error",
			nil,
			"[config_error:Config] test error",
		},
		{
			"With wrapped error",
			ErrCodeParse,
			"Parse",
			"parsing failed",
			errors.New("underlying error"),
			"[parse_error:Parse] parsing failed: underlying error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := NewFilterError(tt.code, tt.category, tt.message)
			if tt.wrapped != nil {
				fe.WithCause(tt.wrapped)
			}
			if fe.Error() != tt.expected {
				t.Errorf("got %q, want %q", fe.Error(), tt.expected)
			}
		})
	}
}

func TestFilterError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("original error")
	fe := NewFilterError(ErrCodeConfig, "Config", "config failed").WithCause(wrappedErr)

	unwrapped := fe.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("Unwrap: got %v, want %v", unwrapped, wrappedErr)
	}
}

func TestFilterError_WithCause(t *testing.T) {
	fe := NewFilterError(ErrCodeIO, "IO", "read failed")
	wrappedErr := errors.New("file not found")

	result := fe.WithCause(wrappedErr)

	if result != fe {
		t.Error("WithCause should return the same error for chaining")
	}
	if fe.Err != wrappedErr {
		t.Errorf("Err: got %v, want %v", fe.Err, wrappedErr)
	}
}

func TestFilterError_WithContext(t *testing.T) {
	fe := NewFilterError(ErrCodeNetwork, "Network", "fetch failed")

	fe.WithContext("sourceID", "source1").
		WithContext("url", "http://example.com").
		WithContext("statusCode", 500)

	if fe.Context["sourceID"] != "source1" {
		t.Errorf("sourceID: got %v, want %q", fe.Context["sourceID"], "source1")
	}
	if fe.Context["url"] != "http://example.com" {
		t.Errorf("url: got %v, want %q", fe.Context["url"], "http://example.com")
	}
	if fe.Context["statusCode"] != 500 {
		t.Errorf("statusCode: got %v, want %d", fe.Context["statusCode"], 500)
	}
}

func TestFilterError_WithSeverity(t *testing.T) {
	fe := NewFilterError(ErrCodeValidate, "Validate", "validation failed")

	result := fe.WithSeverity(SeverityCritical)

	if result != fe {
		t.Error("WithSeverity should return the same error for chaining")
	}
	if fe.Severity != SeverityCritical {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityCritical)
	}
}

func TestFilterError_IsRecoverable(t *testing.T) {
	tests := []struct {
		name        string
		code        ErrorCode
		severity    Severity
		recoverable bool
	}{
		{"Network error", ErrCodeNetwork, SeverityWarning, true},
		{"HTTP error", ErrCodeHTTP, SeverityWarning, true},
		{"IO error", ErrCodeIO, SeverityWarning, true},
		{"Config error", ErrCodeConfig, SeverityError, false},
		{"Validation error", ErrCodeValidate, SeverityInfo, false},
		{"Logic error (not critical)", ErrCodeLogic, SeverityWarning, true},
		{"Logic error (critical)", ErrCodeLogic, SeverityCritical, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := NewFilterError(tt.code, "test", "test error").WithSeverity(tt.severity)
			if fe.IsRecoverable() != tt.recoverable {
				t.Errorf("IsRecoverable: got %v, want %v", fe.IsRecoverable(), tt.recoverable)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	underlyingErr := errors.New("syntax error")
	fe := ParseError("failed to parse JSON", underlyingErr)

	if fe.Code != ErrCodeParse {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeParse)
	}
	if fe.Category != "Parse" {
		t.Errorf("Category: got %q, want %q", fe.Category, "Parse")
	}
	if fe.Severity != SeverityWarning {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityWarning)
	}
	if fe.Err != underlyingErr {
		t.Errorf("Err: got %v, want %v", fe.Err, underlyingErr)
	}
}

func TestNetworkError(t *testing.T) {
	underlyingErr := errors.New("connection timeout")
	fe := NetworkError("failed to fetch data", underlyingErr)

	if fe.Code != ErrCodeNetwork {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeNetwork)
	}
	if fe.Category != "Network" {
		t.Errorf("Category: got %q, want %q", fe.Category, "Network")
	}
	if fe.Severity != SeverityWarning {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityWarning)
	}
	if fe.IsRecoverable() != true {
		t.Error("Network error should be recoverable")
	}
}

func TestConfigError(t *testing.T) {
	underlyingErr := errors.New("YAML parse error")
	fe := ConfigError("invalid configuration", underlyingErr)

	if fe.Code != ErrCodeConfig {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeConfig)
	}
	if fe.Category != "Config" {
		t.Errorf("Category: got %q, want %q", fe.Category, "Config")
	}
	if fe.Severity != SeverityError {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityError)
	}
	if fe.IsRecoverable() != false {
		t.Error("Config error should not be recoverable")
	}
}

func TestValidationError(t *testing.T) {
	fe := ValidationError("invalid country code")

	if fe.Code != ErrCodeValidate {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeValidate)
	}
	if fe.Category != "Validate" {
		t.Errorf("Category: got %q, want %q", fe.Category, "Validate")
	}
	if fe.Severity != SeverityInfo {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityInfo)
	}
	if fe.Err != nil {
		t.Errorf("Err should be nil, got %v", fe.Err)
	}
}

func TestIOError(t *testing.T) {
	underlyingErr := errors.New("permission denied")
	fe := IOError("failed to write file", underlyingErr)

	if fe.Code != ErrCodeIO {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeIO)
	}
	if fe.Category != "IO" {
		t.Errorf("Category: got %q, want %q", fe.Category, "IO")
	}
	if fe.Severity != SeverityWarning {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityWarning)
	}
	if fe.IsRecoverable() != true {
		t.Error("IO error should be recoverable")
	}
}

func TestFilterError_Chaining(t *testing.T) {
	underlyingErr := errors.New("root cause")
	fe := NewFilterError(ErrCodeNetwork, "Network", "fetch failed").
		WithCause(underlyingErr).
		WithContext("url", "http://example.com").
		WithContext("timeout", 30*time.Second).
		WithSeverity(SeverityWarning)

	if fe.Code != ErrCodeNetwork {
		t.Errorf("Code: got %q, want %q", fe.Code, ErrCodeNetwork)
	}
	if fe.Err != underlyingErr {
		t.Errorf("Err: got %v, want %v", fe.Err, underlyingErr)
	}
	if fe.Context["url"] != "http://example.com" {
		t.Errorf("url context: got %v, want %q", fe.Context["url"], "http://example.com")
	}
	if fe.Severity != SeverityWarning {
		t.Errorf("Severity: got %q, want %q", fe.Severity, SeverityWarning)
	}
}

func TestFilterError_ErrorsInterface(t *testing.T) {
	underlyingErr := errors.New("underlying")
	fe := NewFilterError(ErrCodeIO, "IO", "failed").WithCause(underlyingErr)

	// Test that FilterError implements the error interface (compiler already
	// guarantees non-nil because we create fe above, so just exercise the
	// variable to silence unused warnings).
	var err error = fe
	_ = err

	// Test errors.Unwrap
	unwrapped := errors.Unwrap(err)
	if unwrapped != underlyingErr {
		t.Errorf("errors.Unwrap: got %v, want %v", unwrapped, underlyingErr)
	}
}

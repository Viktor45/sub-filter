package logger

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := New(handler)

	if logger == nil {
		t.Error("New() returned nil")
	}
	if logger.Logger == nil {
		t.Error("Logger field is nil")
	}
}

func TestNewDefault(t *testing.T) {
	logger := NewDefault(slog.LevelInfo)

	if logger == nil {
		t.Error("NewDefault() returned nil")
	}
	if logger.Logger == nil {
		t.Error("Logger field is nil")
	}
}

func TestNewTextLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelDebug)

	if logger == nil {
		t.Error("NewTextLogger() returned nil")
	}
	if logger.Logger == nil {
		t.Error("Logger field is nil")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"unknown", "unknown", slog.LevelInfo},
		{"empty", "", slog.LevelInfo},
		{"WARN uppercase", "WARN", slog.LevelInfo}, // Should not match (case-sensitive)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLevel(tt.input)
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelError)

	logger.Error("test error message", slog.String("key", "value"))

	output := buf.String()
	if !strings.Contains(output, "test error message") {
		t.Errorf("output should contain 'test error message', got: %s", output)
	}
	if !strings.Contains(output, "key") {
		t.Errorf("output should contain 'key', got: %s", output)
	}
}

func TestLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	logger.Info("test info message", slog.String("level", "info"))

	output := buf.String()
	if !strings.Contains(output, "test info message") {
		t.Errorf("output should contain 'test info message', got: %s", output)
	}
}

func TestLogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelDebug)

	logger.Debug("test debug message", slog.String("level", "debug"))

	output := buf.String()
	if !strings.Contains(output, "test debug message") {
		t.Errorf("output should contain 'test debug message', got: %s", output)
	}
}

func TestLogger_ErrorWithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelError)

	fields := map[string]interface{}{
		"sourceID": "source1",
		"url":      "http://example.com",
	}

	err := fmt.Errorf("test error")
	logger.ErrorWithContext("operation failed", err, fields)

	output := buf.String()
	if !strings.Contains(output, "operation failed") {
		t.Errorf("output should contain 'operation failed', got: %s", output)
	}
}

func TestLogger_InfoWithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	fields := map[string]interface{}{
		"operation": "fetch",
		"duration":  "100ms",
	}

	logger.InfoWithContext("operation completed", fields)

	output := buf.String()
	if !strings.Contains(output, "operation completed") {
		t.Errorf("output should contain 'operation completed', got: %s", output)
	}
}

func TestLogger_DebugWithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelDebug)

	fields := map[string]interface{}{
		"step": "parsing",
		"line": 42,
	}

	logger.DebugWithContext("parsing data", fields)

	output := buf.String()
	if !strings.Contains(output, "parsing data") {
		t.Errorf("output should contain 'parsing data', got: %s", output)
	}
}

func TestLogger_Timed_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	err := logger.Timed("test operation", func() error {
		// Simulate successful operation
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "operation completed") {
		t.Errorf("output should contain 'operation completed', got: %s", output)
	}
	if !strings.Contains(output, "test operation") {
		t.Errorf("output should contain 'test operation', got: %s", output)
	}
}

func TestLogger_Timed_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelError)

	err := logger.Timed("failing operation", func() error {
		return fmt.Errorf("test error")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}

	output := buf.String()
	if !strings.Contains(output, "operation failed") {
		t.Errorf("output should contain 'operation failed', got: %s", output)
	}
	if !strings.Contains(output, "failing operation") {
		t.Errorf("output should contain 'failing operation', got: %s", output)
	}
}

func TestLogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelWarn)

	logger.Warn("test warning message", slog.String("code", "W001"))

	output := buf.String()
	if !strings.Contains(output, "test warning message") {
		t.Errorf("output should contain 'test warning message', got: %s", output)
	}
}

func TestLogger_LogLevel_Filtering(t *testing.T) {
	// Test that debug messages are not logged when level is info
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	logger.Debug("this should not appear", slog.String("level", "debug"))

	output := buf.String()
	if strings.Contains(output, "this should not appear") {
		t.Errorf("debug message should not appear at info level, got: %s", output)
	}

	// Test that info messages are logged when level is info
	logger.Info("this should appear", slog.String("level", "info"))
	output = buf.String()
	if !strings.Contains(output, "this should appear") {
		t.Errorf("info message should appear at info level, got: %s", output)
	}
}

func TestLogger_Chaining(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	// Test method chaining by calling multiple logger methods
	logger.Info("first message", slog.String("order", "1"))
	logger.Warn("second message", slog.String("order", "2"))
	logger.Error("third message", slog.String("order", "3"))

	output := buf.String()
	if !strings.Contains(output, "first message") {
		t.Error("first message missing")
	}
	if !strings.Contains(output, "second message") {
		t.Error("second message missing")
	}
	if !strings.Contains(output, "third message") {
		t.Error("third message missing")
	}
}

func TestLogger_JSON_Output(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf, slog.LevelInfo)

	logger.Info("test message", slog.String("service", "test"))

	output := buf.String()
	// JSON output should contain the message
	if !strings.Contains(output, "test message") {
		t.Errorf("JSON output should contain 'test message', got: %s", output)
	}
	// JSON output should be valid JSON (check for quotes)
	if !strings.Contains(output, `"`) {
		t.Errorf("JSON output should contain quotes, got: %s", output)
	}
}

func TestLogger_MultipleFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewTextLogger(&buf, slog.LevelInfo)

	fields := map[string]interface{}{
		"sourceID": "src1",
		"url":      "http://example.com",
		"status":   200,
		"size":     1024,
	}

	logger.InfoWithContext("request completed", fields)

	output := buf.String()
	if !strings.Contains(output, "request completed") {
		t.Errorf("output should contain 'request completed', got: %s", output)
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerConfig_Defaults(t *testing.T) {
	cfg := ServerConfig{}

	if cfg.Port != 0 {
		t.Errorf("Port should default to 0 in struct, got %d", cfg.Port)
	}
	if cfg.Host != "" {
		t.Errorf("Host should default to empty string in struct, got %q", cfg.Host)
	}
}

func TestCacheConfig_Defaults(t *testing.T) {
	cfg := CacheConfig{}

	if cfg.TTL != 0 {
		t.Errorf("TTL should default to 0 in struct, got %v", cfg.TTL)
	}
	if cfg.MergeBuckets != 0 {
		t.Errorf("MergeBuckets should default to 0 in struct, got %d", cfg.MergeBuckets)
	}
}

func TestSourcesConfig_Defaults(t *testing.T) {
	cfg := SourcesConfig{}

	if cfg.FetchTimeout != 0 {
		t.Errorf("FetchTimeout should default to 0 in struct, got %v", cfg.FetchTimeout)
	}
	if cfg.MaxSize != 0 {
		t.Errorf("MaxSize should default to 0 in struct, got %d", cfg.MaxSize)
	}
}

func TestValidationConfig_Defaults(t *testing.T) {
	cfg := ValidationConfig{}

	if cfg.MaxPatterns != 0 {
		t.Errorf("MaxPatterns should default to 0 in struct, got %d", cfg.MaxPatterns)
	}
	if cfg.MaxCountries != 0 {
		t.Errorf("MaxCountries should default to 0 in struct, got %d", cfg.MaxCountries)
	}
}

func TestLoggingConfig_Defaults(t *testing.T) {
	cfg := LoggingConfig{}

	if cfg.Level != "" {
		t.Errorf("Level should default to empty string in struct, got %q", cfg.Level)
	}
	if cfg.Format != "" {
		t.Errorf("Format should default to empty string in struct, got %q", cfg.Format)
	}
}

func TestLoad_WithoutFile(t *testing.T) {
	// Test load without config file (should use defaults)
	cfg, err := Load("nonexistent.yaml")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check defaults were set
	if cfg.Server.Port != 8000 {
		t.Errorf("Server.Port: got %d, want 8000", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host: got %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Cache.TTL != 30*time.Minute {
		t.Errorf("Cache.TTL: got %v, want %v", cfg.Cache.TTL, 30*time.Minute)
	}
	if cfg.Cache.MaxAge != 24*time.Hour {
		t.Errorf("Cache.MaxAge: got %v, want %v", cfg.Cache.MaxAge, 24*time.Hour)
	}
	if cfg.Sources.MaxSources != 1000 {
		t.Errorf("Sources.MaxSources: got %d, want 1000", cfg.Sources.MaxSources)
	}
}

func TestLoad_EnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("SERVER_PORT", "9000")
	os.Setenv("LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("LOG_LEVEL")
	}()

	cfg, err := Load("nonexistent.yaml")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Server.Port != 9000 {
		t.Errorf("Server.Port: got %d, want 9000", cfg.Server.Port)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level: got %q, want %q", cfg.Logging.Level, "debug")
	}
}

func TestLoad_InvalidPort_InEnvironment(t *testing.T) {
	os.Setenv("SERVER_PORT", "invalid")
	defer os.Unsetenv("SERVER_PORT")

	cfg, err := Load("nonexistent.yaml")

	// Should not error, just ignore invalid port
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg == nil {
		t.Fatal("config should not be nil")
	}
}

func TestValidate_Success(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			TTL:    30 * time.Minute,
			MaxAge: 1 * time.Hour,
		},
		Sources: SourcesConfig{},
	}

	err := cfg.Validate()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port: 0, // Invalid
			Host: "localhost",
		},
		Cache: CacheConfig{
			TTL:    30 * time.Minute,
			MaxAge: 1 * time.Hour,
		},
	}

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for port 0")
	}
	if err.Error() != "server.port must be set (1-65535)" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidate_InvalidReadTimeout(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 0, // Invalid
		},
		Cache: CacheConfig{
			TTL:    30 * time.Minute,
			MaxAge: 1 * time.Hour,
		},
	}

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for zero read timeout")
	}
}

func TestValidate_CreatesCacheDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "test-cache")

	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			Directory: cacheDir,
			TTL:       30 * time.Minute,
			MaxAge:    1 * time.Hour,
		},
	}

	// Directory should not exist yet
	if _, err := os.Stat(cacheDir); err == nil {
		t.Fatal("cache directory should not exist yet")
	}

	err := cfg.Validate()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Directory should be created
	if _, err := os.Stat(cacheDir); err != nil {
		t.Errorf("cache directory should exist after validate: %v", err)
	}
}

func TestValidate_DefaultsCacheDirectory(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			Directory: "", // Should be set to default
			TTL:       30 * time.Minute,
			MaxAge:    1 * time.Hour,
		},
	}

	err := cfg.Validate()

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if cfg.Cache.Directory == "" {
		t.Error("Cache.Directory should not be empty after validate")
	}
	if !filepath.IsAbs(cfg.Cache.Directory) {
		t.Errorf("Cache.Directory should be absolute path, got %q", cfg.Cache.Directory)
	}
}

func TestValidate_InvalidCacheTTL(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			TTL:    0, // Invalid
			MaxAge: 1 * time.Hour,
		},
	}

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error for zero TTL")
	}
}

func TestValidate_InvalidCacheMaxAge(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			Host:        "localhost",
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			TTL:    1 * time.Hour,
			MaxAge: 30 * time.Minute, // MaxAge < TTL is invalid
		},
	}

	err := cfg.Validate()

	if err == nil {
		t.Error("expected error when MaxAge < TTL")
	}
}

func TestValidate_DefaultsRulesFile(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Port:        8000,
			ReadTimeout: 10 * time.Second,
		},
		Cache: CacheConfig{
			TTL:    30 * time.Minute,
			MaxAge: 1 * time.Hour,
		},
		Validation: ValidationConfig{
			RulesFile: "", // Should be set to default
		},
	}

	err := cfg.Validate()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check that RulesFile was set to default
	if cfg.Validation.RulesFile != "./config/rules.yaml" {
		t.Errorf("expected RulesFile to be set to './config/rules.yaml', got '%s'", cfg.Validation.RulesFile)
	}
}

func TestFileExists(t *testing.T) {
	// Create a temporary file
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Existing file", tmpFile, true},
		{"Non-existent file", filepath.Join(t.TempDir(), "nonexistent.txt"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fileExists(tt.path)
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfig_AllDefaults(t *testing.T) {
	cfg, err := Load("nonexistent.yaml")

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check all default values
	if cfg.Server.Port != 8000 {
		t.Errorf("Server.Port: got %d, want 8000", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host: got %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("Server.ReadTimeout: got %v, want %v", cfg.Server.ReadTimeout, 10*time.Second)
	}
	if cfg.Server.WriteTimeout != 10*time.Second {
		t.Errorf("Server.WriteTimeout: got %v, want %v", cfg.Server.WriteTimeout, 10*time.Second)
	}
	if cfg.Server.IdleTimeout != 60*time.Second {
		t.Errorf("Server.IdleTimeout: got %v, want %v", cfg.Server.IdleTimeout, 60*time.Second)
	}

	if cfg.Cache.TTL != 30*time.Minute {
		t.Errorf("Cache.TTL: got %v, want %v", cfg.Cache.TTL, 30*time.Minute)
	}
	if cfg.Cache.MaxAge != 24*time.Hour {
		t.Errorf("Cache.MaxAge: got %v, want %v", cfg.Cache.MaxAge, 24*time.Hour)
	}
	if cfg.Cache.MergeBuckets != 256 {
		t.Errorf("Cache.MergeBuckets: got %d, want 256", cfg.Cache.MergeBuckets)
	}

	if cfg.Sources.FetchTimeout != 10*time.Second {
		t.Errorf("Sources.FetchTimeout: got %v, want %v", cfg.Sources.FetchTimeout, 10*time.Second)
	}
	if cfg.Sources.MaxSize != 10*1024*1024 {
		t.Errorf("Sources.MaxSize: got %d, want %d", cfg.Sources.MaxSize, 10*1024*1024)
	}
	if cfg.Sources.MaxSources != 1000 {
		t.Errorf("Sources.MaxSources: got %d, want 1000", cfg.Sources.MaxSources)
	}

	if cfg.Validation.MaxPatterns != 20 {
		t.Errorf("Validation.MaxPatterns: got %d, want 20", cfg.Validation.MaxPatterns)
	}
	if cfg.Validation.MaxPatternLen != 100 {
		t.Errorf("Validation.MaxPatternLen: got %d, want 100", cfg.Validation.MaxPatternLen)
	}
	if cfg.Validation.MaxCountries != 20 {
		t.Errorf("Validation.MaxCountries: got %d, want 20", cfg.Validation.MaxCountries)
	}
	if cfg.Validation.MaxMergeIDs != 20 {
		t.Errorf("Validation.MaxMergeIDs: got %d, want 20", cfg.Validation.MaxMergeIDs)
	}

	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level: got %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format: got %q, want %q", cfg.Logging.Format, "json")
	}
}

func TestLoad_WithValidYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	// Create a minimal valid config file
	yaml := `
server:
  port: 9000
  host: localhost
cache:
  ttl: 1h
  max_age: 48h
`

	if err := os.WriteFile(configFile, []byte(yaml), 0o644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	cfg, err := Load(configFile)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Server.Port != 9000 {
		t.Errorf("Server.Port: got %d, want 9000", cfg.Server.Port)
	}
	if cfg.Server.Host != "localhost" {
		t.Errorf("Server.Host: got %q, want %q", cfg.Server.Host, "localhost")
	}
	if cfg.Cache.TTL != 1*time.Hour {
		t.Errorf("Cache.TTL: got %v, want %v", cfg.Cache.TTL, 1*time.Hour)
	}
}

func TestLoad_WithInvalidYAMLFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "bad.yaml")

	// Create an invalid YAML file
	yaml := `
server:
  port: invalid
  host: localhost
bad yaml: [
`

	if err := os.WriteFile(configFile, []byte(yaml), 0o644); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	_, err := Load(configFile)

	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

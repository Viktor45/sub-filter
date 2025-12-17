// main_test.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub-filter/internal/utils"
)

// TestIsValidSourceURL проверяет функцию isValidSourceURL.
func TestIsValidSourceURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com/sub", true},
		{"http://example.com/sub", true},
		{"https://localhost/sub", false},
		{"https://127.0.0.1/sub", false},
		{"https://192.168.1.1/sub", false},
		{"https://example.local/sub", false},
		{"ftp://example.com", false},
		{"not-a-url", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isValidSourceURL(tt.url); got != tt.valid {
				t.Errorf("isValidSourceURL() = %v, want %v", got, tt.valid)
			}
		})
	}
}

// TestIsLocalIP проверяет функцию isLocalIP.
func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		ip    string
		local bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
		{"invalid", true}, // Treats invalid as local
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isLocalIP(tt.ip); got != tt.local {
				t.Errorf("isLocalIP() = %v, want %v", got, tt.local)
			}
		})
	}
}

// TestLoadConfigFromArgsOrFile проверяет логику загрузки конфигурации.
func TestLoadConfigFromArgsOrFile(t *testing.T) {
	tempDir := t.TempDir()
	tempConfigFile := filepath.Join(tempDir, "test_config.yaml")
	tempRulesFile := filepath.Join(tempDir, "test_rules.yaml")
	tempSourcesFile := filepath.Join(tempDir, "test_sources.txt")
	tempBadWordsFile := filepath.Join(tempDir, "test_bad.txt")
	tempUAgentFile := filepath.Join(tempDir, "test_ua.txt")
	tempCountriesFile := filepath.Join(tempDir, "test_countries.yaml")

	// Записываем countries.yaml в НОВОМ формате
	countriesYAML := `
AD:
  cca3: AND
  flag: "🇦🇩"
  name: Andorra
  native: "Andorra|Principat d'Andorra"
AE:
  cca3: ARE
  flag: "🇦🇪"
  name: United Arab Emirates
  native: "دولة الإمارات العربية المتحدة|الإمارات العربية المتحدة"
`
	if err := os.WriteFile(tempCountriesFile, []byte(countriesYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Записываем основной config.yaml
	configContent := fmt.Sprintf(`
sources_file: "%s"
rules_file: "%s"
bad_words_file: "%s"
uagent_file: "%s"
countries_file: "%s"
cache_dir: "%s"
cache_ttl: 1800s
`, tempSourcesFile, tempRulesFile, tempBadWordsFile, tempUAgentFile, tempCountriesFile, filepath.Join(tempDir, "cache"))

	err := os.WriteFile(tempConfigFile, []byte(configContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to write temp config file: %v", err)
	}
	t.Logf("Config file written to: %s", tempConfigFile)

	// Правила
	if err := os.WriteFile(tempRulesFile, []byte(`
vless:
  required_params: [encryption, sni]
  forbidden_values: { security: ["none"] }
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Источники
	if err := os.WriteFile(tempSourcesFile, []byte("https://example.com/sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Bad words и UA
	if err := os.WriteFile(tempBadWordsFile, []byte("badword\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempUAgentFile, []byte("test-agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("Load from existing file", func(t *testing.T) {
		cfg, err := loadConfigFromArgsOrFile(tempConfigFile, "", []string{"8080"})
		if err != nil {
			t.Fatalf("loadConfigFromArgsOrFile failed: %v", err)
		}

		if cfg.SourcesFile != tempSourcesFile {
			t.Errorf("Expected SourcesFile %s, got %s", tempSourcesFile, cfg.SourcesFile)
		}
		if cfg.RulesFile != tempRulesFile {
			t.Errorf("Expected RulesFile %s, got %s", tempRulesFile, cfg.RulesFile)
		}
		if cfg.CountriesFile != tempCountriesFile {
			t.Errorf("Expected CountriesFile %s, got %s", tempCountriesFile, cfg.CountriesFile)
		}
		if len(cfg.Countries) != 2 {
			t.Errorf("Expected 2 countries, got %d", len(cfg.Countries))
		}
		if _, ok := cfg.Countries["AD"]; !ok {
			t.Error("Country AD not loaded")
		}
		if cfg.Countries["AD"].Name != "Andorra" {
			t.Errorf("Expected name 'Andorra', got %q", cfg.Countries["AD"].Name)
		}
		if cfg.Countries["AD"].Native != "Andorra|Principat d'Andorra" {
			t.Errorf("Expected native 'Andorra|Principat d'Andorra', got %q", cfg.Countries["AD"].Native)
		}

		if len(cfg.BadWords) == 0 || cfg.BadWords[0] != "badword" {
			t.Errorf("Expected BadWords [\"badword\"], got %v", cfg.BadWords)
		}
		if len(cfg.AllowedUA) == 0 || cfg.AllowedUA[0] != "test-agent" {
			t.Errorf("Expected AllowedUA [\"test-agent\"], got %v", cfg.AllowedUA)
		}
		if len(cfg.Rules) == 0 {
			t.Error("Expected rules to be loaded")
		}
		if len(cfg.Sources) == 0 {
			t.Error("Expected sources to be loaded")
		}
	})

	t.Run("Load from args if file doesn't exist", func(t *testing.T) {
		args := []string{"8081", "3600", tempSourcesFile, tempBadWordsFile, tempUAgentFile, tempRulesFile}
		cfg, err := loadConfigFromArgsOrFile("nonexistent.yaml", "", args)
		if err != nil {
			t.Fatalf("loadConfigFromArgsOrFile failed: %v", err)
		}
		if cfg.CacheTTL != 3600*time.Second {
			t.Errorf("Expected CacheTTL 3600s, got %v", cfg.CacheTTL)
		}
		if cfg.SourcesFile != tempSourcesFile {
			t.Errorf("Expected SourcesFile %s, got %s", tempSourcesFile, cfg.SourcesFile)
		}
		// В режиме CLI без countries_file — мапа стран пустая
		if len(cfg.Countries) != 0 {
			t.Errorf("Expected empty countries in CLI mode, got %d", len(cfg.Countries))
		}
	})
}

// TestParseCountryCodes проверяет парсинг и валидацию кодов стран
func TestParseCountryCodes(t *testing.T) {
	countries := map[string]utils.CountryInfo{
		"AD": {CCA3: "AND", Name: "Andorra"},
		"AE": {CCA3: "ARE", Name: "UAE"},
		"US": {CCA3: "USA", Name: "United States"},
	}

	tests := []struct {
		name        string
		input       string
		expectErr   bool
		expectCodes []string
	}{
		{"single", "AD", false, []string{"AD"}},
		{"multiple", "AD,AE,US", false, []string{"AD", "AE", "US"}},
		{"with spaces", " AD , AE ", false, []string{"AD", "AE"}},
		{"duplicates", "AD,AD,AE", false, []string{"AD", "AE"}},
		{"empty", "", false, nil},
		{"too many", strings.Repeat("A,", 21), true, nil},
		{"invalid format", "A12", true, nil},
		{"unknown country", "XX", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codes, err := parseCountryCodes(tt.input, countries)
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(codes) != len(tt.expectCodes) {
					t.Errorf("Expected %v, got %v", tt.expectCodes, codes)
				} else {
					for i, c := range tt.expectCodes {
						if codes[i] != c {
							t.Errorf("Expected %v, got %v", tt.expectCodes, codes)
						}
					}
				}
			}
		})
	}
}

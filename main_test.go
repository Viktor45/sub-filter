// main_test.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
		{"invalid", true}, // Рассматривается как локальный
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
	tempBadWordsFile := filepath.Join(tempDir, "test_badwords.yaml")
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

	// Запрещенные слова (YAML)
	if err := os.WriteFile(tempBadWordsFile, []byte("- pattern: \"badword\"\n  action: delete\n"), 0o644); err != nil {
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

		if len(cfg.BadWordRules) == 0 || cfg.BadWordRules[0].Pattern != "badword" || cfg.BadWordRules[0].Action != "delete" {
			t.Errorf("Expected BadWordRules with pattern 'badword' delete, got %v", cfg.BadWordRules)
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
func TestParseIDs(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{"single id", []string{"1"}, []string{"1"}},
		{"multiple values", []string{"1", "2", "3"}, []string{"1", "2", "3"}},
		{"comma separated", []string{"1,2,3"}, []string{"1", "2", "3"}},
		{"comma separated with spaces", []string{" 1, 2 ,3 "}, []string{"1", "2", "3"}},
		{"mixed forms", []string{"1,2", "3"}, []string{"1", "2", "3"}},
		{"duplicate ids", []string{"1,2,1,3"}, []string{"1", "2", "3"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIDs(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseIDs(%v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

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
			codes, err := parseCountryCodes(tt.input, countries, 20)
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

// TestBadWordRuleRegexCompilation проверяет компиляцию регулярных выражений для BadWordRule
func TestBadWordRuleRegexCompilation(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		shouldMatch []string
		shouldFail  bool
	}{
		{
			name:        "simple word boundary",
			pattern:     `\btest\b`,
			shouldMatch: []string{"this is a test string", "test server"},
			shouldFail:  false,
		},
		{
			name:        "case-insensitive flag",
			pattern:     `(?i)TEST`,
			shouldMatch: []string{"test", "Test", "TEST", "testing"},
			shouldFail:  false,
		},
		{
			name:        "complex IPv4 pattern",
			pattern:     `(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.)`,
			shouldMatch: []string{"localhost:443", "127.0.0.1:8080", "192.168.1.1:443", "10.0.0.1"},
			shouldFail:  false,
		},
		{
			name:        "version pattern v1.2.3",
			pattern:     `\[?v\d+\.\d+(\.\d+)?\]?`,
			shouldMatch: []string{"[v1.2]", "v1.2.3", "[v2.0]", "v3.4.5"},
			shouldFail:  false,
		},
		{
			name:        "invalid regex",
			pattern:     `[invalid(regex`,
			shouldMatch: []string{},
			shouldFail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected regex compilation to fail for pattern %q", tt.pattern)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected regex compilation error: %v", err)
			}
			for _, match := range tt.shouldMatch {
				if !re.MatchString(match) {
					t.Errorf("Pattern %q should match %q but didn't", tt.pattern, match)
				}
			}
		})
	}
}

// TestCreateProxyProcessorsStripAction проверяет strip-действие (вырезание совпадения)
func TestCreateProxyProcessorsStripAction(t *testing.T) {
	badRules := []BadWordRule{
		{Pattern: `(?i)\btest\b`, Action: "strip"},
		{Pattern: `\[demo\]`, Action: "strip"},
	}

	// Компилируем процессоры
	type compiledRule struct {
		re     *regexp.Regexp
		action string
		raw    string
	}
	compiled := make([]compiledRule, 0, len(badRules))
	for _, br := range badRules {
		if br.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(br.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %q: %v", br.Pattern, err)
		}
		act := strings.ToLower(strings.TrimSpace(br.Action))
		if act != "strip" && act != "delete" {
			act = "delete"
		}
		compiled = append(compiled, compiledRule{re: re, action: act, raw: br.Pattern})
	}

	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		for _, cr := range compiled {
			if cr.re.MatchString(decoded) {
				if cr.action == "strip" {
					newFrag := cr.re.ReplaceAllString(decoded, " ")
					// Сжимаем множественные пробелы в один
					multiSpaceRe := regexp.MustCompile(`\s+`)
					newFrag = multiSpaceRe.ReplaceAllString(newFrag, " ")
					newFrag = strings.TrimSpace(newFrag)
					return newFrag, false, ""
				}
				return fragment, true, fmt.Sprintf("bad word match rule: %q", cr.raw)
			}
		}
		return fragment, false, ""
	}

	tests := []struct {
		name         string
		input        string
		expectedFrag string
		shouldReject bool
	}{
		{
			name:         "strip 'test' from fragment",
			input:        "my test server",
			expectedFrag: "my server",
			shouldReject: false,
		},
		{
			name:         "strip [demo] marker",
			input:        "server [demo] prod",
			expectedFrag: "server prod",
			shouldReject: false,
		},
		{
			name:         "no match, keep original",
			input:        "production server",
			expectedFrag: "production server",
			shouldReject: false,
		},
		{
			name:         "case-insensitive match (TEST)",
			input:        "my TEST server",
			expectedFrag: "my server",
			shouldReject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frag, hasBad, reason := checkBadWords(tt.input)
			if tt.shouldReject {
				if !hasBad {
					t.Errorf("Expected rejection but got accepted: %q", frag)
				}
			} else {
				if hasBad {
					t.Errorf("Expected no rejection but got: %v", reason)
				}
				if frag != tt.expectedFrag {
					t.Errorf("Expected fragment %q, got %q", tt.expectedFrag, frag)
				}
			}
		})
	}
}

// TestCreateProxyProcessorsDeleteAction проверяет delete-действие (удаление целой строки)
func TestCreateProxyProcessorsDeleteAction(t *testing.T) {
	badRules := []BadWordRule{
		{Pattern: `(?i)\[(spam|fraud|malware)\]`, Action: "delete"},
		{Pattern: `(?i)localhost|127\.0\.0\.1`, Action: "delete"},
	}

	// Компилируем процессоры
	type compiledRule struct {
		re     *regexp.Regexp
		action string
		raw    string
	}
	compiled := make([]compiledRule, 0, len(badRules))
	for _, br := range badRules {
		if br.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(br.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern %q: %v", br.Pattern, err)
		}
		act := strings.ToLower(strings.TrimSpace(br.Action))
		if act != "strip" && act != "delete" {
			act = "delete"
		}
		compiled = append(compiled, compiledRule{re: re, action: act, raw: br.Pattern})
	}

	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		for _, cr := range compiled {
			if cr.re.MatchString(decoded) {
				if cr.action == "strip" {
					newFrag := strings.TrimSpace(cr.re.ReplaceAllString(decoded, ""))
					return newFrag, false, ""
				}
				return fragment, true, fmt.Sprintf("bad word match rule: %q", cr.raw)
			}
		}
		return fragment, false, ""
	}

	tests := []struct {
		name         string
		input        string
		shouldReject bool
	}{
		{
			name:         "reject spam-marked server",
			input:        "server [SPAM]",
			shouldReject: true,
		},
		{
			name:         "reject malware-marked server",
			input:        "proxy [malware]",
			shouldReject: true,
		},
		{
			name:         "reject localhost",
			input:        "localhost:443",
			shouldReject: true,
		},
		{
			name:         "reject 127.0.0.1",
			input:        "127.0.0.1:8080",
			shouldReject: true,
		},
		{
			name:         "accept legitimate server",
			input:        "example.com server",
			shouldReject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, hasBad, reason := checkBadWords(tt.input)
			if tt.shouldReject {
				if !hasBad {
					t.Errorf("Expected rejection but got accepted for input: %q", tt.input)
				}
			} else {
				if hasBad {
					t.Errorf("Expected acceptance but got rejection with reason: %v", reason)
				}
			}
		})
	}
}

// TestBadWordRuleParsing проверяет загрузку и парсинг YAML-файла с badword-правилами
func TestBadWordRuleParsing(t *testing.T) {
	tempDir := t.TempDir()
	badwordsFile := filepath.Join(tempDir, "badwords.yaml")

	// Создаём YAML-файл с правилами
	yamlContent := `
- pattern: '(?i)\btest\b'
  action: strip
- pattern: '\[demo\]'
  action: strip
- pattern: '(?i)\[(spam|fraud)\]'
  action: delete
- pattern: 'localhost'
  action: delete
`
	if err := os.WriteFile(badwordsFile, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("Failed to write badwords file: %v", err)
	}

	// Загружаем и парсим
	rules, err := loadBadWordsFile(badwordsFile)
	if err != nil {
		t.Fatalf("Failed to load badwords file: %v", err)
	}

	if len(rules) != 4 {
		t.Fatalf("Expected 4 rules, got %d", len(rules))
	}

	// Проверяем структуру
	expectedRules := []struct {
		pattern string
		action  string
	}{
		{`(?i)\btest\b`, "strip"},
		{`\[demo\]`, "strip"},
		{`(?i)\[(spam|fraud)\]`, "delete"},
		{`localhost`, "delete"},
	}

	for i, exp := range expectedRules {
		if rules[i].Pattern != exp.pattern {
			t.Errorf("Rule %d: expected pattern %q, got %q", i, exp.pattern, rules[i].Pattern)
		}
		if rules[i].Action != exp.action {
			t.Errorf("Rule %d: expected action %q, got %q", i, exp.action, rules[i].Action)
		}
	}
}

// TestBadWordRuleFallback проверяет fallback на старый текстовый формат
func TestBadWordRuleFallback(t *testing.T) {
	tempDir := t.TempDir()
	badwordsFile := filepath.Join(tempDir, "badwords.txt")

	// Создаём старый текстовый формат (одна строка = одно слово для delete)
	textContent := "spam\nmalware\ntest\n"
	if err := os.WriteFile(badwordsFile, []byte(textContent), 0o644); err != nil {
		t.Fatalf("Failed to write badwords file: %v", err)
	}

	rules, err := loadBadWordsFile(badwordsFile)
	if err != nil {
		t.Fatalf("Failed to load badwords file: %v", err)
	}

	if len(rules) != 3 {
		t.Fatalf("Expected 3 rules from fallback, got %d", len(rules))
	}

	// Все правила должны быть с action "delete"
	for i, rule := range rules {
		if rule.Action != "delete" {
			t.Errorf("Rule %d: expected action 'delete', got %q", i, rule.Action)
		}
	}

	// Проверяем паттерны
	expectedPatterns := []string{"spam", "malware", "test"}
	for i, exp := range expectedPatterns {
		if rules[i].Pattern != exp {
			t.Errorf("Rule %d: expected pattern %q, got %q", i, exp, rules[i].Pattern)
		}
	}
}

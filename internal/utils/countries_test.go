// internal/utils/countries_test.go
package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCountries(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "countries.yaml")
	testContent := `AD:
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
	if err := os.WriteFile(tempFile, []byte(testContent), 0o644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	countries, err := LoadCountries(tempFile)
	if err != nil {
		t.Fatalf("LoadCountries failed: %v", err)
	}
	if len(countries) != 2 {
		t.Errorf("Expected 2 countries, got %d", len(countries))
	}

	ad, ok := countries["AD"]
	if !ok {
		t.Fatal("Country AD not found in loaded map")
	}
	if ad.CCA3 != "AND" {
		t.Errorf("Expected CCA3 'AND', got %q", ad.CCA3)
	}
	if ad.Flag != "🇦🇩" {
		t.Errorf("Expected flag '🇦🇩', got %q", ad.Flag)
	}
	if ad.Name != "Andorra" {
		t.Errorf("Expected name 'Andorra', got %q", ad.Name)
	}
	if ad.Native != "Andorra|Principat d'Andorra" {
		t.Errorf("Expected native 'Andorra|Principat d'Andorra', got %q", ad.Native)
	}
}

func TestGetCountryFilterStrings(t *testing.T) {
	countryMap := map[string]CountryInfo{
		"AD": {
			CCA3:   "AND",
			Flag:   "🇦🇩",
			Name:   "Andorra",
			Native: "Andorra|Principat d'Andorra",
		},
	}

	strings := GetCountryFilterStrings("AD", countryMap)
	expected := []string{"AND", "🇦🇩", "Andorra", "Principat d'Andorra"}
	if len(strings) != len(expected) {
		t.Fatalf("Expected %d terms, got %d: %v", len(expected), len(strings), strings)
	}

	seen := make(map[string]bool)
	for _, s := range strings {
		seen[s] = true
	}
	for _, e := range expected {
		if !seen[e] {
			t.Errorf("Missing expected term: %q", e)
		}
	}
}

func TestIsFragmentMatchingCountry(t *testing.T) {
	filter := []string{"AND", "🇦🇩", "Andorra", "Principat d'Andorra"}
	if !IsFragmentMatchingCountry("#Server 🇦🇩", filter) {
		t.Error("Expected match for flag")
	}
	if !IsFragmentMatchingCountry("#Andorra Node", filter) {
		t.Error("Expected match for name")
	}
	if IsFragmentMatchingCountry("#France", filter) {
		t.Error("Expected no match for France")
	}
}

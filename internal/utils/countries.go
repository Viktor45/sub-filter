// Package utils предоставляет вспомогательные функции для работы со
// списками стран и формирования фильтров по странам.
//
//nolint:revive
package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CountryInfo описывает минимальную информацию о стране, используемую
// в конфигурационных файлах (config/countries.yaml).
type CountryInfo struct {
	CCA3   string `mapstructure:"cca3"`
	Flag   string `mapstructure:"flag"`
	Name   string `mapstructure:"name"`   // Common name only
	Native string `mapstructure:"native"` // "A|B|C"
}

// --- REST Countries API structs ---
type Country struct {
	Name struct {
		Common     string `json:"common"`
		Official   string `json:"official"`
		NativeName map[string]struct {
			Common   string `json:"common"`
			Official string `json:"official"`
		} `json:"nativeName"`
	} `json:"name"`
	Cca2 string `json:"cca2"`
	Cca3 string `json:"cca3"`
	Flag string `json:"flag"`
}

// CountryYAML служит для сериализации/десериализации данных стран в YAML.
type CountryYAML struct {
	CCA3   string `yaml:"cca3"`
	Flag   string `yaml:"flag"`
	Name   string `yaml:"name"`
	Native string `yaml:"native,omitempty"`
}

func dedupJoin(values []string) string {
	seen := make(map[string]bool)
	unique := []string{}
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		unique = append(unique, v)
	}
	return strings.Join(unique, "|")
}

// GenerateCountries получает список стран из REST API и сохраняет
// их в файл ./config/countries.yaml в формате, ожидаемом приложением.
// Используется в режиме CLI для генерации обновлённого списка стран.
func GenerateCountries() {
	resp, err := http.Get("https://restcountries.com/v3.1/all?fields=cca2,cca3,flag,name,nativeName")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var countries []Country
	if err := json.Unmarshal(body, &countries); err != nil {
		panic(err)
	}

	result := make(map[string]CountryYAML)

	for _, c := range countries {
		cca2 := strings.ToUpper(c.Cca2)
		if cca2 == "" {
			continue
		}

		var nativeParts []string
		for _, lang := range c.Name.NativeName {
			nativeParts = append(nativeParts, lang.Common, lang.Official)
		}

		result[cca2] = CountryYAML{
			CCA3:   strings.ToUpper(c.Cca3),
			Flag:   c.Flag,
			Name:   c.Name.Common,
			Native: dedupJoin(nativeParts),
		}
	}

	keys := make([]string, 0, len(result))
	for k := range result {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sorted := make(map[string]CountryYAML)
	for _, k := range keys {
		sorted[k] = result[k]
	}

	out, err := yaml.Marshal(sorted)
	if err != nil {
		panic(err)
	}

	configDir := "./config"
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		panic(fmt.Errorf("mkdir config: %w", err))
	}

	if err := os.WriteFile(filepath.Join(configDir, "countries.yaml"), out, 0o644); err != nil {
		panic(err)
	}

	fmt.Println("✅ countries.yaml создан в требуемом формате")
}

// LoadCountries загружает файл стран YAML и возвращает карту код->CountryInfo.
func LoadCountries(filePath string) (map[string]CountryInfo, error) {
	if filePath == "" {
		return make(map[string]CountryInfo), nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read countries file: %w", err)
	}

	var countries map[string]CountryInfo
	if err := yaml.Unmarshal(data, &countries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal countries YAML: %w", err)
	}

	return countries, nil
}

// GetCountryFilterStrings возвращает набор строк для поиска/фильтрации
// для указанного кода страны (CCA2). Результат включает CCA3, флаг,
// название и native-имена.
func GetCountryFilterStrings(countryCode string, countryMap map[string]CountryInfo) []string {
	if countryCode == "" {
		return []string{}
	}
	countryCode = strings.ToUpper(countryCode)
	info, ok := countryMap[countryCode]
	if !ok {
		return []string{}
	}

	var searchTerms []string

	if info.CCA3 != "" {
		searchTerms = append(searchTerms, info.CCA3)
	}
	if info.Flag != "" {
		searchTerms = append(searchTerms, info.Flag)
	}
	if info.Name != "" {
		searchTerms = append(searchTerms, info.Name)
	}
	if info.Native != "" {
		parts := strings.Split(info.Native, "|")
		for _, part := range parts {
			if part != "" {
				searchTerms = append(searchTerms, part)
			}
		}
	}

	seen := make(map[string]bool)
	var unique []string
	for _, term := range searchTerms {
		lower := strings.ToLower(term)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, term)
		}
	}
	return unique
}

// GetCountryFilterStringsForMultiple объединяет фильтры для нескольких кодов стран.
func GetCountryFilterStringsForMultiple(codes []string, countryMap map[string]CountryInfo) []string {
	if len(codes) == 0 {
		return []string{}
	}
	var all []string
	seen := make(map[string]bool)
	for _, code := range codes {
		terms := GetCountryFilterStrings(code, countryMap)
		for _, t := range terms {
			if t != "" && !seen[t] {
				seen[t] = true
				all = append(all, t)
			}
		}
	}
	return all
}

// IsFragmentMatchingCountry проверяет, содержит ли фрагмент одну из строк фильтра.
func IsFragmentMatchingCountry(fragment string, filterStrings []string) bool {
	if len(filterStrings) == 0 {
		return true
	}
	lowerFragment := strings.ToLower(FullyDecode(fragment))
	for _, term := range filterStrings {
		if strings.Contains(lowerFragment, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

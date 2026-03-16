// pkg/config/config.go
// Пакет config предоставляет централизованное управление конфигурацией приложения
// с поддержкой загрузки из файла, переменных окружения и валидацией.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// SafeSource содержит URL источника и резолвнутый IP-адрес для подключения.
type SafeSource struct {
	URL string
	IP  net.IP
}

// SourceMap отображает идентификатор источника в его описание (SafeSource).
type SourceMap map[string]*SafeSource

// BadWordRule описывает одно правило фильтрации bad-слов.
type BadWordRule struct {
	Pattern string `yaml:"pattern"`
	Action  string `yaml:"action"`
}

// Config представляет полную конфигурацию приложения
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Cache      CacheConfig      `yaml:"cache"`
	Sources    SourcesConfig    `yaml:"sources"`
	Validation ValidationConfig `yaml:"validation"`
	Logging    LoggingConfig    `yaml:"logging"`

	// Runtime-loaded data
	SourcesMap   SourceMap                      `yaml:"-"`
	Rules        map[string]validator.Validator `yaml:"-"`
	Countries    map[string]utils.CountryInfo   `yaml:"-"`
	BadWordRules []BadWordRule                  `yaml:"-"`
	AllowedUA    []string                       `yaml:"-"`
}

// ServerConfig содержит параметры HTTP-сервера
type ServerConfig struct {
	Port         uint16        `yaml:"port" default:"8000"`
	Host         string        `yaml:"host" default:"0.0.0.0"`
	ReadTimeout  time.Duration `yaml:"read_timeout" default:"10s"`
	WriteTimeout time.Duration `yaml:"write_timeout" default:"10s"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" default:"60s"`
}

// CacheConfig содержит параметры кэширования
type CacheConfig struct {
	Directory    string        `yaml:"directory"`
	TTL          time.Duration `yaml:"ttl" default:"30m"`
	MaxAge       time.Duration `yaml:"max_age" default:"24h"`
	CleanupTime  time.Duration `yaml:"cleanup_interval" default:"2m"`
	MergeBuckets int           `yaml:"merge_buckets" default:"256"`
}

// SourcesConfig содержит параметры источников прокси
type SourcesConfig struct {
	File         string        `yaml:"file"`
	FetchTimeout time.Duration `yaml:"fetch_timeout" default:"10s"`
	MaxSize      int64         `yaml:"max_size" default:"10485760"` // 10MB
	MaxSources   int           `yaml:"max_sources" default:"1000"`
}

// ValidationConfig содержит параметры правил валидации
type ValidationConfig struct {
	RulesFile         string   `yaml:"rules_file"`
	BadWordsFile      string   `yaml:"bad_words_file"`
	CountriesFile     string   `yaml:"countries_file"`
	UAFile            string   `yaml:"ua_file"`
	AllowedUserAgents []string `yaml:"allowed_user_agents"`
	MaxPatterns       int      `yaml:"max_patterns" default:"20"`
	MaxPatternLen     int      `yaml:"max_pattern_length" default:"100"`
	MaxCountries      int      `yaml:"max_countries" default:"20"`
	MaxMergeIDs       int      `yaml:"max_merge_ids" default:"20"`
}

// LoggingConfig содержит параметры логирования
type LoggingConfig struct {
	Level  string `yaml:"level" default:"info"`  // debug, info, warn, error
	Format string `yaml:"format" default:"json"` // json, text
}

// Load загружает и валидирует конфигурацию из файла и переменных окружения
func Load(configPath string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         8000,
			Host:         "0.0.0.0",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Cache: CacheConfig{
			TTL:          30 * time.Minute,
			MaxAge:       24 * time.Hour,
			CleanupTime:  2 * time.Minute,
			MergeBuckets: 256,
		},
		Sources: SourcesConfig{
			FetchTimeout: 10 * time.Second,
			MaxSize:      10 * 1024 * 1024,
			MaxSources:   1000,
		},
		Validation: ValidationConfig{
			MaxPatterns:   20,
			MaxPatternLen: 100,
			MaxCountries:  20,
			MaxMergeIDs:   20,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	// Загрузить из файла, если он существует
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Переопределить переменными окружения
	if port := os.Getenv("SERVER_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &cfg.Server.Port)
	}
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}

	// Загрузить runtime данные
	if err := cfg.loadRuntimeData(); err != nil {
		return nil, fmt.Errorf("failed to load runtime data: %w", err)
	}

	// Загрузить дополнительные файлы
	if cfg.Validation.UAFile != "" {
		if uaList, err := loadTextFile(cfg.Validation.UAFile); err == nil {
			cfg.Validation.AllowedUserAgents = uaList
		}
	}

	// Валидировать конфигурацию
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadRuntimeData загружает данные из файлов конфигурации
func (c *Config) loadRuntimeData() error {
	// Загрузить источники
	if c.Sources.File != "" {
		sources, err := loadSourcesFromFile(c.Sources.File)
		if err != nil {
			return fmt.Errorf("failed to load sources: %w", err)
		}
		c.SourcesMap = sources
	}

	// Загрузить правила
	if c.Validation.RulesFile != "" {
		rules, err := loadRulesOrDefault(c.Validation.RulesFile)
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		c.Rules = rules
	}

	// Загрузить bad words
	if c.Validation.BadWordsFile != "" {
		if rules, err := loadBadWordsFile(c.Validation.BadWordsFile); err == nil {
			c.BadWordRules = rules
		}
	}

	// Загрузить страны
	if c.Validation.CountriesFile != "" {
		if countries, err := utils.LoadCountries(c.Validation.CountriesFile); err == nil {
			c.Countries = countries
		}
	}

	return nil
}

// Validate выполняет валидацию конфигурации
func (c *Config) Validate() error {
	// Валидация сервера
	if c.Server.Port == 0 {
		return errors.New("server.port must be set (1-65535)")
	}
	if c.Server.ReadTimeout == 0 {
		return errors.New("server.read_timeout must be > 0")
	}

	// Валидация кэша
	if c.Cache.Directory == "" {
		c.Cache.Directory = filepath.Join(os.TempDir(), "sub-filter-cache")
	}
	if c.Cache.TTL == 0 {
		return errors.New("cache.ttl must be > 0")
	}
	if c.Cache.MaxAge < c.Cache.TTL {
		return errors.New("cache.max_age must be >= cache.ttl")
	}

	// Создать директорию кэша, если нужно
	if err := os.MkdirAll(c.Cache.Directory, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Файлы валидации
	if c.Validation.RulesFile == "" {
		c.Validation.RulesFile = "./config/rules.yaml"
	}
	if c.Validation.BadWordsFile == "" {
		c.Validation.BadWordsFile = "./config/bad_words.yaml"
	}

	// Проверить наличие требуемых файлов
	// Проверяем только явно указанные файлы, не установленные по умолчанию
	requiredFiles := []string{}
	if c.Sources.File != "" {
		requiredFiles = append(requiredFiles, c.Sources.File)
	}
	// RulesFile проверяем только если он был явно установлен (не по умолчанию)
	if c.Validation.RulesFile != "" && c.Validation.RulesFile != "./config/rules.yaml" {
		requiredFiles = append(requiredFiles, c.Validation.RulesFile)
	}

	for _, file := range requiredFiles {
		if !fileExists(file) {
			return fmt.Errorf("required file not found: %s", file)
		}
	}

	return nil
}

// fileExists проверяет, существует ли файл
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadTextFile загружает текстовый файл и возвращает список строк
func loadTextFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func isValidSourceURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		return false
	}
	if strings.HasPrefix(host, "127.") {
		return false
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	return true
}

func IsIPAllowed(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	return true
}

func loadSourcesFromFile(sourcesFile string) (SourceMap, error) {
	lines, err := loadTextFile(sourcesFile)
	if err != nil {
		return nil, err
	}
	sources := make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := u.Hostname()
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if IsIPAllowed(ip) {
				sources[strconv.Itoa(validIndex)] = &SafeSource{URL: line, IP: ip}
				validIndex++
				break
			}
		}
	}
	if len(sources) < 1 {
		return nil, fmt.Errorf("source file has no valid sources: %s", sourcesFile)
	}
	return sources, nil
}

func loadRulesOrDefault(rulesFile string) (map[string]validator.Validator, error) {
	finalRulesFile := rulesFile
	if finalRulesFile == "" {
		finalRulesFile = "./config/rules.yaml"
	}
	return validator.LoadRules(finalRulesFile)
}

func loadBadWordsFile(filename string) ([]BadWordRule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var rules []BadWordRule
	if err := yaml.Unmarshal(data, &rules); err == nil && len(rules) > 0 {
		return rules, nil
	}
	// fallback: older plain-text format
	lines, err := loadTextFile(filename)
	if err != nil {
		return nil, err
	}
	out := make([]BadWordRule, 0, len(lines))
	for _, l := range lines {
		if l == "" {
			continue
		}
		out = append(out, BadWordRule{Pattern: l, Action: "delete"})
	}
	return out, nil
}

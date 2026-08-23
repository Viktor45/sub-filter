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
	"unicode"

	"gopkg.in/yaml.v3"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// SafeSource содержит URL источника и разрешенный IP-адрес для подключения.
type SafeSource struct {
	URL string
	IP  net.IP
}

// SourceMap отображает идентификатор источника в его описание (SafeSource).
type SourceMap map[string]*SafeSource

// BadWordRule описывает одно правило фильтрации bad-слов.
type BadWordRule struct {
	Pattern     string `yaml:"pattern"`
	Action      string `yaml:"action"`
	Replacement string `yaml:"replacement,omitempty"`
}

// Config представляет полную конфигурацию приложения
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Cache      CacheConfig      `yaml:"cache"`
	Sources    SourcesConfig    `yaml:"sources"`
	Validation ValidationConfig `yaml:"validation"`
	Logging    LoggingConfig    `yaml:"logging"`

	// Данные, загружаемые на этапе выполнения
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

		// Сначала пытаемся распарсить в структуру (новый формат)
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		// Поддержка legacy плоского формата ключей (sources_file, rules_file и т.д.)
		var flat map[string]any
		if err := yaml.Unmarshal(data, &flat); err == nil {
			if v, ok := flat["sources_file"].(string); ok && cfg.Sources.File == "" {
				cfg.Sources.File = v
			}
			if v, ok := flat["rules_file"].(string); ok && cfg.Validation.RulesFile == "" {
				cfg.Validation.RulesFile = v
			}
			// старое имя без underscore
			if v, ok := flat["bad_words_file"].(string); ok && cfg.Validation.BadWordsFile == "" {
				cfg.Validation.BadWordsFile = v
			}
			if v, ok := flat["countries_file"].(string); ok && cfg.Validation.CountriesFile == "" {
				cfg.Validation.CountriesFile = v
			}
			if v, ok := flat["uagent_file"].(string); ok && cfg.Validation.UAFile == "" {
				cfg.Validation.UAFile = v
			}
			if v, ok := flat["cache_dir"].(string); ok && cfg.Cache.Directory == "" {
				cfg.Cache.Directory = v
			}
			if v, ok := flat["cache_ttl"].(string); ok && cfg.Cache.TTL == 0 {
				if d, err := time.ParseDuration(v); err == nil {
					cfg.Cache.TTL = d
				}
			}
			if v, ok := flat["max_country_codes"].(int); ok && cfg.Validation.MaxCountries == 0 {
				cfg.Validation.MaxCountries = v
			}
			if v, ok := flat["max_country_codes"].(int64); ok && cfg.Validation.MaxCountries == 0 {
				cfg.Validation.MaxCountries = int(v)
			}
			if v, ok := flat["max_merge_ids"].(int); ok && cfg.Validation.MaxMergeIDs == 0 {
				cfg.Validation.MaxMergeIDs = v
			}
			if v, ok := flat["merge_buckets"].(int); ok && cfg.Cache.MergeBuckets == 0 {
				cfg.Cache.MergeBuckets = v
			}
			// имя rules_file может быть задано плоско как rules_file
			if v, ok := flat["rules_file"].(string); ok && cfg.Validation.RulesFile == "" {
				cfg.Validation.RulesFile = v
			}
		}
	}

	// Переопределить переменными окружения
	if port := os.Getenv("SUBFILTER_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &cfg.Server.Port)
	}
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}

	// Валидировать конфигурацию (установит значения по умолчанию для путей)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Загрузить runtime данные (только после установки значений по умолчанию)
	if err := cfg.loadRuntimeData(); err != nil {
		return nil, fmt.Errorf("failed to load runtime data: %w", err)
	}

	// Загрузить дополнительные файлы
	if cfg.Validation.UAFile != "" {
		if uaList, err := loadTextFile(cfg.Validation.UAFile); err == nil {
			cfg.Validation.AllowedUserAgents = uaList
		}
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

	// Загрузить правила (если файл присутствует). Отсутствие файла не является фатальной ошибкой —
	// используем пустой набор правил.
	if c.Validation.RulesFile != "" {
		if fileExists(c.Validation.RulesFile) {
			rules, err := loadRulesOrDefault(c.Validation.RulesFile)
			if err != nil {
				return fmt.Errorf("failed to load rules: %w", err)
			}
			c.Rules = rules
		} else {
			c.Rules = make(map[string]validator.Validator)
		}
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
		} else {
			// Допускаем отсутствие/некорректность файла стран и используем пустую карту
			c.Countries = make(map[string]utils.CountryInfo)
		}
	} else {
		c.Countries = make(map[string]utils.CountryInfo)
	}

	return nil
}

// Validate выполняет валидацию конфигурации с расширенными проверками схемы.
// Нулевые значения заполняются дефолтами (идемпотентность), а явно заданные
// некорректные значения вызывают ошибку.
func (c *Config) Validate() error {
	// --- Сервер ---
	if c.Server.Port == 0 {
		return errors.New("server.port must be set (1-65535)")
	}
	if c.Server.Port > 65535 {
		return errors.New("server.port must be <= 65535")
	}
	if c.Server.ReadTimeout == 0 {
		return errors.New("server.read_timeout must be > 0")
	}
	// Дефолты для необязательных тайм-аутов
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 10 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 60 * time.Second
	}
	// Верхние границы для явно заданных значений
	if c.Server.ReadTimeout > 5*time.Minute {
		return errors.New("server.read_timeout must be <= 5m")
	}
	if c.Server.WriteTimeout > 5*time.Minute {
		return errors.New("server.write_timeout must be <= 5m")
	}
	if c.Server.IdleTimeout > 10*time.Minute {
		return errors.New("server.idle_timeout must be <= 10m")
	}

	// Валидация хоста — только валидные IP/hostname
	if c.Server.Host != "" && c.Server.Host != "0.0.0.0" {
		if ip := net.ParseIP(c.Server.Host); ip == nil {
			if !isValidHostname(c.Server.Host) {
				return fmt.Errorf("invalid server.host: %s", c.Server.Host)
			}
		}
	}

	// --- Кэш ---
	if c.Cache.Directory == "" {
		c.Cache.Directory = filepath.Join(os.TempDir(), "sub-filter-cache")
	}
	if c.Cache.TTL == 0 {
		return errors.New("cache.ttl must be > 0")
	}
	if c.Cache.MaxAge < c.Cache.TTL {
		return errors.New("cache.max_age must be >= cache.ttl")
	}
	if c.Cache.MaxAge > 7*24*time.Hour {
		return errors.New("cache.max_age must be <= 168h")
	}
	if c.Cache.CleanupTime == 0 {
		c.Cache.CleanupTime = 2 * time.Minute
	}
	if c.Cache.CleanupTime > time.Hour {
		return errors.New("cache.cleanup_interval must be <= 1h")
	}
	if c.Cache.MergeBuckets <= 0 {
		c.Cache.MergeBuckets = 256
	}
	if c.Cache.MergeBuckets > 4096 {
		return errors.New("cache.merge_buckets must be <= 4096")
	}

	// Создать директорию кэша, если нужно
	if err := os.MkdirAll(c.Cache.Directory, 0o750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// --- Источники ---
	if c.Sources.FetchTimeout == 0 {
		c.Sources.FetchTimeout = 10 * time.Second
	}
	if c.Sources.FetchTimeout > 2*time.Minute {
		return errors.New("sources.fetch_timeout must be <= 2m")
	}
	if c.Sources.MaxSize <= 0 {
		c.Sources.MaxSize = 10 * 1024 * 1024
	}
	if c.Sources.MaxSize > 100*1024*1024 {
		return errors.New("sources.max_size must be <= 100MB")
	}
	if c.Sources.MaxSources <= 0 {
		c.Sources.MaxSources = 1000
	}
	if c.Sources.MaxSources > 10000 {
		return errors.New("sources.max_sources must be <= 10000")
	}

	// --- Файлы валидации ---
	if c.Validation.RulesFile == "" {
		c.Validation.RulesFile = "./config/rules.yaml"
	}
	if c.Validation.BadWordsFile == "" {
		c.Validation.BadWordsFile = "./config/bad_words.yaml"
	}
	if c.Validation.CountriesFile == "" {
		c.Validation.CountriesFile = "./config/countries.yaml"
	}

	// --- Лимиты валидации ---
	if c.Validation.MaxPatterns <= 0 {
		c.Validation.MaxPatterns = 20
	}
	if c.Validation.MaxPatterns > 100 {
		return errors.New("validation.max_patterns must be <= 100")
	}
	if c.Validation.MaxPatternLen <= 0 {
		c.Validation.MaxPatternLen = 100
	}
	if c.Validation.MaxPatternLen > 500 {
		return errors.New("validation.max_pattern_length must be <= 500")
	}
	if c.Validation.MaxCountries <= 0 {
		c.Validation.MaxCountries = 20
	}
	if c.Validation.MaxCountries > 100 {
		return errors.New("validation.max_countries must be <= 100")
	}
	if c.Validation.MaxMergeIDs <= 0 {
		c.Validation.MaxMergeIDs = 20
	}
	if c.Validation.MaxMergeIDs > 200 {
		return errors.New("validation.max_merge_ids must be <= 200")
	}

	// --- Проверка наличия требуемых файлов ---
	if c.Sources.File != "" {
		if !fileExists(c.Sources.File) {
			return fmt.Errorf("sources file not found: %s", c.Sources.File)
		}
	}
	if c.Validation.RulesFile != "" && c.Validation.RulesFile != "./config/rules.yaml" {
		if !fileExists(c.Validation.RulesFile) {
			return fmt.Errorf("rules file not found: %s", c.Validation.RulesFile)
		}
	}
	if c.Validation.UAFile != "" && c.Validation.UAFile != "./config/uagent.txt" {
		if !fileExists(c.Validation.UAFile) {
			return fmt.Errorf("ua file not found: %s", c.Validation.UAFile)
		}
	}

	return nil
}

// isValidHostname проверяет валидность hostname
func isValidHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	// Валидация hostname по RFC 1123
	for _, part := range strings.Split(hostname, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for i, r := range part {
			if i == 0 && (r == '-' || r == '_') {
				return false
			}
			if i == len(part)-1 && (r == '-' || r == '_') {
				return false
			}
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
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

	// Если хост указан как IP-литерал, проверяем его через общий allowlist
	if ip := net.ParseIP(host); ip != nil {
		if !IsIPAllowed(ip) {
			return false
		}
	}

	// Блокируем внутренние/служебные доменные имена
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return false
	}
	internalSuffixes := []string{".local", ".internal", ".lan", ".home.arpa", ".corp", ".intranet", ".private"}
	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(lowerHost, suffix) {
			return false
		}
	}

	// Валидируем порт, если он указан явно
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}

	// Запрещаем userinfo в URL источника (не используется и может путать парсеры)
	if u.User != nil {
		return false
	}

	return true
}

// cgnatNet — диапазон Carrier-Grade NAT (100.64.0.0/10), не должен использоваться как внешний источник.
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// benchmarkNet — диапазон 198.18.0.0/15 для бенчмаркинга сетей (RFC 2544).
var benchmarkNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("198.18.0.0/15")
	return n
}()

// IsIPAllowed проверяет, является ли IP-адрес допустимым для подключения к источнику.
// Отклоняются loopback, приватные, link-local, multicast, unspecified адреса,
// а также диапазоны CGNAT (100.64.0.0/10) и бенчмаркинга (198.18.0.0/15).
// Используется как защита от SSRF при загрузке источников подписок.
func IsIPAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// Дополнительные диапазоны, не являющиеся публичными
	if ip4 := ip.To4(); ip4 != nil {
		if cgnatNet.Contains(ip4) || benchmarkNet.Contains(ip4) {
			return false
		}
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
	// Резервный вариант: старый текстовый формат
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

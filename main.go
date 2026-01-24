// main.go
// Пакет main реализует утилиту для фильтрации прокси-подписок.
// Поддерживает два режима работы:
//   - HTTP-сервер для динамической фильтрации (/filter?id=1&c=AD)
//   - CLI-режим для однократной обработки всех подписок (--cli)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"sub-filter/hysteria2"
	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
	"sub-filter/ss"
	"sub-filter/trojan"
	"sub-filter/vless"
	"sub-filter/vmess"

	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

const (
	maxIDLength     = 64
	maxURILength    = 4096
	maxSourceBytes  = 10 * 1024 * 1024
	limiterBurst    = 5
	limiterEvery    = 100 * time.Millisecond
	cleanupInterval = 2 * time.Minute
	inactiveTimeout = 30 * time.Minute
)

var defaultCacheDir = filepath.Join(os.TempDir(), "sub-filter-cache")

// SafeSource содержит URL источника и резолвнутый IP-адрес для подключения.
type SafeSource struct {
	URL string
	IP  net.IP
}

// SourceMap отображает идентификатор источника в его описание (SafeSource).
type SourceMap map[string]*SafeSource

type AppConfig struct {
	CacheDir        string        `mapstructure:"cache_dir"`
	CacheTTL        time.Duration `mapstructure:"cache_ttl"`
	SourcesFile     string        `mapstructure:"sources_file"`
	BadWordsFile    string        `mapstructure:"bad_words_file"`
	UAgentFile      string        `mapstructure:"uagent_file"`
	RulesFile       string        `mapstructure:"rules_file"`
	CountriesFile   string        `mapstructure:"countries_file"`
	AllowedUA       []string
	BadWords        []string
	Sources         SourceMap
	Rules           map[string]validator.Validator
	Countries       map[string]utils.CountryInfo
	MaxCountryCodes int `mapstructure:"max_country_codes"`
	MaxMergeIDs     int `mapstructure:"max_merge_ids"`
	MergeBuckets    int `mapstructure:"merge_buckets"`
}

// Init устанавливает значения по умолчанию для полей AppConfig, если они не заданы.
// Это позволяет корректно запускать приложение при неполной конфигурации.
func (cfg *AppConfig) Init() {
	if cfg.CacheDir == "" {
		cfg.CacheDir = defaultCacheDir
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Minute
	}
	if cfg.SourcesFile == "" {
		cfg.SourcesFile = "./config/sub.txt"
	}
	if cfg.BadWordsFile == "" {
		cfg.BadWordsFile = "./config/bad.txt"
	}
	if cfg.UAgentFile == "" {
		cfg.UAgentFile = "./config/uagent.txt"
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = "./config/rules.yaml"
	}
	if cfg.CountriesFile == "" {
		cfg.CountriesFile = "./config/countries.yaml"
	}
	if cfg.MaxCountryCodes == 0 {
		cfg.MaxCountryCodes = 20
	}
	if cfg.MaxMergeIDs == 0 {
		cfg.MaxMergeIDs = 20
	}
	if cfg.MergeBuckets == 0 {
		cfg.MergeBuckets = 256
	}
}

var (
	ipLimiter              sync.Map // map[string]*rate.Limiter, для безблокировочного чтения
	ipLastSeen             sync.Map // map[string]time.Time
	fetchGroup             singleflight.Group
	builtinAllowedPrefixes = []string{"clash", "happ"}
	validIDRe              = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

	// Кешированные регулярные выражения для избежания перекомпиляции
	filenameCleanupRegex  = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	validProfileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`)

	// Протокольные схемы для быстрого одноходового детектирования
	protoSchemes = [][]byte{
		[]byte("vless://"),
		[]byte("vmess://"),
		[]byte("trojan://"),
		[]byte("ss://"),
		[]byte("hysteria2://"),
		[]byte("hy2://"),
	}
)

type ProxyLink interface {
	Matches(s string) bool
	Process(s string) (string, string)
}

// ProxyLink описывает обработчик одного формата прокси-ссылки.
// Реализации должны определять, соответствует ли строка формату
// (`Matches`) и возвращать нормализованную строку и (опционально)
// причину отказа из `Process`.

// detectProxyScheme выполняет быстрое одноходовое детектирование протокола.
// Намного эффективнее чем 6 отдельных bytes.Contains вызовов.
func detectProxyScheme(content []byte) bool {
	for _, scheme := range protoSchemes {
		if bytes.Contains(content, scheme) {
			return true
		}
	}
	return false
}

// buildProfileHeader эффективно конструирует метаданные профиля используя strings.Builder
func buildProfileHeader(profileName, id string, countryCodes []string) string {
	var buf strings.Builder
	buf.WriteString("#profile-title: ")
	buf.WriteString(profileName)
	buf.WriteString(" filtered ")
	buf.WriteString(id)

	if len(countryCodes) > 0 {
		buf.WriteString(" (")
		for i, code := range countryCodes {
			if i > 0 {
				buf.WriteString(",")
			}
			buf.WriteString(code)
		}
		buf.WriteString(")")
	}

	return buf.String()
}

// buildProfileInterval эффективно создаёт директиву интервала обновления
func buildProfileInterval(cacheTTL time.Duration) string {
	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}
	return "#profile-update-interval: " + strconv.Itoa(updateInterval)
}

// streamProcessResponse обрабатывает тело HTTP ответа построчно
// Обрабатывает строки по мере их поступления вместо буферизации всего ответа в памяти.
// Это значительно снижает пиковое использование памяти для больших источников.
func streamProcessResponse(resp *http.Response, processor func(string) error) error {
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxSourceBytes))
	// Увеличение размера буфера для лучшей пропускной способности на больших строках
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := processor(line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return newError("Parse", "stream read error: %w", err)
	}
	return nil
}

// createHTTPClientWithDialContext создает HTTP клиента с pooling транспортом и кастомным DialContext
// Переиспользует соединения благодаря MaxIdleConns и IdleConnTimeout.
func createHTTPClientWithDialContext(_ context.Context, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialFunc,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			DisableCompression:  false,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		},
	}
}

// fetchSourceContent загружает содержимое источника из кэша или удалённого URL с поддержкой streamProcessResponse
// Параметр lineProcessor (если не nil) обрабатывает каждую строку по мере её поступления.
// Если lineProcessor == nil, функция возвращает весь контент как []byte для обратной совместимости.
// Это обеспечивает минимальное пиковое использование памяти для больших источников.
func fetchSourceContent(id string, source *SafeSource, cfg *AppConfig, origCache string, stdout bool, lineProcessor func(string) error) ([]byte, error) {
	// Проверка кэша сначала
	if !stdout {
		if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cfg.CacheTTL {
			if content, err := os.ReadFile(origCache); err == nil {
				return content, nil
			}
		}
	}

	// Парсинг URL источника для извлечения хоста и порта
	parsedSource, err := url.Parse(source.URL)
	if err != nil {
		return nil, newError("Parse", "invalid source URL: %w", err)
	}

	_, portStr, _ := net.SplitHostPort(parsedSource.Host)
	if portStr == "" {
		portStr = getDefaultPort(parsedSource.Scheme)
	}

	// Создание HTTP клиента с pooling транспортом и кастомным DialContext
	// createHTTPClientWithDialContext переиспользует соединения благодаря MaxIdleConns и IdleConnTimeout
	dialFunc := func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
	}
	client := createHTTPClientWithDialContext(context.TODO(), dialFunc)

	// Если lineProcessor предоставлен, используем streamProcessResponse для построчной обработки
	if lineProcessor != nil {
		// Использование singleflight для дедупликации одновременных запросов для того же источника
		_, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, newError("HTTP", "create request: %w", err)
			}
			req.Header.Set("User-Agent", "go-filter/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil, newError("HTTP", "fetch failed: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode >= 400 {
				return nil, newError("HTTP", "status code %d", resp.StatusCode)
			}

			// Обработка ответа построчно без буферизации
			// Это позволяет обрабатывать большие источники с минимальным пиковым использованием памяти
			if err := streamProcessResponse(resp, lineProcessor); err != nil {
				return nil, newError("Parse", "stream processing failed: %w", err)
			}

			return nil, nil
		})
		return nil, err
	}

	// Для обратной совместимости: если lineProcessor == nil, читаем весь контент как раньше
	result, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
		req, err := http.NewRequest("GET", source.URL, nil)
		if err != nil {
			return nil, newError("HTTP", "create request: %w", err)
		}
		req.Header.Set("User-Agent", "go-filter/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, newError("HTTP", "fetch failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			return nil, newError("HTTP", "status code %d", resp.StatusCode)
		}

		content, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
		if err != nil {
			return nil, newError("IO", "read failed: %w", err)
		}

		// Кеширование исходного содержимого
		if !stdout {
			tmpFile := origCache + ".tmp"
			if err := os.WriteFile(tmpFile, content, 0o644); err == nil {
				logErrorf("FileOp", "rename cache", os.Rename(tmpFile, origCache))
			}
		}

		return content, nil
	})

	if err != nil {
		return nil, err
	}

	content, ok := result.([]byte)
	if !ok {
		return nil, newError("Validate", "fetch returned unexpected type for id=%s", id)
	}

	return content, nil
}

// createProxyProcessors формирует список обработчиков ссылок для поддерживаемых протоколов.
func createProxyProcessors(badWords []string, rules map[string]validator.Validator) []ProxyLink {
	checkBadWords := func(fragment string) (bool, string) {
		if fragment == "" {
			return false, ""
		}
		decoded := utils.FullyDecode(fragment)
		lower := strings.ToLower(decoded)
		for _, word := range badWords {
			if word != "" && strings.Contains(lower, word) {
				return true, fmt.Sprintf("bad word in name: %q", word)
			}
		}
		return false, ""
	}
	getValidator := func(name string) validator.Validator {
		if v, ok := rules[name]; ok {
			return v
		}
		return &validator.GenericValidator{}
	}
	return []ProxyLink{
		vless.NewVLESSLink(badWords, utils.IsValidHost, utils.IsValidPort, checkBadWords, getValidator("vless")),
		vmess.NewVMessLink(badWords, utils.IsValidHost, checkBadWords, getValidator("vmess")),
		trojan.NewTrojanLink(badWords, utils.IsValidHost, checkBadWords, getValidator("trojan")),
		ss.NewSSLink(badWords, utils.IsValidHost, checkBadWords, getValidator("ss")),
		hysteria2.NewHysteria2Link(badWords, utils.IsValidHost, checkBadWords, getValidator("hysteria2")),
	}
}

// logErrorf логирует ошибку с категорией и контекстом
// Унифицирует все сообщения об ошибках с единообразным форматом
func logErrorf(category, context string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %s %s: %v\n", category, context, err)
	}
}

// logWarnf логирует предупреждение с категорией и контекстом
func logWarnf(category, context string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] %s %s: %v\n", category, context, err)
	}
}

// newError создаёт ошибку с категорией контекста для унифицированного логирования
// Позволяет использовать %w для обёртывания исходных ошибок
func newError(category, format string, args ...interface{}) error {
	return fmt.Errorf("[%s] "+format, append([]interface{}{category}, args...)...)
}

// loadTextFile читает текстовый файл построчно, опционально применяя
// функцию-обработчик к каждой непустой и некомментированной строке.
// Поддерживается удаление BOM (UTF-8). Возвращается слайс обработанных строк.

func loadTextFile(filename string, processor func(string) string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader := bufio.NewReader(file)
	if b, err := reader.Peek(3); err == nil && bytes.Equal(b, []byte{0xEF, 0xBB, 0xBF}) {
		_, err := reader.Discard(3)
		logWarnf("Parse", "discard BOM", err)
	}
	var result []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if processor != nil {
			line = processor(line)
		}
		result = append(result, line)
	}
	return result, scanner.Err()
}

func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func isIPAllowed(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsMulticast()
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
	if ip := net.ParseIP(host); ip != nil {
		return isIPAllowed(ip)
	}
	return true
}

func getLimiter(ip string) *rate.Limiter {
	// Быстрый путь: попытка загрузить существующий limiter (без блокировок)
	if limiterInterface, ok := ipLimiter.Load(ip); ok {
		limiter := limiterInterface.(*rate.Limiter)
		// Обновление времени последнего доступа
		ipLastSeen.Store(ip, time.Now())
		return limiter
	}

	// Медленный путь: создание нового limiter и его сохранение (блокировка только для этого IP)
	limiter := rate.NewLimiter(rate.Every(limiterEvery), limiterBurst)
	ipLimiter.Store(ip, limiter)
	ipLastSeen.Store(ip, time.Now())
	return limiter
}

// getLimiter возвращает или создаёт ограничитель скорости для указанного IP.
// Также обновляет отметку времени последнего доступа. Оптимизировано с sync.Map для безблокировочного чтения.

func cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var toDelete []string
			now := time.Now()

			// Итерирование через ipLastSeen для поиска неактивных IP
			ipLastSeen.Range(func(key, value interface{}) bool {
				ip := key.(string)
				lastSeen := value.(time.Time)
				if now.Sub(lastSeen) > inactiveTimeout {
					toDelete = append(toDelete, ip)
				}
				return true // продолжить итерацию
			})

			// Удаление неактивных IP
			if len(toDelete) > 0 {
				for _, ip := range toDelete {
					ipLimiter.Delete(ip)
					ipLastSeen.Delete(ip)
				}
			}
		}
	}
}

// cleanupLimiters периодически удаляет неиспользуемые IP ограничители из памяти.
// Функция выполняется до отмены контекста.

func isValidUserAgent(ua string, allowedUA []string) bool {
	lowerUA := strings.ToLower(ua)
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}
	for _, allowed := range allowedUA {
		if allowed != "" && strings.Contains(lowerUA, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

// isValidUserAgent проверяет, разрешён ли User-Agent запроса.
// Разрешаются встроенные префиксы и значения из конфигурации.
// Сравнение проводится без учёта регистра.

func serveFile(w http.ResponseWriter, content []byte, sourceURL, id string) {
	filename := "filtered_" + id + ".txt"
	if u, err := url.Parse(sourceURL); err == nil {
		base := path.Base(u.Path)
		if base != "" && validProfileNameRegex.MatchString(base) {
			filename = base
		}
	}
	filename = filenameCleanupRegex.ReplaceAllString(filename, "_")
	if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
		filename += ".txt"
	}
	filename = filepath.Base(filename)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	_, err := w.Write(content)
	logErrorf("HTTP", "write response", err)
}

// serveFile отправляет `content` в ответ как загружаемый .txt файл.
// Имя файла формируется из URL источника или переданного id и
// очищается для предотвращения обхода путей и недопустимых символов.

// isLocalIP возвращает true для loopback/частных адресов или если
// входная строка не распарсилась как IP. Это позволяет трактовать
// некорректные RemoteAddr как локальные для консервативной обработки.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// parseCountryCodes парсит и валидирует список кодов стран вида "AD,DE,FR".
// Возвращает отсортованный список уникальных кодов или ошибку.
func parseCountryCodes(cParam string, countryMap map[string]utils.CountryInfo, maxCodes int) ([]string, error) {
	if cParam == "" {
		return nil, nil
	}
	rawCodes := strings.Split(cParam, ",")
	if maxCodes > 0 && len(rawCodes) > maxCodes {
		return nil, newError("Validate", "too many country codes (max %d)", maxCodes)
	}

	seen := make(map[string]bool)
	var validCodes []string
	for _, code := range rawCodes {
		code = strings.ToUpper(strings.TrimSpace(code))
		if code == "" {
			continue
		}
		if len(code) != 2 || !validIDRe.MatchString(code) {
			return nil, newError("Validate", "invalid country code format: %q", code)
		}
		if _, exists := countryMap[code]; !exists {
			return nil, newError("Validate", "unknown country code: %q", code)
		}
		if !seen[code] {
			seen[code] = true
			validCodes = append(validCodes, code)
		}
	}

	sort.Strings(validCodes)
	return validCodes, nil
}

func handleMerge(w http.ResponseWriter, r *http.Request, cfg *AppConfig, proxyProcessors []ProxyLink) {
	// Общая валидация клиента: rate-limit, UA
	if status, msg := validateClientRequest(r, cfg); status != 0 {
		http.Error(w, msg, status)
		return
	}

	idList := r.URL.Query()["ids"]
	if len(idList) == 0 {
		idList = r.URL.Query()["id"]
	}
	if status, msg := validateIDs(idList, cfg); status != 0 {
		http.Error(w, msg, status)
		return
	}
	// validateIDs уже проверил лимиты, формат и существование id

	sortedIDs := make([]string, len(idList))
	copy(sortedIDs, idList)
	sort.Strings(sortedIDs)

	// Поддерживается указание нескольких кодов стран, разделённых запятой.
	countryCodes, err := parseCountryCodes(r.URL.Query().Get("c"), cfg.Countries, cfg.MaxCountryCodes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid country codes: %v", err), http.StatusBadRequest)
		return
	}

	mergeCacheKey := "merge_" + strings.Join(sortedIDs, "_")
	if len(countryCodes) > 0 {
		countryKey := strings.Join(countryCodes, "_")
		mergeCacheKey += "_c_" + countryKey
	}

	cacheFilePath := filepath.Join(cfg.CacheDir, mergeCacheKey+".txt")
	if info, err := os.Stat(cacheFilePath); err == nil && time.Since(info.ModTime()) <= cfg.CacheTTL {
		content, _ := os.ReadFile(cacheFilePath)
		serveFile(w, content, "merged_sources", mergeCacheKey)
		return
	}

	// Streaming merge: шардируем все обработанные ссылки по bucket'ам на диск,
	// затем обрабатываем каждый bucket отдельно в памяти для дедупликации.
	nBuckets := cfg.MergeBuckets
	if nBuckets <= 0 {
		nBuckets = 256
	}
	tmpDir := filepath.Join(cfg.CacheDir, "merge_tmp_"+mergeCacheKey)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create temp dir: %v", err), http.StatusInternalServerError)
		return
	}
	// Открытие файлов bucket и writers
	bucketFiles := make([]*os.File, nBuckets)
	bucketWriters := make([]*bufio.Writer, nBuckets)
	bucketLocks := make([]sync.Mutex, nBuckets)

	// Гарантируем очистку частично созданных ресурсов при раннем выходе
	success := false
	defer func() {
		if !success {
			for i := 0; i < nBuckets; i++ {
				if bucketWriters[i] != nil {
					logErrorf("FileOp", fmt.Sprintf("flush bucket_%d", i), bucketWriters[i].Flush())
				}
				if bucketFiles[i] != nil {
					logErrorf("FileOp", fmt.Sprintf("close bucket_%d", i), bucketFiles[i].Close())
				}
				logErrorf("FileOp", fmt.Sprintf("remove bucket_%d", i), os.Remove(filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i))))
			}
			logErrorf("FileOp", "remove merge temp dir", os.RemoveAll(tmpDir))
		}
	}()

	for i := 0; i < nBuckets; i++ {
		p := filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i))
		f, err := os.Create(p)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create bucket file: %v", err), http.StatusInternalServerError)
			return
		}
		bucketFiles[i] = f
		bucketWriters[i] = bufio.NewWriter(f)
	}

	// Обработка источников параллельно, запись обработанных строк в файлы bucket
	eg, ctx := errgroup.WithContext(context.Background())
	for _, id := range idList {
		id := id
		eg.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			source, exists := cfg.Sources[id]
			if !exists {
				return newError("Config", "source not found for id: %s", id)
			}
			// Обработка и запись в bucket
			if err := processSourceToBuckets(id, source, cfg, proxyProcessors, countryCodes, nBuckets, bucketWriters, &bucketLocks); err != nil {
				return newError("Process", "error processing source id '%s': %w", id, err)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		http.Error(w, fmt.Sprintf("Processing error during merge: %v", err), http.StatusInternalServerError)
		return
	}

	// Промывка и закрытие файлов bucket
	for i := 0; i < nBuckets; i++ {
		logErrorf("FileOp", fmt.Sprintf("flush bucket_%d", i), bucketWriters[i].Flush())
		logErrorf("FileOp", fmt.Sprintf("close bucket_%d", i), bucketFiles[i].Close())
	}

	// Итерирование bucket'ов, дедупликация per-bucket и сбор финальных строк
	finalLines := make([]string, 0)
	for i := 0; i < nBuckets; i++ {
		p := filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i))
		f, err := os.Open(p)
		if err != nil {
			// пропуск пустых/отсутствующих bucket'ов
			continue
		}
		scanner := bufio.NewScanner(f)
		// разрешаем длинные строки
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 4*1024*1024)
		bucketMap := make(map[string]string)
		for scanner.Scan() {
			line := scanner.Text()
			// формат: key\tfull_line
			idx := strings.IndexByte(line, '\t')
			if idx <= 0 {
				continue
			}
			key := line[:idx]
			full := line[idx+1:]
			if existing, ok := bucketMap[key]; ok {
				better := utils.CompareAndSelectBetter(full, existing)
				bucketMap[key] = better
			} else {
				bucketMap[key] = full
			}
		}
		_ = f.Close()
		for _, v := range bucketMap {
			finalLines = append(finalLines, v)
		}
		// удаление файла bucket для экономии памяти
		logErrorf("FileOp", "remove bucket file", os.Remove(p))
	}
	// удаление временной директории
	logErrorf("FileOp", "remove merge temp dir", os.Remove(tmpDir))
	sort.Strings(finalLines)

	profileName := "merged_" + strings.Join(sortedIDs, "_")
	if len(countryCodes) > 0 {
		profileName += "_" + strings.Join(countryCodes, "_")
	}
	updateInterval := int(cfg.CacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}
	profileTitle := fmt.Sprintf("#profile-title: %s", profileName)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)
	finalContent := strings.Join(append([]string{profileTitle, profileInterval, ""}, finalLines...), "\n")

	tmpFile := cacheFilePath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(finalContent), 0o644); err == nil {
		logErrorf("FileOp", "rename merge cache", os.Rename(tmpFile, cacheFilePath))
	}
	// отметка успешного завершения для избежания отложенной очистки
	success = true
	serveFile(w, []byte(finalContent), "merged_sources", mergeCacheKey)
}

// handleMerge обрабатывает несколько идентификаторов источников
// параллельно и выполняет потоковое слияние по bucket'ам на диске,
// что позволяет выполнить дедупликацию с ограниченным использованием памяти.
// Результат сохраняется в кэше и отдаётся как загружаемый файл.

// Обратите внимание: countryCode заменён на countryCodes []string
func processSource(id string, source *SafeSource, cfg *AppConfig, proxyProcessors []ProxyLink, stdout bool, countryCodes []string) (string, error) {
	// processSource загружает (или читает из кэша) источник подписки,
	// парсит его, фильтрует и нормализует прокси‑ссылки и возвращает
	// финальный контент профиля. При stdout==false результат кешируется
	// в каталоге cfg.CacheDir.
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return "", newError("Parse", "invalid source URL")
	}
	if source == nil || source.IP == nil {
		return "", newError("Validate", "missing resolved IP for source id=%s", id)
	}
	host := parsedSource.Hostname()
	if !utils.IsValidHost(host) {
		return "", newError("Validate", "invalid source host: %s", host)
	}

	cacheSuffix := ""
	if len(countryCodes) > 0 {
		cacheSuffix = "_c_" + strings.Join(countryCodes, "_")
	}

	origCache := filepath.Join(cfg.CacheDir, "orig_"+id+cacheSuffix+".txt")
	modCache := filepath.Join(cfg.CacheDir, "mod_"+id+cacheSuffix+".txt")
	rejectedCache := filepath.Join(cfg.CacheDir, "rejected_"+id+cacheSuffix+".txt")

	if !utils.IsPathSafe(origCache, cfg.CacheDir) ||
		!utils.IsPathSafe(modCache, cfg.CacheDir) ||
		!utils.IsPathSafe(rejectedCache, cfg.CacheDir) {
		return "", newError("Validate", "unsafe cache path for id=%s", id)
	}

	if !stdout {
		if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cfg.CacheTTL {
			content, err := os.ReadFile(modCache)
			if err == nil {
				return string(content), nil
			}
		}
	}

	var origContent []byte
	// Использование вспомогательной функции для загрузки содержимого
	// Передаём nil для lineProcessor, чтобы использовать старый режим (возврат []byte)
	content, err := fetchSourceContent(id, source, cfg, origCache, stdout, nil)
	if err != nil {
		return "", err
	}
	origContent = content

	hasProxy := detectProxyScheme(origContent)
	if !hasProxy {
		decoded := utils.AutoDecodeBase64(origContent)
		if detectProxyScheme(decoded) {
			origContent = decoded
		}
	}

	var out []string
	var rejectedLines []string
	rejectedLines = append(rejectedLines, "## Source: "+source.URL)
	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}
		var processedLine, reason string
		handled := false
		for _, p := range proxyProcessors {
			if p.Matches(originalLine) {
				processedLine, reason = p.Process(originalLine)
				handled = true
				break
			}
		}
		if !handled {
			reason = "unsupported protocol"
		}
		if processedLine != "" {
			if len(countryCodes) > 0 {
				parsedProcessed, parseErr := url.Parse(processedLine)
				if parseErr == nil && parsedProcessed.Fragment != "" {
					allFilterStrings := utils.GetCountryFilterStringsForMultiple(countryCodes, cfg.Countries)
					if !utils.IsFragmentMatchingCountry(parsedProcessed.Fragment, allFilterStrings) {
						continue
					}
				} else {
					continue
				}
			}
			out = append(out, processedLine)
		} else {
			if reason == "" {
				reason = "processing failed"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}

	if !stdout {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpFile, []byte(rejectedContent), 0o644); err == nil {
			logErrorf("FileOp", "rename rejected cache", os.Rename(tmpFile, rejectedCache))
		}
	}

	profileName := "filtered_" + id
	if u, err := url.Parse(source.URL); err == nil {
		base := path.Base(u.Path)
		if base != "" && validProfileNameRegex.MatchString(base) {
			profileName = strings.TrimSuffix(base, ".txt")
		}
	}
	profileName = filenameCleanupRegex.ReplaceAllString(profileName, "_")

	profileTitle := buildProfileHeader(profileName, id, countryCodes)
	profileInterval := buildProfileInterval(cfg.CacheTTL)
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	if !stdout {
		tmpFile := modCache + ".tmp"
		if err := os.WriteFile(tmpFile, []byte(final), 0o644); err != nil {
			logErrorf("FileOp", "remove temp file", os.Remove(tmpFile))
			return "", err
		}
		logErrorf("FileOp", "rename modified cache", os.Rename(tmpFile, modCache))
	}
	return final, nil
}

// processSourceToBuckets обрабатывает источник подписки и записывает каждую
// валидную обработанную ссылку в соответствующий bucket writer в формате
// "key\tfull_line\n". Это позволяет затем выполнять дедупликацию по частям,
// уменьшая пиковое использование памяти.
func processSourceToBuckets(id string, source *SafeSource, cfg *AppConfig, proxyProcessors []ProxyLink, countryCodes []string, nBuckets int, bucketWriters []*bufio.Writer, bucketLocks *[]sync.Mutex) error {
	// processSourceToBuckets загружает (или читает из кэша) источник и
	// записывает нормализованные записи прокси в writers bucket'ов на диске.
	// Каждая запись имеет вид "key\tfull_line\n" для последующей
	// дедупликации по bucket'ам.
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return newError("Parse", "invalid source URL")
	}
	if source == nil || source.IP == nil {
		return newError("Validate", "missing resolved IP for source id=%s", id)
	}
	host := parsedSource.Hostname()
	if !utils.IsValidHost(host) {
		return newError("Validate", "invalid source host: %s", host)
	}

	cacheSuffix := ""
	if len(countryCodes) > 0 {
		cacheSuffix = "_c_" + strings.Join(countryCodes, "_")
	}

	origCache := filepath.Join(cfg.CacheDir, "orig_"+id+cacheSuffix+".txt")
	rejectedCache := filepath.Join(cfg.CacheDir, "rejected_"+id+cacheSuffix+".txt")

	if !utils.IsPathSafe(origCache, cfg.CacheDir) || !utils.IsPathSafe(rejectedCache, cfg.CacheDir) {
		return newError("Validate", "unsafe cache path for id=%s", id)
	}

	var rejectedLines []string
	rejectedLines = append(rejectedLines, "## Source: "+source.URL)

	// Инициализация буферов batch для каждого bucket
	const batchSize = 10
	bucketBatches := make([][]string, nBuckets)
	for i := 0; i < nBuckets; i++ {
		bucketBatches[i] = make([]string, 0, batchSize)
	}

	// Вспомогательная лямбда для промывки batch в bucket writer с одной блокировкой
	flushBatch := func(bucketIdx int) error {
		if len(bucketBatches[bucketIdx]) == 0 {
			return nil
		}
		(*bucketLocks)[bucketIdx].Lock()
		defer (*bucketLocks)[bucketIdx].Unlock()
		for _, line := range bucketBatches[bucketIdx] {
			_, err := bucketWriters[bucketIdx].WriteString(line)
			if err != nil {
				logErrorf("IO", fmt.Sprintf("write bucket_%d", bucketIdx), err)
				return err
			}
		}
		bucketBatches[bucketIdx] = bucketBatches[bucketIdx][:0] // сброс batch
		return nil
	}

	// Обработка ответа построчно без буферизации всего контента
	// lineProcessor callback обрабатывает каждую строку по мере её поступления из HTTP ответа
	lineProcessor := func(originalLine string) error {
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			return nil
		}
		var processedLine, reason string
		handled := false
		for _, p := range proxyProcessors {
			if p.Matches(originalLine) {
				processedLine, reason = p.Process(originalLine)
				handled = true
				break
			}
		}
		if !handled {
			reason = "unsupported protocol"
		}
		if processedLine != "" {
			if len(countryCodes) > 0 {
				parsedProcessed, parseErr := url.Parse(processedLine)
				if parseErr == nil && parsedProcessed.Fragment != "" {
					allFilterStrings := utils.GetCountryFilterStringsForMultiple(countryCodes, cfg.Countries)
					if !utils.IsFragmentMatchingCountry(parsedProcessed.Fragment, allFilterStrings) {
						return nil
					}
				} else {
					return nil
				}
			}
			// Нормализация ключа и запись в bucket (батчированная)
			key, err := utils.NormalizeLinkKey(processedLine)
			if err != nil {
				return nil
			}
			// вычисление bucket
			h := fnv.New32a()
			_, err = h.Write([]byte(key))
			if err != nil {
				logWarnf("Hash", "write", err)
				return nil
			}
			b := int(h.Sum32() % uint32(nBuckets))
			// Добавление в буфер batch вместо немедленной записи
			bucketBatches[b] = append(bucketBatches[b], key+"\t"+processedLine+"\n")
			// Промывка batch при достижении batchSize
			if len(bucketBatches[b]) >= batchSize {
				if err := flushBatch(b); err != nil {
					return err
				}
			}
		} else {
			if reason == "" {
				reason = "processing failed"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
		return nil
	}

	// Использование вспомогательной функции для загрузки содержимого с потоковой обработкой
	// fetchSourceContent обрабатывает каждую строку через lineProcessor без буферизации
	_, err = fetchSourceContent(id, source, cfg, origCache, false, lineProcessor)
	if err != nil {
		return err
	}

	// Промывка оставшихся batch для всех bucket'ов
	for i := 0; i < nBuckets; i++ {
		if err := flushBatch(i); err != nil {
			// Логирование ошибки но продолжение промывки остальных bucket'ов
			logErrorf("IO", fmt.Sprintf("flush bucket_%d", i), err)
		}
	}

	// запись кэша отклонённых
	rejectedContent := strings.Join(rejectedLines, "\n")
	tmpFile := rejectedCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(rejectedContent), 0o644); err == nil {
		logErrorf("FileOp", "rename rejected cache", os.Rename(tmpFile, rejectedCache))
	}
	return nil
}

// validateClientRequest выполняет общие проверки запроса: rate-limit и User-Agent.
// Возвращает HTTP-статус != 0 и текст ошибки для прямого ответа клиенту.
func validateClientRequest(r *http.Request, cfg *AppConfig) (int, string) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if !isLocalIP(clientIP) {
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			return http.StatusTooManyRequests, "Too Many Requests"
		}
	}
	if !isValidUserAgent(r.Header.Get("User-Agent"), cfg.AllowedUA) {
		return http.StatusForbidden, "Forbidden: invalid User-Agent"
	}
	return 0, ""
}

// validateIDs проверяет список id: длину, формат и существование в cfg.Sources.
// Возвращает HTTP-статус != 0 и текст ошибки для прямого ответа клиенту.
func validateIDs(idList []string, cfg *AppConfig) (int, string) {
	if len(idList) == 0 {
		return http.StatusBadRequest, "Missing 'ids' parameter"
	}
	if cfg.MaxMergeIDs > 0 && len(idList) > cfg.MaxMergeIDs {
		return http.StatusBadRequest, "Too many IDs requested"
	}
	for _, id := range idList {
		if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
			return http.StatusBadRequest, fmt.Sprintf("Invalid id: %s", id)
		}
		if _, exists := cfg.Sources[id]; !exists {
			return http.StatusBadRequest, fmt.Sprintf("Unknown id: %s", id)
		}
	}
	return 0, ""
}

// остальные функции (loadSourcesFromFile, loadConfigFromFile, loadCountriesFromFile, loadConfigFromArgsOrFile, printRulesInfo, loadRulesOrDefault, main) — без изменений, кроме:
// - в main: в CLI-режиме countryCode остаётся пустым ([]string{})
// - в /filter: вызов parseCountryCodes и передача []string в processSource

func loadSourcesFromFile(sourcesFile string) (SourceMap, error) {
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		return nil, err
	}
	sources := make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			logWarnf("Config", fmt.Sprintf("skipping invalid source: %s", line), nil)
			continue
		}
		u, _ := url.Parse(line)
		host := u.Hostname()
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if isIPAllowed(ip) {
				sources[strconv.Itoa(validIndex)] = &SafeSource{URL: line, IP: ip}
				validIndex++
				break
			}
		}
	}
	return sources, nil
}

func loadConfigFromFile(configPath string) (*AppConfig, error) {
	viper.Reset() // ←←← КЛЮЧЕВОЕ ИЗМЕНЕНИЕ
	viper.SetConfigFile(configPath)
	ext := filepath.Ext(configPath)
	if ext == ".yaml" || ext == ".yml" {
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	cfg := &AppConfig{}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Применяем значения по умолчанию ТОЛЬКО если поля пустые
	if cfg.CacheDir == "" {
		cfg.CacheDir = defaultCacheDir
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Minute
	}
	if cfg.SourcesFile == "" {
		cfg.SourcesFile = "./config/sub.txt"
	}
	if cfg.BadWordsFile == "" {
		cfg.BadWordsFile = "./config/bad.txt"
	}
	if cfg.UAgentFile == "" {
		cfg.UAgentFile = "./config/uagent.txt"
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = "./config/rules.yaml"
	}
	if cfg.CountriesFile == "" {
		cfg.CountriesFile = "./config/countries.yaml"
	}

	if len(cfg.Sources) == 0 {
		sources, err := loadSourcesFromFile(cfg.SourcesFile)
		if err != nil {
			return nil, err
		}
		cfg.Sources = sources
	}
	if len(cfg.BadWords) == 0 {
		bw, _ := loadTextFile(cfg.BadWordsFile, strings.ToLower)
		cfg.BadWords = bw
	}
	if len(cfg.AllowedUA) == 0 {
		ua, _ := loadTextFile(cfg.UAgentFile, nil)
		cfg.AllowedUA = ua
	}
	rules, err := validator.LoadRules(cfg.RulesFile)
	if err != nil {
		return nil, err
	}
	cfg.Rules = rules
	countries, err := utils.LoadCountries(cfg.CountriesFile)
	if err != nil {
		logWarnf("Config", "load countries file", err)
		cfg.Countries = make(map[string]utils.CountryInfo)
	} else {
		cfg.Countries = countries
	}

	// Гарантируем что источники имеют резолвленные IP при предоставлении через конфиг файл
	for id, s := range cfg.Sources {
		if s == nil {
			return nil, newError("Config", "source entry %s is nil", id)
		}
		if s.IP == nil {
			u, err := url.Parse(s.URL)
			if err != nil || u.Hostname() == "" {
				return nil, newError("Parse", "invalid source URL for id=%s", id)
			}
			ips, err := net.LookupIP(u.Hostname())
			if err != nil || len(ips) == 0 {
				return nil, newError("Network", "failed to resolve host for source id=%s: %v", id, err)
			}
			for _, ip := range ips {
				if isIPAllowed(ip) {
					s.IP = ip
					break
				}
			}
			if s.IP == nil {
				return nil, newError("Network", "no allowed IP found for source id=%s", id)
			}
			cfg.Sources[id] = s
		}
	}
	return cfg, nil
}

func loadConfigFromArgsOrFile(configPath, _ string, args []string) (*AppConfig, error) {
	var cfg *AppConfig
	var err error
	if _, statErr := os.Stat(configPath); statErr == nil {
		cfg, err = loadConfigFromFile(configPath)
		if err != nil {
			return nil, err
		}
	} else {
		if len(args) < 1 {
			return nil, newError("Config", "usage: <port> [cache_ttl] [sources] [bad] [ua] [rules]")
		}
		cacheTTLSeconds := 1800
		sourcesFile := "./config/sub.txt"
		badWordsFile := "./config/bad.txt"
		uagentFile := "./config/uagent.txt"
		rulesFile := "./config/rules.yaml"
		if len(args) >= 2 {
			if sec, err := strconv.Atoi(args[1]); err == nil && sec > 0 {
				cacheTTLSeconds = sec
			}
		}
		if len(args) >= 3 {
			sourcesFile = args[2]
		}
		if len(args) >= 4 {
			badWordsFile = args[3]
		}
		if len(args) >= 5 {
			uagentFile = args[4]
		}
		if len(args) >= 6 {
			rulesFile = args[5]
		}
		cfg = &AppConfig{
			CacheDir:     defaultCacheDir,
			CacheTTL:     time.Duration(cacheTTLSeconds) * time.Second,
			SourcesFile:  sourcesFile,
			BadWordsFile: badWordsFile,
			UAgentFile:   uagentFile,
			RulesFile:    rulesFile,
		}
		cfg.Init()
		cfg.Sources, err = loadSourcesFromFile(cfg.SourcesFile)
		if err != nil {
			return nil, err
		}
		cfg.BadWords, _ = loadTextFile(cfg.BadWordsFile, strings.ToLower)
		cfg.AllowedUA, _ = loadTextFile(cfg.UAgentFile, nil)
		cfg.Rules, err = loadRulesOrDefault(cfg.RulesFile)
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func printRulesInfo(cfg *AppConfig) {
	rulesFileToPrint := cfg.RulesFile
	if rulesFileToPrint == "" {
		rulesFileToPrint = "./config/rules.yaml"
	}
	if cfg.RulesFile != "" || len(cfg.Rules) > 0 {
		ruleCounts := make(map[string]int)
		for proto, val := range cfg.Rules {
			if gv, ok := val.(*validator.GenericValidator); ok {
				r := gv.Rule
				count := len(r.RequiredParams) + len(r.AllowedValues) + len(r.ForbiddenValues) + len(r.Conditional)
				ruleCounts[proto] = count
			}
		}
		fmt.Printf("Rules file: %s\n", rulesFileToPrint)
		fmt.Printf("Loaded rules for protocols: %d\n", len(cfg.Rules))
		for proto, count := range ruleCounts {
			fmt.Printf("  - %s: %d rules\n", proto, count)
		}
	} else {
		fmt.Printf("Rules file: %s (not found or empty, using empty validators)\n", rulesFileToPrint)
	}
}

func loadRulesOrDefault(rulesFile string) (map[string]validator.Validator, error) {
	finalRulesFile := rulesFile
	if finalRulesFile == "" {
		finalRulesFile = "./config/rules.yaml"
	}
	return validator.LoadRules(finalRulesFile)
}

func main() {
	var (
		cliMode         = flag.Bool("cli", false, "Run in CLI mode")
		stdout          = flag.Bool("stdout", false, "Print results to stdout (CLI only)")
		config          = flag.String("config", "", "Path to config file (YAML/JSON/TOML). Defaults to ./config/config.yaml if not specified.")
		countries       = flag.Bool("countries", false, "Generate ./config/countries.yaml from REST API (CLI only)")
		countryCodesCLI = flag.String("country", "", "Filter by country codes (comma-separated, max 20), e.g. --country=AR,AE")
	)
	flag.Parse()

	defaultConfigPath := "./config/config.yaml"
	if *config == "" {
		*config = defaultConfigPath
	}

	if *cliMode {
		if *countries {
			utils.GenerateCountries()
			return
		}
		cfg, err := loadConfigFromArgsOrFile(*config, defaultConfigPath, flag.Args())
		if err != nil {
			logErrorf("Config", "load config", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
			logErrorf("FileOp", "create cache dir", err)
			os.Exit(1)
		}
		fmt.Printf("Cache directory: %s\n", cfg.CacheDir)

		// Парсинг флага стран для CLI-режима
		var parsedCountryCodes []string
		if *countryCodesCLI != "" {
			var err error
			parsedCountryCodes, err = parseCountryCodes(*countryCodesCLI, cfg.Countries, cfg.MaxCountryCodes)
			if err != nil {
				logErrorf("Validate", "parse country codes", err)
				os.Exit(1)
			}
		}

		proxyProcessors := createProxyProcessors(cfg.BadWords, cfg.Rules)
		g, _ := errgroup.WithContext(context.Background())
		var mu sync.Mutex
		var outputs []string
		for id, source := range cfg.Sources {
			id, source := id, source
			g.Go(func() error {
				// ← ПЕРЕДАЁМ parsedCountryCodes вместо ""
				result, err := processSource(id, source, cfg, proxyProcessors, *stdout, parsedCountryCodes)
				if err != nil {
					return newError("Process", "process failed %s: %w", id, err)
				}
				if *stdout {
					mu.Lock()
					outputs = append(outputs, fmt.Sprintf("# Source %s\n%s", id, result))
					mu.Unlock()
				} else {
					fmt.Printf("Success: mod_%s.txt saved\n", id)
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			logErrorf("Process", "processing sources", err)
			os.Exit(1)
		}
		if *stdout {
			for _, out := range outputs {
				fmt.Println(out)
			}
		}
		return
	}

	if len(flag.Args()) < 1 {
		logErrorf("Config", "invalid arguments", fmt.Errorf("usage: %s <port> [cache_ttl] [sources] [bad] [ua] [rules]", os.Args[0]))
		os.Exit(1)
	}
	port := flag.Args()[0]
	cfg, err := loadConfigFromArgsOrFile(*config, defaultConfigPath, flag.Args())
	if err != nil {
		logErrorf("Config", "load config", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		logErrorf("FileOp", "create cache dir", err)
		os.Exit(1)
	}
	fmt.Printf("Countries loaded: %d\n", len(cfg.Countries))
	proxyProcessors := createProxyProcessors(cfg.BadWords, cfg.Rules)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cleanupLimiters(ctx)
	printRulesInfo(cfg)

	http.HandleFunc("/filter", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !isLocalIP(clientIP) {
			limiter := getLimiter(clientIP)
			if !limiter.Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		if !isValidUserAgent(r.Header.Get("User-Agent"), cfg.AllowedUA) {
			http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
			return
		}
		id := r.URL.Query().Get("id")
		countryCodes, err := parseCountryCodes(r.URL.Query().Get("c"), cfg.Countries, cfg.MaxCountryCodes)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid country codes: %v", err), http.StatusBadRequest)
			return
		}
		if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		source, exists := cfg.Sources[id]
		if !exists {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		if _, err := processSource(id, source, cfg, proxyProcessors, false, countryCodes); err != nil {
			http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
			return
		}
		cacheFileName := "mod_" + id + ".txt"
		if len(countryCodes) > 0 {
			cacheFileName = "mod_" + id + "_c_" + strings.Join(countryCodes, "_") + ".txt"
		}
		content, err := os.ReadFile(filepath.Join(cfg.CacheDir, cacheFileName))
		if err != nil {
			http.Error(w, "Result not found", http.StatusNotFound)
			return
		}
		serveFile(w, content, source.URL, id)
	})

	http.HandleFunc("/merge", func(w http.ResponseWriter, r *http.Request) {
		handleMerge(w, r, cfg, proxyProcessors)
	})

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logErrorf("Network", "listen", err)
		os.Exit(1)
	}
	fmt.Printf("Proxy Filter Server Starting...\n")
	fmt.Printf("Port: %s\n", port)
	fmt.Printf("Cache TTL: %d sec\n", cfg.CacheTTL/time.Second)
	fmt.Printf("Cache dir: %s\n", cfg.CacheDir)
	fmt.Printf("Sources: %d\n", len(cfg.Sources))
	server := &http.Server{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	errChan := make(chan error, 1)
	go func() { errChan <- server.Serve(listener) }()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errChan:
		logErrorf("Network", "server", err)
		os.Exit(1)
	case <-sigChan:
		fmt.Println("\nShutting down gracefully...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logErrorf("Network", "shutdown", err)
			os.Exit(1)
		}
	}
	fmt.Println("Server stopped.")
}

// pkg/service/service.go
package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"sub-filter/hysteria2"
	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
	"sub-filter/pkg/cache"
	"sub-filter/pkg/config"
	"sub-filter/pkg/errors"
	"sub-filter/pkg/logger"
	"sub-filter/ss"
	"sub-filter/trojan"
	"sub-filter/vless"
	"sub-filter/vmess"
)

const (
	MaxRegexPatterns = 20
	MaxRegexLength   = 100
)

// IsRegexSafe проверяет шаблон регулярного выражения на устойчивость к ReDoS-атакам
func IsRegexSafe(pattern string) bool {
	// Блокируем явно опасные конструкции
	dangerousPatterns := []string{
		"(.*)*",   // вложенные * квантификаторы
		"(.*)+",   // вложенные + квантификаторы
		"(.+)*",   // вложенные + квантификаторы
		"(.+)+",   // вложенные + квантификаторы
		"(\\s+)*", // вложенные whitespace квантификаторы
		"(\\s+)+", // вложенные whitespace квантификаторы
		"(.*?)*",  // вложенные lazy квантификаторы
		"(.*?)+",  // вложенные lazy квантификаторы
	}
	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return false
		}
	}
	// Проверяем сложность: количество скобок
	opening := strings.Count(pattern, "(")
	if opening > 3 {
		return false // слишком много групп - потенциальный ReDoS
	}
	return true
}

// protoSchemes используются detectProxyScheme для быстрой однопроходной проверки.
// Скопировано из main.go чтобы сохранить независимость пакета service.
var protoSchemes = [][]byte{
	[]byte("vless://"),
	[]byte("vmess://"),
	[]byte("trojan://"),
	[]byte("ss://"),
	[]byte("hysteria2://"),
	[]byte("hy2://"),
}

// detectProxyScheme выполняет быстрое одноходовое детектирование протокола.
// Намного эффективнее чем несколько отдельных bytes.Contains вызовов.
func detectProxyScheme(content []byte) bool {
	for _, scheme := range protoSchemes {
		if bytes.Contains(content, scheme) {
			return true
		}
	}
	return false
}

// ProxyLink это интерфейс, реализованный процессорами протоколов (ss, vless, etc).
// Это сделано намеренно; любые значения, чьи методы совпадают, могут быть
// сохранены в этот интерфейс независимо от пакета.
type ProxyLink interface {
	Matches(s string) bool
	Process(s string) (string, string)
}

// ServiceOptions содержит данные специфичные для приложения, требуемые для логики
// фильтрации и слияния. Пакет main конструирует эту структуру при создании
// сервиса, чтобы избежать циклической зависимости.
type ServiceOptions struct {
	Sources         map[string]*config.SafeSource
	Rules           map[string]validator.Validator
	BadWordRules    []config.BadWordRule
	Countries       map[string]utils.CountryInfo
	MaxCountryCodes int
	MaxMergeIDs     int
	MergeBuckets    int
	Debug           bool
}

// Service представляет основной сервис приложения с внедрением зависимостей
type Service struct {
	// Конфигурация
	cfg *config.Config

	// Логгер
	logger *logger.Logger

	// Данные, переданные из main
	sources         map[string]*config.SafeSource
	rules           map[string]validator.Validator
	badWordRules    []config.BadWordRule
	countries       map[string]utils.CountryInfo
	maxCountryCodes int
	maxMergeIDs     int
	mergeBuckets    int
	debug           bool

	// Процессоры протоколов (ss, vmess, и т.п.)
	proxyProcessors []ProxyLink

	// Кэш регулярных выражений для производительности
	regexCache *cache.RegexCache

	// Pool буферов для оптимизации памяти
	bufferPool sync.Pool

	// Глобальные переменные, перемещенные из main.go
	ipLimiter              sync.Map // map[string]*rate.Limiter
	ipLastSeen             sync.Map // map[string]time.Time
	fetchGroup             singleflight.Group
	builtinAllowedPrefixes []string
	validIDRe              *regexp.Regexp
	filenameCleanupRegex   *regexp.Regexp
	validProfileNameRegex  *regexp.Regexp

	// HTTP сервер
	server *http.Server

	// Контекст для graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

const (
	maxIDLength = 64
)

// NewService создает новый экземпляр сервиса с dependency injection
func NewService(cfg *config.Config, log *logger.Logger, opts *ServiceOptions) (*Service, error) {
	if cfg == nil {
		return nil, errors.ConfigError("configuration is required", nil)
	}
	if log == nil {
		return nil, errors.ConfigError("logger is required", nil)
	}
	if opts == nil {
		return nil, errors.ConfigError("service options are required", nil)
	}

	ctx, cancel := context.WithCancel(context.Background())

	svc := &Service{
		cfg:             cfg,
		logger:          log,
		sources:         opts.Sources,
		rules:           opts.Rules,
		badWordRules:    opts.BadWordRules,
		countries:       opts.Countries,
		maxCountryCodes: opts.MaxCountryCodes,
		maxMergeIDs:     opts.MaxMergeIDs,
		mergeBuckets:    opts.MergeBuckets,
		debug:           opts.Debug,
		regexCache:      cache.NewRegexCache(),
		bufferPool: sync.Pool{
			New: func() any {
				return &bytes.Buffer{}
			},
		},
		builtinAllowedPrefixes: []string{"clash", "happ", "incy"},
		validIDRe:              regexp.MustCompile(`^[a-zA-Z0-9_]+$`),
		filenameCleanupRegex:   regexp.MustCompile(`[^a-zA-Z0-9._-]`),
		validProfileNameRegex:  regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`),
		ctx:                    ctx,
		cancel:                 cancel,
	}

	// Создаем proxy processors с использованием regex cache
	svc.proxyProcessors = svc.createProxyProcessors()

	// Инициализация HTTP сервера
	mux := http.NewServeMux()
	svc.registerHandlers(mux)

	svc.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	return svc, nil
}

// registerHandlers регистрирует HTTP обработчики
func (s *Service) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/filter", s.handleFilter)
	mux.HandleFunc("/merge", s.handleMerge)
	mux.HandleFunc("/health", s.handleHealth)
}

// createProxyProcessors создает процессоры протоколов с использованием regex cache
func (s *Service) createProxyProcessors() []ProxyLink {
	// Компилируем правила для ускорения
	type compiledRule struct {
		re          *regexp.Regexp
		action      string
		raw         string
		replacement string
	}

	// Ограничение количества шаблонов для предотвращения переполнения памяти
	if len(s.badWordRules) > MaxRegexPatterns {
		s.logger.Warn("Too many badword patterns, ignoring excess",
			"count", len(s.badWordRules),
			"max", MaxRegexPatterns,
		)
	}

	compiled := make([]compiledRule, 0, len(s.badWordRules))
	for i, br := range s.badWordRules {
		// Применить ограничение количества шаблонов
		if i >= MaxRegexPatterns {
			break
		}
		if br.Pattern == "" {
			continue
		}
		// Ограничить длину шаблона
		if len(br.Pattern) > MaxRegexLength {
			s.logger.Warn("Badword pattern too long",
				"length", len(br.Pattern),
				"max", MaxRegexLength,
				"pattern", br.Pattern,
			)
			continue
		}
		// Проверка шаблона регулярного выражения на устойчивость к ReDoS-атакам
		if !IsRegexSafe(br.Pattern) {
			s.logger.Warn("Dangerous badword pattern rejected",
				"pattern", br.Pattern,
			)
			continue
		}
		re, err := s.regexCache.Get(br.Pattern)
		if err != nil {
			s.logger.Warn("Failed to compile badword pattern",
				"pattern", br.Pattern,
				"error", err,
			)
			continue
		}
		act := strings.ToLower(strings.TrimSpace(br.Action))
		if act != "strip" && act != "delete" && act != "replace" {
			act = "delete"
		}
		compiled = append(compiled, compiledRule{re: re, action: act, raw: br.Pattern, replacement: br.Replacement})
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
				if cr.action == "replace" {
					newFrag := cr.re.ReplaceAllString(decoded, cr.replacement)
					return newFrag, false, ""
				}
				return fragment, true, fmt.Sprintf("bad word match rule: %q", cr.raw)
			}
		}
		return fragment, false, ""
	}
	getValidator := func(name string) validator.Validator {
		if v, ok := s.rules[name]; ok {
			return v
		}
		return &validator.GenericValidator{}
	}
	// Для совместимости формируем простой слайс паттернов (старый параметр bw)
	patterns := make([]string, 0, len(s.badWordRules))
	for _, br := range s.badWordRules {
		patterns = append(patterns, br.Pattern)
	}
	return []ProxyLink{
		vless.NewVLESSLink(patterns, utils.IsValidHost, utils.IsValidPort, checkBadWords, getValidator("vless")),
		vmess.NewVMessLink(patterns, utils.IsValidHost, checkBadWords, getValidator("vmess")),
		trojan.NewTrojanLink(patterns, utils.IsValidHost, checkBadWords, getValidator("trojan")),
		ss.NewSSLink(patterns, utils.IsValidHost, checkBadWords, getValidator("ss")),
		hysteria2.NewHysteria2Link(patterns, utils.IsValidHost, checkBadWords, getValidator("hysteria2")),
	}
}

func (s *Service) applyReplaceBadWords(line string) string {
	if line == "" {
		return line
	}
	for _, br := range s.badWordRules {
		if strings.ToLower(strings.TrimSpace(br.Action)) != "replace" {
			continue
		}
		if br.Pattern == "" || br.Replacement == "" {
			continue
		}
		if !IsRegexSafe(br.Pattern) {
			continue
		}
		re, err := s.regexCache.Get(br.Pattern)
		if err != nil {
			continue
		}
		line = re.ReplaceAllString(line, br.Replacement)
	}
	return line
}

// Start запускает HTTP сервер
func (s *Service) Start() error {
	s.logger.Info("Starting HTTP server",
		"port", s.cfg.Server.Port,
		"readTimeout", s.cfg.Server.ReadTimeout,
		"writeTimeout", s.cfg.Server.WriteTimeout,
	)

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return errors.NetworkError("failed to start HTTP server", err).
			WithContext("port", s.cfg.Server.Port)
	}
	return nil
}

// Stop останавливает сервис gracefully
func (s *Service) Stop() error {
	s.logger.Info("Stopping service")

	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return errors.NetworkError("failed to shutdown HTTP server", err)
	}

	s.logger.Info("Service stopped")
	return nil
}

// GetBuffer возвращает буфер из pool для оптимизации памяти
func (s *Service) GetBuffer() *bytes.Buffer {
	return s.bufferPool.Get().(*bytes.Buffer)
}

// PutBuffer возвращает буфер в pool
func (s *Service) PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	s.bufferPool.Put(buf)
}

// ValidateClientRequest выполняет общие проверки запроса: rate-limit и User-Agent
func (s *Service) ValidateClientRequest(r *http.Request) (int, string) {
	clientIP := s.getClientIP(r)

	// Проверяем rate limit
	limiter := s.GetLimiter(clientIP)
	if !limiter.Allow() {
		s.logger.Warn("Rate limit exceeded",
			"ip", clientIP,
			"limiter", limiter.Limit(),
			"burst", limiter.Burst(),
		)
		return http.StatusTooManyRequests, "Rate limit exceeded"
	}

	// Проверяем User-Agent
	if !s.isValidUserAgent(r.Header.Get("User-Agent")) {
		s.logger.Warn("Invalid User-Agent",
			"ip", clientIP,
			"userAgent", r.Header.Get("User-Agent"),
		)
		return http.StatusBadRequest, "Invalid User-Agent"
	}

	return 0, "" // OK
}

// getClientIP извлекает IP адрес клиента из запроса
// SECURITY: Приоритизирует RemoteAddr для защиты от IP spoofing через proxy headers
// X-Forwarded-For и X-Real-IP доверяются только в случае явной конфигурации
func (s *Service) getClientIP(r *http.Request) string {
	// Первый приоритет: RemoteAddr (прямое соединение, невозможно подделать)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}

	// Fallback для IPv6 ::1 или других форматов без портов
	if ip := net.ParseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}

	return r.RemoteAddr

	// ПРИМЕЧАНИЕ: X-Forwarded-For и X-Real-IP НЕ используются здесь
	// для защиты от IP spoofing атак. Если ваше приложение находится
	// за reverse proxy (nginx, HAProxy), вы можете добавить проверку
	// доверенного источника прокси, но это требует явной конфигурации
	// и валидации IP адреса прокси.
}

// GetLimiter возвращает rate limiter для указанного IP адреса
func (s *Service) GetLimiter(ip string) *rate.Limiter {
	const limiterBurst = 5
	const limiterEvery = 100 * time.Millisecond

	val, _ := s.ipLimiter.LoadOrStore(ip, rate.NewLimiter(rate.Every(limiterEvery), limiterBurst))
	limiter, ok := val.(*rate.Limiter)
	if !ok || limiter == nil {
		// Fallback: create new limiter (defensive programming)
		limiter = rate.NewLimiter(rate.Every(limiterEvery), limiterBurst)
	}
	return limiter
}

// isValidUserAgent проверяет User-Agent на допустимость
func (s *Service) isValidUserAgent(ua string) bool {
	if ua == "" {
		return false
	}

	// Проверяем встроенные префиксы
	for _, prefix := range s.builtinAllowedPrefixes {
		if len(ua) >= len(prefix) && ua[:len(prefix)] == prefix {
			return true
		}
	}

	// Проверяем по списку из конфига
	return slices.Contains(s.cfg.Validation.AllowedUserAgents, ua)
}

// handleHealth обрабатывает запросы на проверку здоровья сервиса
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Debug: log incoming request data
	if s.debug {
		clientIP := s.getClientIP(r)
		ua := r.Header.Get("User-Agent")
		s.logger.Info("Incoming /health request",
			"ip", clientIP,
			"user_agent", ua,
			"method", r.Method,
		)
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `{"status":"ok","timestamp":"%s"}`, time.Now().Format(time.RFC3339)); err != nil {
		s.logger.Error("Failed to write health status", "error", err)
	}
}

// formatContent преобразует содержимое в требуемый формат (yaml, base64 или обычный текст).
// Возвращает ошибку при недопустимом значении format.
func formatContent(content []byte, formatStr string) ([]byte, string, error) {
	// формат может быть: yaml, base64, yaml+base64, base64+yaml или пусто (по умолчанию)
	format := strings.ToLower(strings.TrimSpace(formatStr))
	if format == "" {
		return content, "text/plain; charset=utf-8", nil
	}

	// Валидация: допускаются только токены yaml и base64, разделённые "+"
	for _, token := range strings.Split(format, "+") {
		token = strings.TrimSpace(token)
		if token != "yaml" && token != "base64" {
			return nil, "", fmt.Errorf("invalid format %q: allowed values are yaml, base64 or their combination (e.g. yaml+base64)", formatStr)
		}
	}

	var result []byte
	contentType := "text/plain; charset=utf-8"

	// Проверяем наличие yaml формата
	if strings.Contains(format, "yaml") {
		result = contentToYAML(content)
		contentType = "application/x-yaml; charset=utf-8"
	} else {
		result = content
	}

	// Проверяем наличие base64 кодирования
	if strings.Contains(format, "base64") {
		result = []byte(base64.StdEncoding.EncodeToString(result))
		contentType = "application/octet-stream"
	}

	return result, contentType, nil
}

// contentToYAML преобразует список прокси-ссылок в YAML формат для Clash/Mihomo.
// Игнорирует комментарии, пустые строки и неподдерживаемые схемы.
func contentToYAML(content []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

	var result bytes.Buffer
	result.WriteString("proxies:\n")

	proxyIndex := 0
	for _, line := range lines {
		line = bytes.TrimSpace(line)

		// Пропускаем пустые строки и комментарии
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}

		yamlBlock := parseProxyToYAML(string(line), proxyIndex)
		if yamlBlock != "" {
			result.WriteString(yamlBlock)
			proxyIndex++
		}
	}

	// Если нет прокси, возвращаем минимальный YAML
	if proxyIndex == 0 {
		return []byte("proxies: []")
	}

	return result.Bytes()
}

// parseProxyToYAML парсит прокси URL и создает YAML блок для Clash/Meta.
// Возвращает пустую строку для комментариев, невалидных URL и неподдерживаемых схем.
func parseProxyToYAML(proxyURL string, index int) string {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" || strings.HasPrefix(proxyURL, "#") {
		return ""
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return ""
	}

	scheme := strings.ToLower(u.Scheme)
	params := u.Query()

	// Поддерживаются только известные протоколы; остальные пропускаются,
	// чтобы не искажать профиль фиктивными записями.
	switch scheme {
	case "ss", "vless", "vmess", "trojan", "hy2", "hysteria2":
	default:
		return ""
	}

	name := extractProxyName(proxyURL, index)
	var sb strings.Builder
	sb.WriteString("  - name: ")
	sb.WriteString(yamlQuote(name))
	sb.WriteString("\n    type: ")

	switch scheme {
	case "ss":
		return buildSSYAML(&sb, u, params)
	case "vless":
		return buildVLESSYAML(&sb, u, params)
	case "vmess":
		return buildVMESSYAML(&sb, proxyURL)
	case "trojan":
		return buildTrojanYAML(&sb, u, params)
	default: // hy2, hysteria2
		return buildHysteria2YAML(&sb, u, params)
	}
}

// yamlQuote экранирует строку для безопасной вставки в YAML в двойных кавычках.
func yamlQuote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// buildSSYAML создает YAML для Shadowsocks прокси.
// Нормализатор ss/ss.go кодирует userinfo как base64(cipher:password),
// поэтому userinfo необходимо декодировать.
func buildSSYAML(sb *strings.Builder, u *url.URL, params url.Values) string {
	sb.WriteString("ss\n")

	// Декодируем userinfo (base64 от cipher:password)
	var cipher, password string
	if userinfo := u.User.String(); userinfo != "" {
		if decoded, err := utils.DecodeUserInfo(userinfo); err == nil {
			if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 {
				cipher, password = parts[0], parts[1]
			}
		}
	}

	sb.WriteString("    server: ")
	sb.WriteString(yamlQuote(u.Hostname()))
	sb.WriteString("\n")

	if port := u.Port(); port != "" {
		sb.WriteString("    port: ")
		sb.WriteString(port)
		sb.WriteString("\n")
	}

	if cipher != "" {
		sb.WriteString("    cipher: ")
		sb.WriteString(cipher)
		sb.WriteString("\n")
	}

	if password != "" {
		sb.WriteString("    password: ")
		sb.WriteString(yamlQuote(password))
		sb.WriteString("\n")
	}

	// Опциональные параметры
	if obfs := params.Get("obfs"); obfs != "" {
		sb.WriteString("    plugin: obfs\n")
		sb.WriteString("    plugin-opts:\n")
		sb.WriteString("      mode: ")
		sb.WriteString(obfs)
		sb.WriteString("\n")
	}

	if udp := params.Get("udp"); udp == "1" || udp == "true" {
		sb.WriteString("    udp: true\n")
	}

	return sb.String()
}

// buildVLESSYAML создает YAML для VLESS прокси.
// Поддерживает TLS/REALITY и транспорты ws/grpc/httpupgrade.
func buildVLESSYAML(sb *strings.Builder, u *url.URL, params url.Values) string {
	sb.WriteString("vless\n")

	sb.WriteString("    server: ")
	sb.WriteString(yamlQuote(u.Hostname()))
	sb.WriteString("\n")

	if port := u.Port(); port != "" {
		sb.WriteString("    port: ")
		sb.WriteString(port)
		sb.WriteString("\n")
	}

	// UUID из userinfo
	if uuid := u.User.Username(); uuid != "" {
		sb.WriteString("    uuid: ")
		sb.WriteString(yamlQuote(uuid))
		sb.WriteString("\n")
	}

	// Определяем network: канонический параметр Xray — type, network — запасной
	network := params.Get("type")
	if network == "" {
		network = params.Get("network")
	}
	if network == "" {
		network = "tcp"
	}
	sb.WriteString("    network: ")
	sb.WriteString(network)
	sb.WriteString("\n")

	// TLS и REALITY
	switch security := params.Get("security"); security {
	case "tls":
		sb.WriteString("    tls: true\n")
		if sni := params.Get("sni"); sni != "" {
			sb.WriteString("    servername: ")
			sb.WriteString(yamlQuote(sni))
			sb.WriteString("\n")
		}
	case "reality":
		sb.WriteString("    tls: true\n")
		if sni := params.Get("sni"); sni != "" {
			sb.WriteString("    servername: ")
			sb.WriteString(yamlQuote(sni))
			sb.WriteString("\n")
		}
		sb.WriteString("    reality-opts:\n")
		if pbk := params.Get("pbk"); pbk != "" {
			sb.WriteString("      public-key: ")
			sb.WriteString(yamlQuote(pbk))
			sb.WriteString("\n")
		}
		if sid := params.Get("sid"); sid != "" {
			sb.WriteString("      short-id: ")
			sb.WriteString(yamlQuote(sid))
			sb.WriteString("\n")
		}
		if fp := params.Get("fp"); fp != "" {
			sb.WriteString("    client-fingerprint: ")
			sb.WriteString(fp)
			sb.WriteString("\n")
		}
	}

	// ALPN
	writeALPN(sb, params)

	// Flow (XTLS)
	if flow := params.Get("flow"); flow != "" {
		sb.WriteString("    flow: ")
		sb.WriteString(yamlQuote(flow))
		sb.WriteString("\n")
	}

	// Параметры транспорта
	writeTransportOpts(sb, network, params)

	if udp := params.Get("udp"); udp == "1" || udp == "true" {
		sb.WriteString("    udp: true\n")
	}

	return sb.String()
}

// writeTransportOpts добавляет опции транспорта (ws/httpupgrade, grpc, xhttp) в YAML блок.
func writeTransportOpts(sb *strings.Builder, network string, params url.Values) {
	switch network {
	case "ws", "httpupgrade":
		pathVal := params.Get("path")
		hostVal := params.Get("host")
		if pathVal == "" && hostVal == "" {
			return
		}
		sb.WriteString("    ws-opts:\n")
		if pathVal != "" {
			sb.WriteString("      path: ")
			sb.WriteString(yamlQuote(pathVal))
			sb.WriteString("\n")
		}
		if hostVal != "" {
			sb.WriteString("      headers:\n")
			sb.WriteString("        Host: ")
			sb.WriteString(yamlQuote(hostVal))
			sb.WriteString("\n")
		}
	case "grpc":
		if sn := params.Get("serviceName"); sn != "" {
			sb.WriteString("    grpc-opts:\n")
			sb.WriteString("      grpc-service-name: ")
			sb.WriteString(yamlQuote(sn))
			sb.WriteString("\n")
		}
	case "xhttp":
		pathVal := params.Get("path")
		hostVal := params.Get("host")
		if pathVal == "" && hostVal == "" {
			return
		}
		sb.WriteString("    xhttp-opts:\n")
		if pathVal != "" {
			sb.WriteString("      path: ")
			sb.WriteString(yamlQuote(pathVal))
			sb.WriteString("\n")
		}
		if hostVal != "" {
			sb.WriteString("      extra-headers:\n")
			sb.WriteString("        Host: ")
			sb.WriteString(yamlQuote(hostVal))
			sb.WriteString("\n")
		}
	}
}

// writeALPN добавляет список ALPN-протоколов в YAML блок.
func writeALPN(sb *strings.Builder, params url.Values) {
	alpn := params.Get("alpn")
	if alpn == "" {
		return
	}
	var list []string
	for _, v := range strings.Split(alpn, ",") {
		if v = strings.TrimSpace(v); v != "" {
			list = append(list, v)
		}
	}
	if len(list) == 0 {
		return
	}
	sb.WriteString("    alpn:\n")
	for _, v := range list {
		sb.WriteString("      - ")
		sb.WriteString(yamlQuote(v))
		sb.WriteString("\n")
	}
}

// isInsecureFlag проверяет legacy-флаги пропуска проверки сертификата
// (insecure/allowInsecure в разных регистрах).
func isInsecureFlag(params url.Values) bool {
	for _, key := range []string{"insecure", "allowInsecure", "allowinsecure"} {
		if v := params.Get(key); v == "1" || strings.EqualFold(v, "true") {
			return true
		}
	}
	return false
}

// vmessPayload возвращает base64-payload VMess-ссылки без префикса схемы и фрагмента.
func vmessPayload(proxyURL string) string {
	payload := strings.TrimPrefix(proxyURL, "vmess://")
	if idx := strings.IndexByte(payload, '#'); idx != -1 {
		payload = payload[:idx]
	}
	return payload
}

// buildVMESSYAML создает YAML для VMess прокси.
// Нормализатор vmess/vmess.go отдает vmess://BASE64(JSON) (v2rayN-формат),
// поэтому конфигурация извлекается из декодированного JSON payload.
func buildVMESSYAML(sb *strings.Builder, proxyURL string) string {
	decoded, err := utils.DecodeUserInfo(vmessPayload(proxyURL))
	if err != nil {
		return ""
	}
	var vm map[string]any
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return ""
	}

	sb.WriteString("vmess\n")

	// Адрес сервера
	add, _ := vm["add"].(string)
	sb.WriteString("    server: ")
	sb.WriteString(yamlQuote(add))
	sb.WriteString("\n")

	// Порт может быть числом или строкой
	switch p := vm["port"].(type) {
	case float64:
		sb.WriteString("    port: ")
		sb.WriteString(strconv.Itoa(int(p)))
		sb.WriteString("\n")
	case string:
		if port, err := strconv.Atoi(p); err == nil {
			sb.WriteString("    port: ")
			sb.WriteString(strconv.Itoa(port))
			sb.WriteString("\n")
		}
	}

	// UUID
	if id, _ := vm["id"].(string); id != "" {
		sb.WriteString("    uuid: ")
		sb.WriteString(yamlQuote(id))
		sb.WriteString("\n")
	}

	// Alter ID (по умолчанию 0)
	alterID := 0
	switch a := vm["aid"].(type) {
	case float64:
		alterID = int(a)
	case string:
		if v, err := strconv.Atoi(a); err == nil {
			alterID = v
		}
	}
	sb.WriteString("    alterId: ")
	sb.WriteString(strconv.Itoa(alterID))
	sb.WriteString("\n")

	// Шифрование (по умолчанию auto)
	cipher, _ := vm["scy"].(string)
	if cipher == "" {
		cipher = "auto"
	}
	sb.WriteString("    cipher: ")
	sb.WriteString(cipher)
	sb.WriteString("\n")

	// Транспорт
	network, _ := vm["net"].(string)
	if network != "" {
		sb.WriteString("    network: ")
		sb.WriteString(network)
		sb.WriteString("\n")
	}

	// TLS
	if tlsVal, _ := vm["tls"].(string); tlsVal == "tls" {
		sb.WriteString("    tls: true\n")
		if sni, _ := vm["sni"].(string); sni != "" {
			sb.WriteString("    servername: ")
			sb.WriteString(yamlQuote(sni))
			sb.WriteString("\n")
		}
	}

	// Параметры транспорта
	switch network {
	case "ws", "httpupgrade":
		pathVal, _ := vm["path"].(string)
		hostVal, _ := vm["host"].(string)
		if pathVal != "" || hostVal != "" {
			sb.WriteString("    ws-opts:\n")
			if pathVal != "" {
				sb.WriteString("      path: ")
				sb.WriteString(yamlQuote(pathVal))
				sb.WriteString("\n")
			}
			if hostVal != "" {
				sb.WriteString("      headers:\n")
				sb.WriteString("        Host: ")
				sb.WriteString(yamlQuote(hostVal))
				sb.WriteString("\n")
			}
		}
	case "grpc":
		if sn, _ := vm["serviceName"].(string); sn != "" {
			sb.WriteString("    grpc-opts:\n")
			sb.WriteString("      grpc-service-name: ")
			sb.WriteString(yamlQuote(sn))
			sb.WriteString("\n")
		}
	case "h2":
		pathVal, _ := vm["path"].(string)
		hostVal, _ := vm["host"].(string)
		if pathVal != "" || hostVal != "" {
			sb.WriteString("    h2-opts:\n")
			if pathVal != "" {
				sb.WriteString("      path: ")
				sb.WriteString(yamlQuote(pathVal))
				sb.WriteString("\n")
			}
			if hostVal != "" {
				sb.WriteString("      host:\n")
				sb.WriteString("        - ")
				sb.WriteString(yamlQuote(hostVal))
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// buildTrojanYAML создает YAML для Trojan прокси.
// Поддерживает TLS/REALITY и транспорты ws/grpc/httpupgrade.
func buildTrojanYAML(sb *strings.Builder, u *url.URL, params url.Values) string {
	sb.WriteString("trojan\n")

	sb.WriteString("    server: ")
	sb.WriteString(yamlQuote(u.Hostname()))
	sb.WriteString("\n")

	if port := u.Port(); port != "" {
		sb.WriteString("    port: ")
		sb.WriteString(port)
		sb.WriteString("\n")
	}

	// Password из userinfo
	if password := u.User.Username(); password != "" {
		sb.WriteString("    password: ")
		sb.WriteString(yamlQuote(password))
		sb.WriteString("\n")
	}

	// SNI
	sni := params.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	if sni != "" {
		sb.WriteString("    sni: ")
		sb.WriteString(yamlQuote(sni))
		sb.WriteString("\n")
	}

	// REALITY
	if params.Get("security") == "reality" {
		sb.WriteString("    reality-opts:\n")
		if pbk := params.Get("pbk"); pbk != "" {
			sb.WriteString("      public-key: ")
			sb.WriteString(yamlQuote(pbk))
			sb.WriteString("\n")
		}
		if sid := params.Get("sid"); sid != "" {
			sb.WriteString("      short-id: ")
			sb.WriteString(yamlQuote(sid))
			sb.WriteString("\n")
		}
		if fp := params.Get("fp"); fp != "" {
			sb.WriteString("    client-fingerprint: ")
			sb.WriteString(fp)
			sb.WriteString("\n")
		}
	}

	// Skip cert verify (включая legacy-флаг allowInsecure)
	if skip := params.Get("skip-cert-verify"); skip == "1" || skip == "true" || isInsecureFlag(params) {
		sb.WriteString("    skip-cert-verify: true\n")
	} else {
		sb.WriteString("    skip-cert-verify: false\n")
	}

	// ALPN
	writeALPN(sb, params)

	// Транспорт: канонический параметр Xray — type, network — запасной
	network := params.Get("type")
	if network == "" {
		network = params.Get("network")
	}
	if network != "" {
		sb.WriteString("    network: ")
		sb.WriteString(network)
		sb.WriteString("\n")
	}

	// Параметры транспорта
	writeTransportOpts(sb, network, params)

	if udp := params.Get("udp"); udp == "1" || udp == "true" {
		sb.WriteString("    udp: true\n")
	}

	return sb.String()
}

// buildHysteria2YAML создает YAML для Hysteria2 прокси.
// Пароль берется из userinfo либо из параметра obfs-password (стандарт hy2);
// параметр obfs задает только тип обфускации.
func buildHysteria2YAML(sb *strings.Builder, u *url.URL, params url.Values) string {
	sb.WriteString("hysteria2\n")

	sb.WriteString("    server: ")
	sb.WriteString(yamlQuote(u.Hostname()))
	sb.WriteString("\n")

	if port := u.Port(); port != "" {
		sb.WriteString("    port: ")
		sb.WriteString(port)
		sb.WriteString("\n")
	}

	// Password из userinfo или параметра obfs-password
	password := u.User.Username()
	if password == "" {
		password = params.Get("obfs-password")
	}
	if password != "" {
		sb.WriteString("    password: ")
		sb.WriteString(yamlQuote(password))
		sb.WriteString("\n")
	}

	// Обфускация (только тип; пароль — отдельно в obfs-password)
	if obfs := params.Get("obfs"); obfs == "salamander" {
		sb.WriteString("    obfs: ")
		sb.WriteString(obfs)
		sb.WriteString("\n")
	}

	// SNI
	if sni := params.Get("sni"); sni != "" {
		sb.WriteString("    sni: ")
		sb.WriteString(yamlQuote(sni))
		sb.WriteString("\n")
	}

	// Пропуск проверки сертификата (включая legacy-флаг allowInsecure)
	if isInsecureFlag(params) {
		sb.WriteString("    skip-cert-verify: true\n")
	}

	// Скоростные лимиты: канонические для hy2 — upmbps/downmbps, up/down — запасные
	up := params.Get("upmbps")
	if up == "" {
		up = params.Get("up")
	}
	if up != "" {
		sb.WriteString("    up: ")
		sb.WriteString(yamlQuote(up))
		sb.WriteString("\n")
	}
	down := params.Get("downmbps")
	if down == "" {
		down = params.Get("down")
	}
	if down != "" {
		sb.WriteString("    down: ")
		sb.WriteString(yamlQuote(down))
		sb.WriteString("\n")
	}

	if udp := params.Get("udp"); udp == "1" || udp == "true" {
		sb.WriteString("    udp: true\n")
	}

	return sb.String()
}

// extractProxyName извлекает имя прокси из URL или генерирует стандартное
func extractProxyName(proxyURL string, index int) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Sprintf("proxy-%d", index)
	}

	// VMess: имя берется из поля ps декодированного JSON payload,
	// при его отсутствии — из фрагмента URL
	if strings.ToLower(u.Scheme) == "vmess" {
		if decoded, err := utils.DecodeUserInfo(vmessPayload(proxyURL)); err == nil {
			var vm map[string]any
			if json.Unmarshal(decoded, &vm) == nil {
				if ps, _ := vm["ps"].(string); ps != "" {
					return ps
				}
			}
		}
		if u.Fragment != "" {
			return u.Fragment
		}
		return fmt.Sprintf("vmess-%d", index)
	}

	// Пытаемся получить имя из фрагмента (#name=...)
	if fragment := u.Fragment; fragment != "" {
		if strings.Contains(fragment, "name=") {
			parts := strings.Split(fragment, "&")
			for _, part := range parts {
				if strings.HasPrefix(part, "name=") {
					name := strings.TrimPrefix(part, "name=")
					if name != "" {
						return name
					}
				}
			}
		}
		// Если фрагмент есть, используем его как имя
		if fragment != "" {
			return fragment
		}
	}

	// Попытка получить имя из параметров query
	params := u.Query()
	if remark := params.Get("remark"); remark != "" {
		return remark
	}
	if desc := params.Get("desc"); desc != "" {
		return desc
	}

	// Используем хост или "proxy-N"
	if u.Hostname() != "" {
		return fmt.Sprintf("%s-%d", u.Hostname(), index)
	}

	return fmt.Sprintf("proxy-%d", index)
}

// handleFilter обрабатывает запросы на фильтрацию подписок
func (s *Service) handleFilter(w http.ResponseWriter, r *http.Request) {
	// Debug: log incoming request data
	if s.debug {
		clientIP := s.getClientIP(r)
		ua := r.Header.Get("User-Agent")
		s.logger.Info("Incoming /filter request",
			"ip", clientIP,
			"user_agent", ua,
			"raw_query", r.URL.RawQuery,
		)
	}
	if status, msg := s.ValidateClientRequest(r); status != 0 {
		http.Error(w, msg, status)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" || len(id) > maxIDLength || !s.validIDRe.MatchString(id) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	countryCodes, err := s.parseCountryCodes(r.URL.Query().Get("c"), s.countries, s.maxCountryCodes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid country codes: %v", err), http.StatusBadRequest)
		return
	}
	// Ограничиваем число отдаваемых строк для слабых клиентов (iOS), чтобы избежать их перегрузки при больших профилях
	lim := parseLimit(r.URL.Query().Get("lim"))
	format := r.URL.Query().Get("format")

	content, err := s.Filter(id, countryCodes, lim)
	if err != nil {
		http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
		return
	}
	source, ok := s.sources[id]
	if !ok || source == nil {
		http.Error(w, "Source not found", http.StatusInternalServerError)
		return
	}

	// Применяем форматирование если указано
	formattedContent, contentType, err := formatContent(content, format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.serveFile(w, formattedContent, source.URL, id, format, contentType)
}

// handleMerge обрабатывает запросы на слияние подписок
func (s *Service) handleMerge(w http.ResponseWriter, r *http.Request) {
	// Debug: log incoming request data
	if s.debug {
		clientIP := s.getClientIP(r)
		ua := r.Header.Get("User-Agent")
		s.logger.Info("Incoming /merge request",
			"ip", clientIP,
			"user_agent", ua,
			"raw_query", r.URL.RawQuery,
		)
	}
	if status, msg := s.ValidateClientRequest(r); status != 0 {
		http.Error(w, msg, status)
		return
	}

	rawIDs := r.URL.Query()["ids"]
	if len(rawIDs) == 0 {
		rawIDs = r.URL.Query()["id"]
	}
	idList := parseIDs(rawIDs)
	if len(idList) == 0 {
		http.Error(w, "no ids provided", http.StatusBadRequest)
		return
	}
	if len(idList) > s.maxMergeIDs && s.maxMergeIDs > 0 {
		http.Error(w, fmt.Sprintf("too many ids (max %d)", s.maxMergeIDs), http.StatusBadRequest)
		return
	}
	for _, id := range idList {
		if id == "" || len(id) > maxIDLength || !s.validIDRe.MatchString(id) {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		if _, ok := s.sources[id]; !ok {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
	}

	sortedIDs := make([]string, len(idList))
	copy(sortedIDs, idList)
	sort.Strings(sortedIDs)

	countryCodes, err := s.parseCountryCodes(r.URL.Query().Get("c"), s.countries, s.maxCountryCodes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid country codes: %v", err), http.StatusBadRequest)
		return
	}
	// Ограничиваем число отдаваемых строк для слабых клиентов (iOS), чтобы избежать их перегрузки при больших профилях
	lim := parseLimit(r.URL.Query().Get("lim"))
	format := r.URL.Query().Get("format")

	content, err := s.Merge(sortedIDs, countryCodes, lim)
	if err != nil {
		http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
		return
	}

	// Применяем форматирование если указано
	formattedContent, contentType, err := formatContent(content, format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.serveFile(w, formattedContent, "merged_sources", strings.Join(sortedIDs, "_"), format, contentType)
}

// serveFile отвечает клиенту результатом фильтрации/слияния с безопасными заголовками
func (s *Service) serveFile(w http.ResponseWriter, content []byte, sourceURL, id, format, contentType string) {
	filename := "filtered_" + id + ".txt"
	if u, err := url.Parse(sourceURL); err == nil {
		base := path.Base(u.Path)
		if base != "" && s.validProfileNameRegex.MatchString(base) {
			filename = base
		}
	}
	filename = s.filenameCleanupRegex.ReplaceAllString(filename, "_")

	// Определяем расширение файла на основе формата
	normalizedFormat := strings.ToLower(strings.TrimSpace(format))
	if strings.Contains(normalizedFormat, "yaml") {
		if !strings.HasSuffix(strings.ToLower(filename), ".yaml") && !strings.HasSuffix(strings.ToLower(filename), ".yml") {
			filename = strings.TrimSuffix(filename, ".txt") + ".yaml"
		}
	} else if strings.Contains(normalizedFormat, "base64") {
		if !strings.HasSuffix(strings.ToLower(filename), ".b64") {
			filename = strings.TrimSuffix(filename, ".txt") + ".b64"
		}
	} else {
		if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
			filename += ".txt"
		}
	}

	filename = filepath.Base(filename)
	if len(filename) > MaxFilenameLength {
		filename = filename[:MaxFilenameLength]
	}
	encoded := EncodeRFC5987(filename)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=%s", encoded))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if _, err := w.Write(content); err != nil {
		s.logger.Error("Failed to write response",
			"error", err,
			"id", id,
			"size", len(content),
		)
	}
}

// parseLimit преобразует строковый параметр лимита в int (0 если не указано или некорректно)
func parseLimit(s string) int {
	if s == "" {
		return 0
	}
	if v, err := strconv.Atoi(s); err == nil && v > 0 {
		return v
	}
	return 0
}

// parseCountryCodes парсит список кодов стран и проверяет их.
// Метод используется только внутри Service, поэтому имеет доступ к regex.
func (s *Service) parseCountryCodes(cParam string, countryMap map[string]utils.CountryInfo, maxCodes int) ([]string, error) {
	if cParam == "" {
		return nil, nil
	}
	rawCodes := strings.Split(cParam, ",")
	if maxCodes > 0 && len(rawCodes) > maxCodes {
		return nil, errors.ValidationError(fmt.Sprintf("too many country codes (max %d)", maxCodes))
	}

	seen := make(map[string]bool)
	var validCodes []string
	for _, code := range rawCodes {
		code = strings.ToUpper(strings.TrimSpace(code))
		if code == "" {
			continue
		}
		if len(code) != 2 || !s.validIDRe.MatchString(code) {
			return nil, errors.ValidationError(fmt.Sprintf("invalid country code format: %q", code))
		}
		if _, exists := countryMap[code]; !exists {
			return nil, errors.ValidationError(fmt.Sprintf("unknown country code: %q", code))
		}
		if !seen[code] {
			seen[code] = true
			validCodes = append(validCodes, code)
		}
	}

	sort.Strings(validCodes)
	return validCodes, nil
}

// Максимальная длина имени файла, совпадает с реализацией в main.go
const MaxFilenameLength = 255

// applyLimit возвращает первые lim строк из content, игнорируя строки-комментарии (#)
func applyLimit(content []byte, lim int) []byte {
	if lim <= 0 {
		return content
	}
	var out []byte
	for line := range bytes.SplitSeq(content, []byte("\n")) {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 || trim[0] == '#' {
			continue
		}
		out = append(out, line...)
		out = append(out, '\n')
		lim--
		if lim == 0 {
			break
		}
	}
	return out
}

// EncodeRFC5987 возвращает RFC5987-encoded значение для заголовка Content-Disposition
func EncodeRFC5987(filename string) string {
	return "UTF-8''" + url.QueryEscape(filename)
}

// helpers для сетевого взаимодействия, скопированы из main.go
func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func createHTTPClientWithDialContext(hostname string, dialFunc func(context.Context, string, string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{
		DialContext:        dialFunc,
		ForceAttemptHTTP2:  true,
		TLSClientConfig:    &tls.Config{ServerName: hostname},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func streamProcessResponse(resp *http.Response, lineProcessor func(string) error) error {
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		if err := lineProcessor(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// generateProfile выполняет полную логику processSource из main.go и возвращает контент
func (s *Service) generateProfile(id string, countryCodes []string) (string, error) {
	source, exists := s.sources[id]
	if !exists {
		return "", errors.ValidationError(fmt.Sprintf("source not found for id: %s", id)).WithContext("sourceID", id)
	}
	// replicate main.processSource logic using s.* fields
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return "", errors.ParseError("invalid source URL", err).
			WithContext("sourceID", id).
			WithContext("url", source.URL)
	}
	if source == nil || source.IP == nil {
		return "", errors.ValidationError("missing resolved IP").WithContext("sourceID", id)
	}
	host := parsedSource.Hostname()
	if !utils.IsValidHost(host) {
		return "", errors.ValidationError(fmt.Sprintf("invalid source host: %s", host)).WithContext("host", host)
	}

	cacheSuffix := ""
	if len(countryCodes) > 0 {
		cacheSuffix = "_c_" + strings.Join(countryCodes, "_")
	}

	origCache := filepath.Join(s.cfg.Cache.Directory, "orig_"+id+cacheSuffix+".txt")
	modCache := filepath.Join(s.cfg.Cache.Directory, "mod_"+id+cacheSuffix+".txt")
	rejectedCache := filepath.Join(s.cfg.Cache.Directory, "rejected_"+id+cacheSuffix+".txt")

	if !utils.IsPathSafe(origCache, s.cfg.Cache.Directory) ||
		!utils.IsPathSafe(modCache, s.cfg.Cache.Directory) ||
		!utils.IsPathSafe(rejectedCache, s.cfg.Cache.Directory) {
		return "", errors.ValidationError("unsafe cache path").
			WithContext("sourceID", id)
	}

	if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= s.cfg.Cache.TTL {
		content, err := os.ReadFile(modCache)
		if err == nil {
			return string(content), nil
		}
	}

	content, err := s.fetchSourceContent(id, source, origCache, false, nil)
	if err != nil {
		return "", err
	}
	origContent := content

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
	lines := bytes.SplitSeq(origContent, []byte("\n"))
	for lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}
		var processedLine, reason string
		handled := false
		for _, p := range s.proxyProcessors {
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
			processedLine = s.applyReplaceBadWords(processedLine)
			if len(countryCodes) > 0 {
				parsedProcessed, parseErr := url.Parse(processedLine)
				if parseErr == nil && parsedProcessed.Fragment != "" {
					allFilterStrings := utils.GetCountryFilterStringsForMultiple(countryCodes, s.countries)
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

	rejectedContent := strings.Join(rejectedLines, "\n")
	tmpFileObj, tmpErr := os.CreateTemp(s.cfg.Cache.Directory, "rejected_"+id+"_*.tmp")
	if tmpErr != nil {
		s.logger.Warn("Failed to create temp file for rejected cache", "error", tmpErr, "id", id)
	} else {
		tmpName := tmpFileObj.Name()
		_, writeErr := tmpFileObj.WriteString(rejectedContent)
		closeErr := tmpFileObj.Close()
		if writeErr != nil {
			s.logger.Error("Failed to write rejected cache", "error", writeErr, "id", id)
			_ = os.Remove(tmpName)
		} else if closeErr != nil {
			s.logger.Error("Failed to close rejected cache temp file", "error", closeErr, "id", id)
			_ = os.Remove(tmpName)
		} else {
			_ = os.Rename(tmpName, rejectedCache)
		}
	}

	profileName := "filtered_" + id
	if u, err := url.Parse(source.URL); err == nil {
		base := path.Base(u.Path)
		if base != "" && s.validProfileNameRegex.MatchString(base) {
			profileName = strings.TrimSuffix(base, ".txt")
		}
	}
	profileName = s.filenameCleanupRegex.ReplaceAllString(profileName, "_")

	profileTitle := buildProfileHeader(profileName, id, countryCodes)
	profileInterval := buildProfileInterval(s.cfg.Cache.TTL)
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	tmpFileObj, tmpErr = os.CreateTemp(s.cfg.Cache.Directory, "mod_"+id+"_*.tmp")
	if tmpErr != nil {
		s.logger.Warn("Failed to create temp file for modified cache", "error", tmpErr, "id", id)
	} else {
		tmpName := tmpFileObj.Name()
		_, writeErr := tmpFileObj.WriteString(final)
		closeErr := tmpFileObj.Close()
		if writeErr != nil {
			s.logger.Error("Failed to write modified cache", "error", writeErr, "id", id)
			_ = os.Remove(tmpName)
		} else if closeErr != nil {
			s.logger.Error("Failed to close modified cache temp file", "error", closeErr, "id", id)
			_ = os.Remove(tmpName)
		} else {
			_ = os.Rename(tmpName, modCache)
		}
	}

	return final, nil
}

// Filter создает профиль для указанного id и применяет лимит строк.
func (s *Service) Filter(id string, countryCodes []string, lim int) ([]byte, error) {
	content, err := s.generateProfile(id, countryCodes)
	if err != nil {
		return nil, err
	}
	return applyLimit([]byte(content), lim), nil
}

// Merge выполняет объединение нескольких источников с дедупликацией и кешированием
func (s *Service) Merge(ids []string, countryCodes []string, lim int) ([]byte, error) {
	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)

	mergeCacheKey := "merge_" + strings.Join(sorted, "_")
	if len(countryCodes) > 0 {
		mergeCacheKey += "_c_" + strings.Join(countryCodes, "_")
	}

	cacheFilePath := filepath.Join(s.cfg.Cache.Directory, mergeCacheKey+".txt")
	if info, err := os.Stat(cacheFilePath); err == nil && time.Since(info.ModTime()) <= s.cfg.Cache.TTL {
		content, _ := os.ReadFile(cacheFilePath)
		return applyLimit(content, lim), nil
	}

	// streaming merge copy from main.handleMerge (omitting http responses)
	nBuckets := s.mergeBuckets
	if nBuckets <= 0 {
		nBuckets = 256
	}
	tmpDir := filepath.Join(s.cfg.Cache.Directory, "merge_tmp_"+mergeCacheKey)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, err
	}
	bucketFiles := make([]*os.File, nBuckets)
	bucketWriters := make([]*bufio.Writer, nBuckets)
	bucketLocks := make([]sync.Mutex, nBuckets)
	bucketExists := make([]bool, nBuckets)
	success := false
	defer func() {
		if !success {
			for i := 0; i < nBuckets; i++ {
				if bucketWriters[i] != nil {
					_ = bucketWriters[i].Flush()
				}
				if bucketFiles[i] != nil {
					_ = bucketFiles[i].Close()
				}
				if bucketExists[i] {
					_ = os.Remove(filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i)))
				}
			}
			_ = os.RemoveAll(tmpDir)
		}
	}()

	for i := 0; i < nBuckets; i++ {
		p := filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i))
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		bucketFiles[i] = f
		bucketWriters[i] = bufio.NewWriter(f)
		bucketExists[i] = true
	}

	eg, ctx := errgroup.WithContext(context.Background())
	for _, id := range ids {
		id := id
		eg.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			source, exists := s.sources[id]
			if !exists {
				return errors.ValidationError(fmt.Sprintf("source not found for id: %s", id)).WithContext("sourceID", id)
			}
			if err := s.processSourceToBuckets(id, source, countryCodes, nBuckets, bucketWriters, &bucketLocks); err != nil {
				return errors.ParseError(fmt.Sprintf("error processing source id '%s'", id), err).WithContext("sourceID", id)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	for i := 0; i < nBuckets; i++ {
		if err := bucketWriters[i].Flush(); err != nil {
			// ignore
		}
		_ = bucketFiles[i].Close()
	}

	finalLines := make([]string, 0, 10000)
	for i := 0; i < nBuckets; i++ {
		if !bucketExists[i] {
			continue
		}
		p := filepath.Join(tmpDir, fmt.Sprintf("bucket_%d.txt", i))
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 4*1024*1024)
		bucketMap := make(map[string]string)
		for scanner.Scan() {
			line := scanner.Text()
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
		_ = os.Remove(p)
	}
	_ = os.RemoveAll(tmpDir)
	success = true
	sort.Strings(finalLines)

	profileName := "merged_" + strings.Join(sorted, "_")
	if len(countryCodes) > 0 {
		profileName += "_" + strings.Join(countryCodes, "_")
	}
	updateInterval := max(int(s.cfg.Cache.TTL.Seconds()/3600), 1)
	profileTitle := fmt.Sprintf("#profile-title: %s", profileName)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)
	finalContent := strings.Join(append([]string{profileTitle, profileInterval, ""}, finalLines...), "\n")

	tmpFileObj, tmpErr := os.CreateTemp(s.cfg.Cache.Directory, "merge_*.tmp")
	if tmpErr != nil {
		s.logger.Warn("Failed to create temp file for merge cache", "error", tmpErr)
	} else {
		tmpName := tmpFileObj.Name()
		_, writeErr := tmpFileObj.WriteString(finalContent)
		closeErr := tmpFileObj.Close()
		if writeErr != nil {
			s.logger.Error("Failed to write merge cache", "error", writeErr)
			_ = os.Remove(tmpName)
		} else if closeErr != nil {
			s.logger.Error("Failed to close merge cache temp file", "error", closeErr)
			_ = os.Remove(tmpName)
		} else {
			_ = os.Rename(tmpName, cacheFilePath)
		}
	}
	return applyLimit([]byte(finalContent), lim), nil
}

// processSourceToBuckets отвечает за обработку одного источника в merge
func (s *Service) processSourceToBuckets(id string, source *config.SafeSource, countryCodes []string, nBuckets int, bucketWriters []*bufio.Writer, bucketLocks *[]sync.Mutex) error {
	// replicate main.processSourceToBuckets logic simplified
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return errors.ParseError("invalid source URL", err).
			WithContext("sourceID", id).
			WithContext("url", source.URL)
	}
	if source == nil || source.IP == nil {
		return errors.ValidationError("missing resolved IP").WithContext("sourceID", id)
	}
	host := parsedSource.Hostname()
	if !utils.IsValidHost(host) {
		return errors.ValidationError(fmt.Sprintf("invalid source host: %s", host)).WithContext("host", host)
	}

	origCache := filepath.Join(s.cfg.Cache.Directory, "orig_"+id+".txt")
	content, err := s.fetchSourceContent(id, source, origCache, false, func(line string) error {
		if line == "" || strings.HasPrefix(line, "#") {
			return nil
		}
		var processedLine string
		for _, p := range s.proxyProcessors {
			if p.Matches(line) {
				processedLine, _ = p.Process(line)
				break
			}
		}
		if processedLine != "" {
			processedLine = s.applyReplaceBadWords(processedLine)
			// Если задан фильтр по странам, отфильтровать по фрагменту (fragment) ссылки
			if len(countryCodes) > 0 {
				parsedProcessed, parseErr := url.Parse(processedLine)
				if parseErr == nil && parsedProcessed.Fragment != "" {
					allFilterStrings := utils.GetCountryFilterStringsForMultiple(countryCodes, s.countries)
					if !utils.IsFragmentMatchingCountry(parsedProcessed.Fragment, allFilterStrings) {
						return nil
					}
				} else {
					// Если у ссылки нет фрагмента, то она не подходит под country filter
					return nil
				}
			}
			key, err := utils.NormalizeLinkKey(processedLine)
			if err != nil {
				return nil
			}
			h := fnv.New32a()
			_, err = h.Write([]byte(key))
			if err != nil {
				return nil
			}
			bucket := int(h.Sum32() % uint32(nBuckets))
			(*bucketLocks)[bucket].Lock()
			_, writeErr := bucketWriters[bucket].WriteString(key + "\t" + processedLine + "\n")
			(*bucketLocks)[bucket].Unlock()
			if writeErr != nil {
				return writeErr
			}
		} else {
			// ignore rejected lines here
		}
		return nil
	})
	if err != nil {
		return err
	}
	_ = content // unused
	return nil
}

// buildProfileHeader формирует заголовок профиля
func buildProfileHeader(name, id string, countryCodes []string) string {
	header := fmt.Sprintf("#profile-title: %s (%s)", name, id)
	if len(countryCodes) > 0 {
		header += " (" + strings.Join(countryCodes, ",") + ")"
	}
	return header
}

// buildProfileInterval формирует строку с указанием интервала обновления
func buildProfileInterval(ttl time.Duration) string {
	interval := max(int(ttl.Seconds()/3600), 1)
	return fmt.Sprintf("#profile-update-interval: %d", interval)
}

// fetchSourceContent дублирует аналогичную функцию из main, но работает с s.fetchGroup
func (s *Service) fetchSourceContent(id string, source *config.SafeSource, origCache string, stdout bool, lineProcessor func(string) error) ([]byte, error) {
	// реализация почти идентична версии в main.go, заменены обращения на s.cfg и s.fetchGroup
	if !stdout {
		if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= s.cfg.Cache.TTL {
			if content, err := os.ReadFile(origCache); err == nil {
				// Если lineProcessor предоставлен, обработаем кэшированный контент
				if lineProcessor != nil {
					for line := range strings.SplitSeq(strings.TrimSpace(string(content)), "\n") {
						if err := lineProcessor(line); err != nil {
							return nil, err
						}
					}
				}
				return content, nil
			}
		}
	}

	parsedSource, err := url.Parse(source.URL)
	if err != nil {
		return nil, errors.ParseError("invalid source URL", err).
			WithContext("sourceID", id).
			WithContext("url", source.URL)
	}

	_, portStr, _ := net.SplitHostPort(parsedSource.Host)
	if portStr == "" {
		portStr = getDefaultPort(parsedSource.Scheme)
	}

	dialFunc := func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
	}
	client := createHTTPClientWithDialContext(parsedSource.Hostname(), dialFunc)

	if lineProcessor != nil {
		_, err, _ := s.fetchGroup.Do(id, func() (any, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, errors.NetworkError("create request", err).
					WithContext("sourceID", id).
					WithContext("url", source.URL)
			}
			req.Header.Set("User-Agent", "go-filter/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil, errors.NetworkError("fetch failed", err).
					WithContext("sourceID", id).
					WithContext("url", source.URL)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode >= 400 {
				return nil, errors.NetworkError(fmt.Sprintf("status code %d", resp.StatusCode), nil).
					WithContext("sourceID", id).
					WithContext("url", source.URL).
					WithContext("statusCode", resp.StatusCode)
			}

			if err := streamProcessResponse(resp, lineProcessor); err != nil {
				return nil, errors.ParseError("stream processing failed", err).
					WithContext("sourceID", id).
					WithContext("url", source.URL)
			}

			return nil, nil
		})
		return nil, err
	}

	result, err, _ := s.fetchGroup.Do(id, func() (any, error) {
		req, err := http.NewRequest("GET", source.URL, nil)
		if err != nil {
			return nil, errors.NetworkError("create request", err).
				WithContext("sourceID", id).
				WithContext("url", source.URL)
		}
		req.Header.Set("User-Agent", "go-filter/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.NetworkError("fetch failed", err).
				WithContext("sourceID", id).
				WithContext("url", source.URL)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			return nil, errors.NetworkError(fmt.Sprintf("status code %d", resp.StatusCode), nil).
				WithContext("sourceID", id).
				WithContext("url", source.URL).
				WithContext("statusCode", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.IOError("read response", err)
		}
		if !stdout {
			_ = os.WriteFile(origCache, body, 0o600) // best effort
		}
		return body, nil
	})
	if err != nil {
		return nil, err
	}
	return result.([]byte), nil
}

// ProcessCLI обрабатывает источники для CLI режима
func (s *Service) ProcessCLI(ids []string, countryCodes []string, stdout bool) error {
	g, _ := errgroup.WithContext(s.ctx)
	var mu sync.Mutex
	var outputs []string
	for _, id := range ids {
		id := id
		g.Go(func() error {
			result, err := s.processSource(id, stdout, countryCodes)
			if err != nil {
				return errors.ParseError(fmt.Sprintf("process failed %s", id), err).
					WithContext("sourceID", id)
			}
			if stdout {
				mu.Lock()
				outputs = append(outputs, fmt.Sprintf("# Source %s\n%s", id, result))
				mu.Unlock()
			} else {
				s.logger.Info("Success", "source", id)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if stdout {
		for _, out := range outputs {
			fmt.Println(out)
		}
	}
	return nil
}

// processSource обрабатывает один источник
func (s *Service) processSource(id string, stdout bool, countryCodes []string) (string, error) {
	source, exists := s.sources[id]
	if !exists {
		return "", errors.ValidationError(fmt.Sprintf("source not found for id: %s", id)).
			WithContext("sourceID", id)
	}

	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return "", errors.ParseError("invalid source URL", err).
			WithContext("sourceID", id).
			WithContext("url", source.URL)
	}

	modCache := filepath.Join(s.cfg.Cache.Directory, id+".txt")
	content, err := s.fetchSourceContent(id, source, modCache, stdout, nil)
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	finalLines := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var processedLine string
		for _, p := range s.proxyProcessors {
			if p.Matches(line) {
				processedLine, _ = p.Process(line)
				break
			}
		}
		if processedLine != "" {
			finalLines = append(finalLines, processedLine)
		}
	}

	profileName := id
	if len(countryCodes) > 0 {
		profileName += "_" + strings.Join(countryCodes, "_")
	}
	profileTitle := buildProfileHeader(profileName, id, countryCodes)
	profileInterval := buildProfileInterval(s.cfg.Cache.TTL)
	finalContent := strings.Join(append([]string{profileTitle, profileInterval, ""}, finalLines...), "\n")

	if !stdout {
		_ = os.WriteFile(modCache, []byte(finalContent), 0o600)
	}

	return finalContent, nil
}

func parseIDs(rawIDs []string) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, raw := range rawIDs {
		for part := range strings.SplitSeq(raw, ",") {
			id := strings.TrimSpace(part)
			if id == "" {
				continue
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

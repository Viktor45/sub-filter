// Пакет main реализует утилиту для фильтрации прокси-подписок.
// Поддерживает два режима работы:
//   - HTTP-сервер для динамической фильтрации (/filter?id=1)
//   - CLI-режим для однократной обработки всех подписок (--cli)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// === Константы конфигурации ===

const (
	defaultSourcesFile  = "./config/sub.txt"    // Файл со списком URL подписок
	defaultBadWordsFile = "./config/bad.txt"    // Файл с запрещёнными словами
	defaultUAgentFile   = "./config/uagent.txt" // Файл с разрешёнными User-Agent
	defaultCacheDir     = "./cache"             // Директория для кэша
	maxIDLength         = 64                    // Макс. длина идентификатора источника
	maxURILength        = 4096                  // Макс. длина одной строки подписки
	maxUserinfoLength   = 1024                  // Макс. длина userinfo в URI
	maxSourceBytes      = 10 * 1024 * 1024      // Макс. размер скачиваемой подписки (10 МБ)

	// Параметры rate limiting
	limiterBurst    = 5                      // Макс. число запросов за раз
	limiterEvery    = 100 * time.Millisecond // Интервал пополнения лимита
	cleanupInterval = 2 * time.Minute        // Интервал очистки старых лимитёров
	inactiveTimeout = 30 * time.Minute       // Время неактивности для удаления лимитёра
)

// SafeSource представляет проверенный источник подписки с зарезолвленным публичным IP.
type SafeSource struct {
	URL string // Исходный URL подписки
	IP  net.IP // Публичный IP, на который будет выполнен фетч
}

// SourceMap — карта источников, где ключ — строковый ID (1, 2, 3...).
type SourceMap map[string]*SafeSource

// === Глобальные переменные конфигурации ===

var (
	cacheDir  string        // Директория кэша (устанавливается при запуске)
	cacheTTL  time.Duration // Время жизни кэша
	sources   SourceMap     // Валидированные источники подписок
	badWords  []string      // Список запрещённых слов для фильтрации
	allowedUA []string      // Список разрешённых User-Agent
)

// === Регулярные выражения для валидации ===

var (
	validIDRe  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)                                                   // Валидный ID источника
	ssCipherRe = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)                                                 // Валидный шифр Shadowsocks
	hostRegex  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`) // Валидный домен
)

// === Rate limiting по IP-адресам ===

var (
	ipLimiter    = make(map[string]*rate.Limiter) // Лимитёры по IP
	ipLastSeen   = make(map[string]time.Time)     // Последнее обращение по IP
	limiterMutex sync.RWMutex                     // Мьютекс для безопасного доступа
)

// === HTTP-фетчер с дедупликацией ===
// fetchGroup используется для предотвращения параллельных фетчей одного источника.
var fetchGroup singleflight.Group

// Встроенные разрешённые User-Agent-префиксы.
var builtinAllowedPrefixes = []string{"clash", "happ"}

// LineProcessor — тип функции для обработки строк при загрузке файлов.
type LineProcessor func(string) string

// loadTextFile загружает текстовый файл, пропуская пустые строки и комментарии.
// Применяет опциональный процессор к каждой строке.
func loadTextFile(filename string, processor LineProcessor) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	// Пропускаем BOM, если есть
	if b, err := reader.Peek(3); err == nil && bytes.Equal(b, []byte{0xEF, 0xBB, 0xBF}) {
		reader.Discard(3)
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

// getDefaultPort возвращает стандартный порт для схемы.
func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// isValidSourceURL проверяет, что URL подписки безопасен для фетча.
// Запрещает localhost, приватные IP, loopback и специальные домены.
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
	if strings.HasPrefix(host, "xn--") { // Punycode
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		// Используем централизованную проверку IP
		return isIPAllowed(ip)
	}
	return true
}

// isIPAllowed проверяет, что IP-адрес является публичным и пригодным для фетча.
func isIPAllowed(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// getLimiter возвращает или создаёт rate.Limiter для IP-адреса.
func getLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	ipLastSeen[ip] = time.Now()
	if limiter, exists := ipLimiter[ip]; exists {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Every(limiterEvery), limiterBurst)
	ipLimiter[ip] = limiter
	return limiter
}

// cleanupLimiters запускает фоновую горутину для удаления неактивных лимитёров.
func cleanupLimiters() {
	ticker := time.NewTicker(cleanupInterval)
	go func() {
		for range ticker.C {
			limiterMutex.Lock()
			now := time.Now()
			for ip, last := range ipLastSeen {
				if now.Sub(last) > inactiveTimeout {
					delete(ipLimiter, ip)
					delete(ipLastSeen, ip)
				}
			}
			limiterMutex.Unlock()
		}
	}()
}

// decodeUserInfo декодирует строку с учётом всех 4 вариантов base64 (Std, Raw, URL-safe).
// Аналог utils.AutoDecode из эталонного парсера.
func decodeUserInfo(s string) ([]byte, error) {
	isURLSafe := strings.ContainsAny(s, "-_")
	isPadded := strings.HasSuffix(s, "=")

	var enc *base64.Encoding
	switch {
	case isURLSafe && isPadded:
		enc = base64.URLEncoding
	case isURLSafe && !isPadded:
		enc = base64.RawURLEncoding
	case !isURLSafe && isPadded:
		enc = base64.StdEncoding
	case !isURLSafe && !isPadded:
		enc = base64.RawStdEncoding
	default:
		enc = base64.RawURLEncoding
	}
	return enc.DecodeString(s)
}

// isValidUserAgent проверяет, что User-Agent разрешён.
// Поддерживает встроенные префиксы и внешний список.
func isValidUserAgent(ua string) bool {
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

// isValidHost проверяет корректность хоста (домен или публичный IP).
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "xn--") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// isValidPort проверяет, что порт в допустимом диапазоне.
func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// fullyDecode рекурсивно декодирует URL-escape-последовательности.
// Используется для проверки запрещённых слов в названиях.
func fullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

// isForbiddenAnchor проверяет, содержит ли fragment (название сервера) запрещённые слова.
// Поддерживает URL-escaped имена.
func isForbiddenAnchor(fragment string) bool {
	if fragment == "" {
		return false
	}
	decoded := fullyDecode(fragment)
	decodedLower := strings.ToLower(decoded)
	for _, word := range badWords {
		if word != "" && strings.Contains(decodedLower, word) {
			return true
		}
	}
	return false
}

// parseHostPort извлекает и проверяет хост и порт из URL.
// Возвращает хост, порт и флаг успеха.
func parseHostPort(u *url.URL) (string, int, bool) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) || !isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

// isSafeVLESSConfig проверяет безопасность конфигурации VLESS.
// Блокирует: allowInsecure, security=none, reality без sni, flow без reality, gRPC без serviceName.
func isSafeVLESSConfig(q url.Values) bool {
	if q.Get("allowInsecure") == "true" {
		return false
	}
	if q.Get("security") == "none" {
		return false
	}
	if q.Get("security") == "reality" && q.Get("sni") == "" {
		return false
	}
	flow := q.Get("flow")
	if flow != "" && q.Get("security") != "reality" {
		return false
	}
	if q.Get("type") == "grpc" && q.Get("serviceName") == "" {
		return false
	}
	return true
}

// isSafeTrojanConfig проверяет безопасность конфигурации Trojan.
// Разрешает allowInsecure (осознанное решение), но блокирует gRPC без serviceName.
func isSafeTrojanConfig(q url.Values) bool {
	if q.Get("type") == "grpc" && q.Get("serviceName") == "" {
		return false
	}
	return true // allowInsecure разрешён
}

// === Обработка отдельных протоколов ===

// processVLESS обрабатывает VLESS-ссылку: валидирует, фильтрует, пересобирает.
func processVLESS(s string) string {
	if len(s) > maxURILength {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "vless" {
		return ""
	}

	uuid := u.User.Username()
	if uuid == "" || len(uuid) > maxIDLength {
		return ""
	}

	host, port, ok := parseHostPort(u)
	if !ok {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	if !isSafeVLESSConfig(u.Query()) {
		return ""
	}

	q := u.Query()
	if alpnList := q["alpn"]; len(alpnList) > 0 {
		q["alpn"] = alpnList[:1] // Оставляем только первый ALPN
	}

	var buf strings.Builder
	buf.WriteString("vless://")
	buf.WriteString(uuid) // UUID не экранируется повторно
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	if u.Path != "" {
		buf.WriteString(u.Path)
	}
	if len(q) > 0 {
		buf.WriteString("?")
		buf.WriteString(q.Encode())
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// processVMess обрабатывает VMess-ссылку (base64-encoded JSON).
func processVMess(s string) string {
	if len(s) > maxURILength {
		return ""
	}

	if !strings.HasPrefix(strings.ToLower(s), "vmess://") {
		return ""
	}

	b64 := strings.TrimPrefix(s, "vmess://")
	if b64 == "" {
		return ""
	}

	decoded, err := decodeUserInfo(b64)
	if err != nil {
		return ""
	}

	var vm map[string]interface{}
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return ""
	}

	ps, _ := vm["ps"].(string)
	add, _ := vm["add"].(string)
	port, ok := vm["port"].(float64)
	if !ok {
		return ""
	}
	id, _ := vm["id"].(string)

	if add == "" || id == "" {
		return ""
	}

	if int(port) <= 0 || int(port) > 65535 {
		return ""
	}

	if !isValidHost(add) {
		return ""
	}

	if isForbiddenAnchor(ps) {
		return ""
	}

	netType, _ := vm["net"].(string)
	if netType == "grpc" {
		svc, _ := vm["serviceName"].(string)
		if svc == "" {
			return ""
		}
	}

	tls, _ := vm["tls"].(string)
	if netType != "grpc" && tls != "tls" {
		return ""
	}

	reencoded, err := json.Marshal(vm)
	if err != nil {
		return ""
	}

	finalB64 := base64.StdEncoding.EncodeToString(reencoded)
	return "vmess://" + finalB64
}

// processTrojan обрабатывает Trojan-ссылку.
func processTrojan(s string) string {
	if len(s) > maxURILength {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "trojan" {
		return ""
	}

	password := u.User.Username()
	if password == "" {
		return ""
	}

	host, port, ok := parseHostPort(u)
	if !ok {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	if !isSafeTrojanConfig(u.Query()) {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("trojan://")
	buf.WriteString(password) // Пароль не экранируется — он уже в правильной кодировке
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	q := u.Query()
	if len(q) > 0 {
		buf.WriteString("?")
		buf.WriteString(q.Encode())
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// processSS обрабатывает Shadowsocks-ссылку.
func processSS(s string) string {
	if len(s) > maxURILength {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "ss" {
		return ""
	}

	userinfo := u.User.String()
	if userinfo == "" || len(userinfo) > maxUserinfoLength {
		return ""
	}

	decoded, decodeErr := decodeUserInfo(userinfo)
	if decodeErr != nil {
		return ""
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	cipher, password := parts[0], parts[1]
	if cipher == "" || password == "" || !ssCipherRe.MatchString(cipher) {
		return ""
	}

	host, port, ok := parseHostPort(u)
	if !ok {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	newUser := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
	var buf strings.Builder
	buf.WriteString("ss://")
	buf.WriteString(newUser)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// isPathSafe проверяет, что путь находится внутри базовой директории (защита от path traversal).
func isPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// serveFile отдаёт подписку как attachment с правильным Content-Disposition.
func serveFile(w http.ResponseWriter, r *http.Request, content []byte, sourceURL, id string) {
	filename := "filtered_" + id + ".txt"
	if u, err := url.Parse(sourceURL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			filename = base
		}
	}
	filename = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(filename, "_")
	if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
		filename += ".txt"
	}
	filename = filepath.Base(filename)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

// isLocalIP проверяет, является ли IP-адрес локальным (loopback или private).
// Используется для исключения из rate limiting.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // недекодируемое — считаем локальным (консервативно)
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// processSource обрабатывает одну подписку и сохраняет результат в кэш.
// Используется как в HTTP-обработчике, так и в CLI-режиме.
// Использует fetchGroup для дедупликации параллельных фетчей одного источника.
func processSource(id string, source *SafeSource) error {
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return fmt.Errorf("invalid source URL: %v", err)
	}
	host := parsedSource.Hostname()
	if !isValidHost(host) {
		return fmt.Errorf("invalid source host: %s", host)
	}

	origCache := filepath.Join(cacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cacheDir, "mod_"+id+".txt")
	rejectedCache := filepath.Join(cacheDir, "rejected_"+id+".txt")

	if !isPathSafe(origCache, cacheDir) || !isPathSafe(modCache, cacheDir) || !isPathSafe(rejectedCache, cacheDir) {
		return fmt.Errorf("unsafe cache path for id=%s", id)
	}

	// Если уже обработано и не устарело — ничего не делаем
	if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		return nil
	}

	var origContent []byte
	if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(origCache); err == nil {
			origContent = content
		}
	}

	if origContent == nil {
		_, portStr, _ := net.SplitHostPort(parsedSource.Host)
		if portStr == "" {
			portStr = getDefaultPort(parsedSource.Scheme)
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
				},
				TLSClientConfig: &tls.Config{
					ServerName: host,
				},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		// Используем fetchGroup для дедупликации фетчей
		result, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, fmt.Errorf("create request: %w", err)
			}
			req.Header.Set("User-Agent", "go-filter/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("fetch failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 400 {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}

			content, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
			if err != nil {
				return nil, fmt.Errorf("read failed: %w", err)
			}

			// Сохраняем исходную подписку в кэш
			tmpFile := origCache + ".tmp"
			if writeErr := os.WriteFile(tmpFile, content, 0o644); writeErr == nil {
				os.Rename(tmpFile, origCache)
			}
			return content, nil
		})
		if err != nil {
			return err
		}
		origContent = result.([]byte)
	}

	// Обработка строк подписки
	var out []string
	var rejectedLines []string

	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}

		if len(originalLine) > maxURILength {
			rejectedLines = append(rejectedLines, "# REASON: Line too long", originalLine)
			continue
		}

		lowerLine := strings.ToLower(originalLine)
		var processedLine string

		switch {
		case strings.HasPrefix(lowerLine, "vless://"):
			processedLine = processVLESS(originalLine)
		case strings.HasPrefix(lowerLine, "vmess://"):
			processedLine = processVMess(originalLine)
		case strings.HasPrefix(lowerLine, "trojan://"):
			processedLine = processTrojan(originalLine)
		case strings.HasPrefix(lowerLine, "ss://"):
			processedLine = processSS(originalLine)
		}

		if processedLine != "" {
			out = append(out, processedLine)
		} else {
			reason := "Processing failed"
			if strings.HasPrefix(lowerLine, "vless://") {
				reason = "Invalid or unsafe VLESS link"
			} else if strings.HasPrefix(lowerLine, "vmess://") {
				reason = "Invalid or unsafe VMess link"
			} else if strings.HasPrefix(lowerLine, "trojan://") {
				reason = "Invalid or unsafe Trojan link"
			} else if strings.HasPrefix(lowerLine, "ss://") {
				reason = "Invalid or unsafe Shadowsocks link"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}

	// Сохраняем rejected-файл или удаляем, если пуст
	if len(rejectedLines) > 0 {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpRejectedFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpRejectedFile, []byte(rejectedContent), 0o644); err == nil {
			os.Rename(tmpRejectedFile, rejectedCache)
		}
	} else {
		os.Remove(rejectedCache) // Игнорируем ошибку "файл не найден"
	}

	// Формируем итоговую подписку
	sourceHost := "unknown"
	if h, _, err := net.SplitHostPort(parsedSource.Host); err == nil {
		sourceHost = h
	} else {
		sourceHost = parsedSource.Host
	}

	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}

	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", sourceHost, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)

	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	tmpFile := modCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(final), 0o644); err == nil {
		os.Rename(tmpFile, modCache)
	}

	return nil
}

// handler обрабатывает HTTP-запрос /filter?id=...
func handler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Пропускаем лимитирование для локальных IP (127.0.0.1, ::1, 192.168.x.x, fd00::/8 и т.д.)
	if !isLocalIP(clientIP) {
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	if !isValidUserAgent(r.Header.Get("User-Agent")) {
		http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	source, exists := sources[id]
	if !exists {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	err = processSource(id, source)
	if err != nil {
		http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
		return
	}

	content, err := os.ReadFile(filepath.Join(cacheDir, "mod_"+id+".txt"))
	if err != nil {
		http.Error(w, "Result not found", http.StatusNotFound)
		return
	}

	serveFile(w, r, content, source.URL, id)
}

// loadSources загружает и валидирует источники подписок.
// Возвращает SourceMap и ошибку.
func loadSources(sourcesFile string) (SourceMap, error) {
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load sources: %w", err)
	}
	sources := make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			fmt.Fprintf(os.Stderr, "Skipping invalid or unsafe source URL: %s\n", line)
			continue
		}

		u, _ := url.Parse(line)
		host := u.Hostname()
		portStr := u.Port()
		if portStr == "" {
			portStr = getDefaultPort(u.Scheme)
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resolve host %s: %v\n", host, err)
			continue
		}

		var allowedIP net.IP
		for _, ip := range ips {
			if isIPAllowed(ip) {
				allowedIP = ip
				break
			}
		}
		if allowedIP == nil {
			fmt.Fprintf(os.Stderr, "No allowed public IP for host %s\n", host)
			continue
		}

		sources[strconv.Itoa(validIndex)] = &SafeSource{
			URL: line,
			IP:  allowedIP,
		}
		validIndex++
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no valid sources loaded")
	}
	return sources, nil
}

// main — точка входа программы с поддержкой двух режимов.
func main() {
	cliMode := flag.Bool("cli", false, "Run in CLI mode: process all sources once and exit")
	flag.Parse()

	if *cliMode {
		// === CLI-режим: обработать все подписки один раз и выйти ===
		cacheTTLSeconds := 1800
		sourcesFile := defaultSourcesFile
		badWordsFile := defaultBadWordsFile
		uagentFile := defaultUAgentFile

		args := flag.Args()
		if len(args) >= 1 {
			if sec, err := strconv.Atoi(args[0]); err == nil && sec > 0 {
				cacheTTLSeconds = sec
			}
		}
		if len(args) >= 2 {
			sourcesFile = args[1]
		}
		if len(args) >= 3 {
			badWordsFile = args[2]
		}
		if len(args) >= 4 {
			uagentFile = args[3]
		}

		cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
		cacheDir = defaultCacheDir // Используем ту же директорию, что и в серверном режиме

		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
			os.Exit(1)
		}

		// Загрузка источников
		var err error
		sources, err = loadSources(sourcesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
			os.Exit(1)
		}

		badWords, err = loadTextFile(badWordsFile, strings.ToLower)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load bad words: %v (using empty list)\n", err)
			badWords = []string{}
		}

		allowedUA, err = loadTextFile(uagentFile, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Note: using built-in User-Agent rules only (no %s or error: %v)\n", uagentFile, err)
			allowedUA = []string{}
		}

		fmt.Printf("Processing %d sources to cache dir: %s\n", len(sources), cacheDir)
		for id, source := range sources {
			fmt.Printf("Processing source %s: %s\n", id, source.URL)
			if err := processSource(id, source); err != nil {
				fmt.Fprintf(os.Stderr, "Failed source %s: %v\n", id, err)
			} else {
				fmt.Printf("Success: mod_%s.txt saved\n", id)
			}
		}
		fmt.Println("Done.")
		return
	}

	// === Серверный режим: запуск HTTP-сервера ===
	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage (server mode): %s <port> [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage (CLI mode): %s --cli [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		os.Exit(1)
	}

	port := flag.Args()[0]
	cacheTTLSeconds := 1800
	if len(flag.Args()) >= 2 {
		if sec, err := strconv.Atoi(flag.Args()[1]); err == nil && sec > 0 {
			cacheTTLSeconds = sec
		}
	}
	sourcesFile := defaultSourcesFile
	if len(flag.Args()) >= 3 {
		sourcesFile = flag.Args()[2]
	}
	badWordsFile := defaultBadWordsFile
	if len(flag.Args()) >= 4 {
		badWordsFile = flag.Args()[3]
	}
	uagentFile := defaultUAgentFile
	if len(flag.Args()) >= 5 {
		uagentFile = flag.Args()[4]
	}

	cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
	cacheDir = defaultCacheDir

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Загрузка источников
	var err error
	sources, err = loadSources(sourcesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
		os.Exit(1)
	}

	badWords, err = loadTextFile(badWordsFile, strings.ToLower)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load bad words: %v (using empty list)\n", err)
		badWords = []string{}
	}

	allowedUA, err = loadTextFile(uagentFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note: using built-in User-Agent rules only (no %s or error: %v)\n", uagentFile, err)
		allowedUA = []string{}
	}

	cleanupLimiters()
	http.HandleFunc("/filter", handler)

	// IPv6-ready запуск сервера: слушает и IPv4, и IPv6
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot listen on port %s: %v\n", port, err)
		os.Exit(1)
	}
	server := &http.Server{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	fmt.Printf("Server listening on :%s (IPv4/IPv6)\n", port)
	fmt.Printf("Valid sources loaded: %d\n", len(sources))
	fmt.Printf("Bad words: %s\n", badWordsFile)
	fmt.Printf("User-Agent file: %s\n", uagentFile)
	fmt.Printf("Cache TTL: %ds\n", cacheTTLSeconds)

	if err := server.Serve(listener); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

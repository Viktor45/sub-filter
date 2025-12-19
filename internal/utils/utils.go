// internal/utils/utils.go
// Пакет utils содержит общие вспомогательные функции для обработки прокси-подписок.
// Все функции чистые и не зависят от глобального состояния.
package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// === Регулярные выражения ===
var (
	// hostRegex валидирует доменные имена (включая Punycode xn--)
	hostRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
	// ssCipherRe валидирует шифры Shadowsocks
	ssCipherRe = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)
	// base64UrlRegex валидирует 32-байтный ключ в base64url без padding (43 символа)
	base64UrlRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// IsPrintableASCII проверяет, что байты содержат только печатаемые ASCII-символы.
// Допускает \n, \r, \t.
func IsPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b >= 32 && b <= 126 {
			continue
		}
		if b == 10 || b == 13 || b == 9 { // '\n' || '\r' || '\t'
			continue
		}
		return false
	}
	return true
}

// AutoDecodeBase64 пытается декодировать весь входной буфер как base64.
// Если успешно и результат — печатаемый ASCII — возвращает декодированные байты.
// Иначе — возвращает исходные данные.
func AutoDecodeBase64(data []byte) []byte {
	trimmed := regexp.MustCompile(`\s+`).ReplaceAll(data, []byte{})
	missingPadding := len(trimmed) % 4
	if missingPadding != 0 {
		trimmed = append(trimmed, bytes.Repeat([]byte{'='}, 4-missingPadding)...)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(string(trimmed))
		if err != nil {
			return data
		}
	}
	return decoded
}

// DecodeUserInfo безопасно декодирует base64-закодированный userinfo,
// определяя тип кодировки по наличию символов и padding.
func DecodeUserInfo(s string) ([]byte, error) {
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

// IsValidHost проверяет, что хост — это либо валидный домен,
// либо IP-адрес.
func IsValidHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// IsValidPort проверяет, что порт находится в диапазоне 1–65535.
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// FullyDecode рекурсивно декодирует URL-encoded строки.
func FullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

// ParseHostPort извлекает и валидирует хост и порт из *url.URL.
func ParseHostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port")
	}
	if !IsValidPort(port) {
		return "", 0, fmt.Errorf("port out of range")
	}
	if !IsValidHost(host) {
		return "", 0, fmt.Errorf("invalid host")
	}
	return host, port, nil
}

// IsPathSafe проверяет, что путь не выходит за пределы baseDir.
func IsPathSafe(p, baseDir string) bool {
	// Resolve symlinks for both baseDir and path to avoid escaping via symlink tricks
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		resolvedBase = baseDir
	}
	resolvedPath, err := filepath.EvalSymlinks(p)
	if err != nil {
		resolvedPath = p
	}
	cleanPath := filepath.Clean(resolvedPath)
	rel, err := filepath.Rel(resolvedBase, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// NormalizeLinkKey извлекает ключевые компоненты из URL-адреса прокси-ссылки для дедупликации.
// Игнорирует фрагментную часть (#...).
// Порты 80 и 443 ВСЕГДА включаются в ключ.
// Пути "/" и "" считаются одинаковыми.
// Query-параметры сортируются.
func NormalizeLinkKey(line string) (string, error) {
	u, err := url.Parse(line)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("URL has no scheme")
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL has no host")
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())

	portStr := u.Port()
	if portStr == "" {
		if scheme == "https" {
			portStr = "443"
		} else if scheme == "http" {
			portStr = "80"
		}
	}

	var hostWithPort string
	if portStr != "" {
		hostWithPort = net.JoinHostPort(host, portStr)
	} else {
		hostWithPort = host
	}

	path := u.Path
	if path == "/" {
		path = ""
	}

	// Извлекаем параметры
	params := u.Query()
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys) // ← сортируем ключи

	// Собираем отсортированные "key=value"
	var queryParts []string
	for _, k := range keys {
		queryParts = append(queryParts, k+"="+params.Get(k))
	}
	queryStr := strings.Join(queryParts, "&")
	if queryStr == "" {
		return fmt.Sprintf("%s://%s%s", scheme, hostWithPort, path), nil
	}
	return fmt.Sprintf("%s://%s%s?%s", scheme, hostWithPort, path, queryStr), nil
}

// CompareAndSelectBetter выбирает "лучшую" из двух дублирующих ссылок.
// Предпочитает ту, у которой больше query-параметров.
func CompareAndSelectBetter(currentLine, existingLine string) string {
	uCurrent, err1 := url.Parse(currentLine)
	uExisting, err2 := url.Parse(existingLine)

	if err1 != nil {
		return existingLine
	}
	if err2 != nil {
		return currentLine
	}

	score := func(u *url.URL) int {
		s := 0
		q := u.Query()
		if sec := strings.ToLower(q.Get("security")); sec != "" && sec != "none" {
			s += 50
		}
		if q.Get("tls") != "" {
			s += 10
		}
		s += len(q)
		return s
	}

	if score(uCurrent) > score(uExisting) {
		return currentLine
	}
	if score(uExisting) > score(uCurrent) {
		return existingLine
	}
	return existingLine // стабильность: оставить старую
}

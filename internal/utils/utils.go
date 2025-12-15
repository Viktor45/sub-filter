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
		if b == '\n' || b == '\r' || b == '\t' {
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
	// Удаляем все пробельные символы
	trimmed := regexp.MustCompile(`\s+`).ReplaceAll(data, []byte{})
	// Дополняем padding до кратности 4
	missingPadding := len(trimmed) % 4
	if missingPadding != 0 {
		trimmed = append(trimmed, bytes.Repeat([]byte{'='}, 4-missingPadding)...)
	}
	// Пробуем StdEncoding
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		// Пробуем RawStdEncoding
		decoded, err = base64.RawStdEncoding.DecodeString(string(trimmed))
		if err != nil {
			return data
		}
	}
	if !IsPrintableASCII(decoded) {
		return data
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
// либо публичный IP-адрес.
func IsValidHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true // IP всегда считается валидным здесь (фильтрация по типу — отдельно)
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// IsValidPort проверяет, что порт находится в диапазоне 1–65535.
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// FullyDecode рекурсивно декодирует URL-encoded строки (например, %D0%9F → П).
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
// Возвращает ошибку, если порт отсутствует, недействителен или хост невалиден.
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

// IsPathSafe проверяет, что путь не выходит за пределы baseDir (защита от path traversal).
func IsPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

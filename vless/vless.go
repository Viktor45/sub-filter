// Пакет vless — обработчик ссылок VLESS.
// Проверяет безопасность конфигурации, валидирует параметры и фильтрует по bad-words.
package vless

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Глобальные зависимости (инжектятся из main)
var (
	badWords       []string
	isValidHost    func(string) bool
	isValidPort    func(int) bool
	checkBadWords  func(string) (bool, string)
	hostRegex      = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
	base64UrlRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`) // 32-байтный ключ в base64url без padding
)

// VLESSLink — реализация интерфейса ProxyLink для VLESS.
type VLESSLink struct{}

// SetGlobals внедряет зависимости (badWords, валидаторы и т.д.).
func SetGlobals(
	bw []string,
	vh func(string) bool,
	vp func(int) bool,
	cb func(string) (bool, string),
) {
	badWords = bw
	isValidHost = vh
	isValidPort = vp
	checkBadWords = cb
}

// Matches проверяет, начинается ли строка с vless://.
func (VLESSLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vless://")
}

// Process обрабатывает VLESS-ссылку.
// Возвращает обработанную строку или причину отклонения.
func (VLESSLink) Process(s string) (string, string) {
	const maxURILength = 4096
	const maxIDLength = 64

	if len(s) > maxURILength {
		return "", "line too long"
	}

	u, err := url.Parse(s)
	if err != nil || u.Scheme != "vless" {
		return "", "invalid VLESS URL format"
	}

	uuid := u.User.Username()
	if uuid == "" || len(uuid) > maxIDLength {
		return "", "missing or invalid UUID"
	}

	host, port, hostErr := validateVLESSHostPort(u)
	if hostErr != "" {
		return "", "VLESS: " + hostErr
	}

	if hasBad, reason := checkBadWords(u.Fragment); hasBad {
		return "", reason
	}

	q := u.Query()

	// === Удаляем insecure и allowInsecure независимо от значения ===
	// Эти параметры избыточны (значения по умолчанию) или снижают безопасность.
	// Полное удаление упрощает ссылку и гарантирует валидацию сертификата.
	q.Del("insecure")
	q.Del("allowInsecure")
	// =================================================================

	// === Проверка параметра encryption (защита от обхода вроде none%3D) ===
	encryptionRaw := q.Get("encryption")
	if encryptionRaw == "" {
		return "", "VLESS: encryption parameter is missing (outdated format)"
	}

	// Декодируем, если значение закодировано (например, none%3D → none=)
	encryptionDecoded, err := url.QueryUnescape(encryptionRaw)
	if err != nil {
		// Если декодирование невозможно — используем как есть
		encryptionDecoded = encryptionRaw
	}

	// Нормализуем: удаляем trailing = и пробелы, приводим к нижнему регистру
	encryptionNormalized := strings.ToLower(strings.TrimRight(encryptionDecoded, " ="))

	if encryptionNormalized == "none" {
		return "", "VLESS: encryption=none is not allowed (insecure)"
	}
	// =================================================================

	// Валидация всех остальных параметров
	if err := validateVLESSParams(q); err != "" {
		return "", "VLESS: " + err
	}

	// Обработка ALPN: оставляем только первый валидный токен
	if alpnValues := q["alpn"]; len(alpnValues) > 0 {
		rawAlpn := alpnValues[0]
		var firstValid string
		if strings.HasPrefix(rawAlpn, "h3") {
			firstValid = "h3"
		} else if strings.HasPrefix(rawAlpn, "h2") {
			firstValid = "h2"
		} else if strings.HasPrefix(rawAlpn, "http/1.1") {
			firstValid = "http/1.1"
		} else {
			if idx := strings.IndexByte(rawAlpn, ','); idx != -1 {
				firstValid = rawAlpn[:idx]
			} else {
				firstValid = rawAlpn
			}
		}
		if firstValid != "" {
			q["alpn"] = []string{firstValid}
		} else {
			delete(q, "alpn")
		}
	}

	// Сборка итоговой ссылки
	var buf strings.Builder
	buf.WriteString("vless://")
	buf.WriteString(uuid)
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
	return buf.String(), ""
}

// Валидация хоста и порта
func validateVLESSHostPort(u *url.URL) (string, int, string) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, "missing port"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, "invalid port"
	}
	if !isValidPort(port) {
		return "", 0, "port out of range"
	}
	if !isValidHost(host) {
		return "", 0, "invalid host"
	}
	return host, port, ""
}

// Дополнительные проверки безопасности
func isSafeVLESSConfig(q url.Values) string {
	flow := q.Get("flow")
	if flow != "" && q.Get("security") != "reality" {
		return "flow requires reality"
	}
	if q.Get("type") == "grpc" && q.Get("serviceName") == "" {
		return "gRPC requires serviceName"
	}
	return ""
}

// Основная валидация параметров VLESS
func validateVLESSParams(q url.Values) string {
	security := q.Get("security")
	if security == "" {
		return "security parameter is missing (insecure)"
	}
	if security == "none" {
		return "security=none is not allowed"
	}
	if (security == "tls" || security == "reality") && q.Get("sni") == "" {
		return "sni is required for security=tls or reality"
	}
	if security == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			return "missing pbk (public key) for reality"
		}
		if !base64UrlRegex.MatchString(pbk) {
			return "invalid pbk format (must be 43-char base64url)"
		}
		if q.Get("type") == "xhttp" {
			mode := q.Get("mode")
			if mode != "" && mode != "packet" {
				return "invalid mode for xhttp (must be empty or 'packet')"
			}
		}
	}
	transportType := q.Get("type")
	headerType := q.Get("headerType")
	if headerType != "" && headerType != "none" && transportType != "kcp" && transportType != "quic" {
		return fmt.Sprintf("headerType is only allowed with kcp or quic (got type=%s, headerType=%s)", transportType, headerType)
	}
	if (transportType == "ws" || transportType == "httpupgrade" || transportType == "xhttp") && q.Get("path") == "" {
		return fmt.Sprintf("path is required when type=%s", transportType)
	}
	if reason := isSafeVLESSConfig(q); reason != "" {
		return reason
	}
	return ""
}

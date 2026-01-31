// Package utils содержит общие вспомогательные функции для обработки
// прокси-подписок и работы с URL-параметрами, декодированием и т.п.
//
//nolint:revive
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

// ParamsFromValues конвертирует url.Values в map[string]string, беря первый элемент каждого ключа.
func ParamsFromValues(vals url.Values) map[string]string {
	if vals == nil {
		return map[string]string{}
	}
	m := make(map[string]string, len(vals))
	for k, vs := range vals {
		if len(vs) > 0 {
			m[k] = vs[0]
		}
	}
	return m
}

// ParamsFromInterface конвертирует map[string]interface{} в map[string]string.
// Используется для структур типа JSON -> строковые параметры.
func ParamsFromInterface(src map[string]interface{}) map[string]string {
	if src == nil {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		switch vv := v.(type) {
		case string:
			dst[k] = vv
		case float64:
			if vv == float64(int64(vv)) {
				dst[k] = strconv.Itoa(int(vv))
			} else {
				dst[k] = strconv.FormatFloat(vv, 'f', -1, 64)
			}
		case int:
			dst[k] = strconv.Itoa(vv)
		case int64:
			dst[k] = strconv.FormatInt(vv, 10)
		case bool:
			if vv {
				dst[k] = "true"
			} else {
				dst[k] = "false"
			}
		default:
			// fallback to fmt.Sprintf
			dst[k] = fmt.Sprintf("%v", vv)
		}
	}
	return dst
}

// EncodeRawURBase64 кодирует данные в base64 URL-safe без padding.
func EncodeRawURBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// NormalizeALPN выбирает первый допустимый alpn-идентификатор из строки.
// Возвращает пустую строку, если ничего подходящего не найдено.
func NormalizeALPN(raw string) string {
	if raw == "" {
		return ""
	}
	// берем до первой запятой
	if idx := strings.IndexByte(raw, ','); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "h3") {
		return "h3"
	}
	if strings.HasPrefix(raw, "h2") {
		return "h2"
	}
	if strings.HasPrefix(raw, "http/1.1") {
		return "http/1.1"
	}
	return raw
}

// NormalizeParams нормализует map[string]string: ключи в lower-case, значения trimmed.
// Пустые значения удаляются.
func NormalizeParams(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		nk := strings.ToLower(strings.TrimSpace(k))
		nv := strings.TrimSpace(v)
		out[nk] = nv
	}
	return out
}

// === Регулярные выражения ===
var (
	// hostRegex валидирует доменные имена (включая Punycode xn--)
	hostRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
	// ssCipherRe валидирует шифры Shadowsocks (если потребуется в будущем).
	// Дефиниции конкретных шифров находятся в пакетах протоколов.
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
	// Удаляем пробельные символы без выделения regex'а каждый вызов
	trimmed := bytes.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, data)
	// Попробуем стандартный base64 с padding; если неудача — raw
	s := string(trimmed)
	if m := len(trimmed) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d
	}
	if d, err := base64.RawStdEncoding.DecodeString(string(trimmed)); err == nil {
		return d
	}
	return data
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
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		// Если не удалось разрешить симлинки (директория может не существовать),
		// используем абсолютный путь в качестве fallback.
		resolvedBase, err = filepath.Abs(baseDir)
		if err != nil {
			return false
		}
	}
	resolvedBase = filepath.Clean(resolvedBase)

	// Разрешаем только родительскую директорию файла
	dir := filepath.Dir(p)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		// Если директория не существует, используем Abs + Clean
		resolvedDir, err = filepath.Abs(dir)
		if err != nil {
			return false
		}
	}
	resolvedDir = filepath.Clean(resolvedDir)

	// Формируем полный путь к файлу уже в разрешённой директории
	candidate := filepath.Join(resolvedDir, filepath.Base(p))

	// Проверяем префикс
	return strings.HasPrefix(candidate, resolvedBase+string(filepath.Separator)) || candidate == resolvedBase
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
		switch scheme {
		case "https":
			portStr = "443"
		case "http":
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

	// Извлекаем параметры и нормализуем: ключи -> lower-case, значения -> trimmed,
	// пустые значения удаляем (они не должны влиять на ключ дедупликации).
	rawParams := u.Query()
	keys := make([]string, 0, len(rawParams))
	norm := make(map[string]string, len(rawParams))
	origKey := make(map[string]string, len(rawParams))
	for k, vs := range rawParams {
		if len(vs) == 0 {
			continue
		}
		v := strings.TrimSpace(vs[0])
		if v == "" {
			continue
		}
		nk := strings.ToLower(strings.TrimSpace(k))
		// preserve original key casing for the first occurrence
		if _, exists := origKey[nk]; !exists {
			origKey[nk] = k
		}
		norm[nk] = v
		keys = append(keys, nk)
	}
	sort.Strings(keys)
	// Если нет параметров — возвращаем без '?'
	if len(keys) == 0 {
		if path == "" {
			return fmt.Sprintf("%s://%s", scheme, hostWithPort), nil
		}
		return fmt.Sprintf("%s://%s%s", scheme, hostWithPort, path), nil
	}
	qp := make([]string, 0, len(keys))
	for _, k := range keys {
		outKey := origKey[k]
		qp = append(qp, outKey+"="+norm[k])
	}
	queryStr := strings.Join(qp, "&")
	return fmt.Sprintf("%s://%s%s?%s", scheme, hostWithPort, path, queryStr), nil
}

// CompareAndSelectBetter выбирает "лучшую" из двух дублирующих ссылок.
// Предпочитает ту, у которой больше query-параметров.
func CompareAndSelectBetter(currentLine, existingLine string) string {
	u1, err1 := url.Parse(currentLine)
	u2, err2 := url.Parse(existingLine)
	if err1 != nil {
		return existingLine
	}
	if err2 != nil {
		return currentLine
	}
	q1, q2 := u1.Query(), u2.Query()
	score := func(q map[string][]string) int {
		s := 0
		if sec := strings.ToLower(first(q["security"])); sec != "" && sec != "none" {
			s += 50
		}
		if first(q["tls"]) != "" {
			s += 10
		}
		return s + len(q)
	}
	if score(q1) > score(q2) {
		return currentLine
	}
	if score(q2) > score(q1) {
		return existingLine
	}
	return existingLine
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

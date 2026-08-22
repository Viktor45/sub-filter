// pkg/service/format_yaml_file_test.go
package service

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// testSubscriptionFile — пример реальной подписки для проверки format=yaml.
// Путь относителен каталога пакета pkg/service.
const testSubscriptionFile = "../../tmp/test.txt"

// supportedYAMLSchemes — схемы, которые contentToYAML должен преобразовывать.
var supportedYAMLSchemes = map[string]bool{
	"ss": true, "vless": true, "vmess": true,
	"trojan": true, "hy2": true, "hysteria2": true,
}

// loadTestSubscription читает файл-пример. Если файла нет, тест пропускается.
func loadTestSubscription(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(testSubscriptionFile))
	if err != nil {
		t.Skipf("sample file %s not found, skipping: %v", testSubscriptionFile, err)
	}
	return data
}

// extractLinks разбирает содержимое подписки на поддерживаемые ссылки
// и считает неподдерживаемые схемы (для проверки их пропуска).
func extractLinks(t *testing.T, content []byte) (supported []string, unsupported map[string]int) {
	t.Helper()
	unsupported = make(map[string]int)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		if supportedYAMLSchemes[scheme] {
			supported = append(supported, line)
		} else {
			unsupported[scheme]++
		}
	}
	return supported, unsupported
}

// yamlGet проходит по вложенным map YAML и возвращает значение по пути ключей.
func yamlGet(node map[string]any, keys ...string) (any, bool) {
	var cur any = node
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// yamlStr возвращает строковое значение по пути ключей.
func yamlStr(node map[string]any, keys ...string) string {
	v, ok := yamlGet(node, keys...)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// TestFormatYAML_RealSubscriptionFile проверяет преобразование реальной подписки
// в YAML: документ валиден, количество прокси совпадает с числом поддерживаемых
// ссылок, неподдерживаемые схемы пропущены, сырые URL не попадают в вывод.
func TestFormatYAML_RealSubscriptionFile(t *testing.T) {
	content := loadTestSubscription(t)
	supported, unsupported := extractLinks(t, content)

	if len(supported) == 0 {
		t.Fatal("sample file contains no supported proxy links")
	}

	out, contentType, err := formatContent(content, "yaml")
	if err != nil {
		t.Fatalf("formatContent(yaml) returned error: %v", err)
	}
	if contentType != "application/x-yaml; charset=utf-8" {
		t.Errorf("expected x-yaml content type, got %s", contentType)
	}

	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("generated YAML is invalid: %v", err)
	}

	// Количество прокси должно совпадать с числом поддерживаемых ссылок
	if len(doc.Proxies) != len(supported) {
		t.Errorf("proxy count mismatch: got %d, want %d (supported links)", len(doc.Proxies), len(supported))
	}

	// Сырые ссылки не должны попадать в YAML
	outStr := string(out)
	for _, link := range supported {
		if strings.Contains(outStr, link) {
			t.Errorf("raw proxy link leaked into YAML output: %s", link)
			break
		}
	}

	// Имена прокси должны быть непустыми; дубликаты логируются как информация
	// (они могут приходить из самого источника и не являются ошибкой конвертера)
	names := make(map[string]int)
	for i, p := range doc.Proxies {
		name := yamlStr(p, "name")
		if name == "" {
			t.Errorf("proxy #%d has empty name", i)
		}
		names[name]++
	}
	dups := 0
	for _, cnt := range names {
		if cnt > 1 {
			dups += cnt
		}
	}
	if dups > 0 {
		t.Logf("note: %d proxies share duplicate names (inherited from source)", dups)
	}

	// Каждый прокси должен иметь обязательные поля
	for i, p := range doc.Proxies {
		if yamlStr(p, "type") == "" {
			t.Errorf("proxy #%d missing type", i)
		}
		if yamlStr(p, "server") == "" {
			t.Errorf("proxy #%d missing server", i)
		}
		if _, ok := yamlGet(p, "port"); !ok {
			t.Errorf("proxy #%d missing port", i)
		}
	}

	t.Logf("converted %d supported links; skipped unsupported schemes: %v", len(supported), unsupported)
}

// TestFormatYAML_RealFile_NoLostParams проверяет, что значимые параметры каждой
// поддерживаемой ссылки не теряются при преобразовании в YAML.
func TestFormatYAML_RealFile_NoLostParams(t *testing.T) {
	content := loadTestSubscription(t)
	supported, _ := extractLinks(t, content)

	out, _, err := formatContent(content, "yaml")
	if err != nil {
		t.Fatalf("formatContent(yaml) returned error: %v", err)
	}

	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("generated YAML is invalid: %v", err)
	}
	if len(doc.Proxies) != len(supported) {
		t.Fatalf("proxy count mismatch: got %d, want %d", len(doc.Proxies), len(supported))
	}

	lost := 0
	for i, link := range supported {
		proxy := doc.Proxies[i]
		lost += checkLinkParamsPreserved(t, link, proxy)
	}

	if lost > 0 {
		t.Errorf("%d significant parameters were lost during YAML conversion", lost)
	}
}

// checkLinkParamsPreserved сверяет значимые параметры исходной ссылки с YAML-блоком.
// Возвращает число потерянных параметров.
func checkLinkParamsPreserved(t *testing.T, link string, proxy map[string]any) int {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Errorf("failed to parse link %q: %v", link, err)
		return 0
	}
	scheme := strings.ToLower(u.Scheme)
	params := u.Query()
	lost := 0

	lose := func(param, yamlField string) {
		lost++
		t.Errorf("[%s] parameter %q not preserved (expected field %q) in link %s", scheme, param, yamlField, link)
	}

	switch scheme {
	case "vless":
		checkTransportPreserved(t, params, proxy, lose)
		// sni значим только при активном TLS/REALITY; при security=none он
		// не используется, а такие ссылки к тому же отклоняются rules.yaml
		sec := params.Get("security")
		if v := params.Get("sni"); v != "" && (sec == "tls" || sec == "reality") && yamlStr(proxy, "servername") == "" {
			lose("sni", "servername")
		}
		if params.Get("security") == "reality" {
			if v := params.Get("pbk"); v != "" && yamlStr(proxy, "reality-opts", "public-key") == "" {
				lose("pbk", "reality-opts.public-key")
			}
			if v := params.Get("sid"); v != "" && yamlStr(proxy, "reality-opts", "short-id") == "" {
				lose("sid", "reality-opts.short-id")
			}
			if v := params.Get("fp"); v != "" && yamlStr(proxy, "client-fingerprint") == "" {
				lose("fp", "client-fingerprint")
			}
		}
		if v := params.Get("flow"); v != "" && yamlStr(proxy, "flow") == "" {
			lose("flow", "flow")
		}
		if v := params.Get("alpn"); v != "" {
			if _, ok := yamlGet(proxy, "alpn"); !ok {
				lose("alpn", "alpn")
			}
		}

	case "trojan":
		checkTransportPreserved(t, params, proxy, lose)
		if v := params.Get("sni"); v != "" && yamlStr(proxy, "sni") == "" {
			lose("sni", "sni")
		}
		if isInsecureFlag(params) {
			if v, _ := yamlGet(proxy, "skip-cert-verify"); v != true {
				lose("insecure/allowInsecure", "skip-cert-verify")
			}
		}
		if v := params.Get("alpn"); v != "" {
			if _, ok := yamlGet(proxy, "alpn"); !ok {
				lose("alpn", "alpn")
			}
		}

	case "hy2", "hysteria2":
		if v := params.Get("sni"); v != "" && yamlStr(proxy, "sni") == "" {
			lose("sni", "sni")
		}
		if v := params.Get("obfs"); v == "salamander" && yamlStr(proxy, "obfs") == "" {
			lose("obfs", "obfs")
		}
		// Пароль: из userinfo либо из obfs-password
		if u.User.Username() == "" {
			if v := params.Get("obfs-password"); v != "" && yamlStr(proxy, "password") == "" {
				lose("obfs-password", "password")
			}
		}
		if isInsecureFlag(params) {
			if v, _ := yamlGet(proxy, "skip-cert-verify"); v != true {
				lose("insecure/allowInsecure", "skip-cert-verify")
			}
		}
		if v := params.Get("upmbps"); v != "" && yamlStr(proxy, "up") == "" {
			lose("upmbps", "up")
		}
		if v := params.Get("downmbps"); v != "" && yamlStr(proxy, "down") == "" {
			lose("downmbps", "down")
		}

	case "ss":
		// cipher и password извлекаются из base64 userinfo
		if userinfo := u.User.String(); userinfo != "" {
			if decoded, err := base64Decode(userinfo); err == nil {
				if parts := strings.SplitN(string(decoded), ":", 2); len(parts) == 2 {
					if yamlStr(proxy, "cipher") == "" {
						lose("userinfo.cipher", "cipher")
					}
					if yamlStr(proxy, "password") == "" {
						lose("userinfo.password", "password")
					}
				}
			}
		}

	case "vmess":
		payload := strings.TrimPrefix(link, "vmess://")
		// отсекаем фрагмент (#имя) — он не является частью payload
		if idx := strings.IndexByte(payload, '#'); idx != -1 {
			payload = payload[:idx]
		}
		decoded, err := base64Decode(payload)
		if err != nil {
			lose("payload", "(decodable base64)")
			return lost
		}
		var vm map[string]any
		if err := json.Unmarshal(decoded, &vm); err != nil {
			lose("payload", "(valid JSON)")
			return lost
		}
		if v, _ := vm["id"].(string); v != "" && yamlStr(proxy, "uuid") == "" {
			lose("id", "uuid")
		}
		if v, _ := vm["scy"].(string); v != "" && yamlStr(proxy, "cipher") == "" {
			lose("scy", "cipher")
		}
		if v, _ := vm["net"].(string); v != "" && yamlStr(proxy, "network") == "" {
			lose("net", "network")
		}
		// sni значим только при активном TLS
		if v, _ := vm["sni"].(string); v != "" {
			if tlsVal, _ := vm["tls"].(string); tlsVal == "tls" && yamlStr(proxy, "servername") == "" {
				lose("sni", "servername")
			}
		}
	}

	return lost
}

// checkTransportPreserved проверяет перенос параметров транспорта (ws/grpc/xhttp).
func checkTransportPreserved(t *testing.T, params url.Values, proxy map[string]any, lose func(string, string)) {
	t.Helper()
	network := params.Get("type")
	if network == "" {
		network = params.Get("network")
	}
	if network != "" && yamlStr(proxy, "network") == "" {
		lose("type", "network")
	}
	switch network {
	case "ws", "httpupgrade":
		if v := params.Get("path"); v != "" && yamlStr(proxy, "ws-opts", "path") == "" {
			lose("path", "ws-opts.path")
		}
		if v := params.Get("host"); v != "" && yamlStr(proxy, "ws-opts", "headers", "Host") == "" {
			lose("host", "ws-opts.headers.Host")
		}
	case "grpc":
		if v := params.Get("serviceName"); v != "" && yamlStr(proxy, "grpc-opts", "grpc-service-name") == "" {
			lose("serviceName", "grpc-opts.grpc-service-name")
		}
	case "xhttp":
		if v := params.Get("path"); v != "" && yamlStr(proxy, "xhttp-opts", "path") == "" {
			lose("path", "xhttp-opts.path")
		}
	}
}

// base64Decode декодирует userinfo/payload с автоопределением кодировки.
func base64Decode(s string) ([]byte, error) {
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
	default:
		enc = base64.RawStdEncoding
	}
	return enc.DecodeString(s)
}

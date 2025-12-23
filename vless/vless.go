// Package vless обрабатывает VLESS-ссылки (vless://).
package vless

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"sub-filter/internal/utils"

	"sub-filter/internal/validator"
)

// VLESSLink обрабатывает VLESS-ссылки (vless://).
//
//nolint:revive
type VLESSLink struct {
	badWords       []string
	isValidHost    func(string) bool
	isValidPort    func(int) bool
	checkBadWords  func(string) (bool, string)
	ruleValidator  validator.Validator
	hostRegex      *regexp.Regexp
	base64UrlRegex *regexp.Regexp
}

// NewVLESSLink создаёт новый обработчик VLESS.
// Принимает валидатор политик — если nil, используется пустой GenericValidator.
func NewVLESSLink(
	bw []string,
	vh func(string) bool,
	vp func(int) bool,
	cb func(string) (bool, string),
	val validator.Validator,
) *VLESSLink {
	if val == nil {
		val = &validator.GenericValidator{}
	}
	return &VLESSLink{
		badWords:       bw,
		isValidHost:    vh,
		isValidPort:    vp,
		checkBadWords:  cb,
		ruleValidator:  val,
		hostRegex:      regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`),
		base64UrlRegex: regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`),
	}
}

// Matches проверяет, является ли строка VLESS-ссылкой.
func (v *VLESSLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vless://")
}

// Process парсит, валидирует и нормализует VLESS-ссылку.
func (v *VLESSLink) Process(s string) (string, string) {
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
	host, port, hostErr := v.validateVLESSHostPort(u)
	if hostErr != "" {
		return "", "VLESS: " + hostErr
	}
	if hasBad, reason := v.checkBadWords(u.Fragment); hasBad {
		return "", reason
	}

	q := u.Query()
	q.Del("insecure")
	q.Del("allowInsecure")

	// Параметр 'encryption' больше не обязателен — проверка делегируется политике.

	// Собираем параметры для валидатора
	params := utils.ParamsFromValues(q)
	params = utils.NormalizeParams(params)

	// Если параметр 'security' отсутствует, устанавливаем значение по умолчанию 'none'.
	// Это упрощает обработку политик, которые ожидают явно заданное значение.
	if _, exists := params["security"]; !exists {
		params["security"] = "none"
	}

	// Валидация теперь полностью делегирована политике
	if result := v.ruleValidator.Validate(params); !result.Valid {
		return "", "VLESS: " + result.Reason
	}

	// Обработка ALPN (остаётся как часть форматирования, а не валидации)
	if alpnValues := q["alpn"]; len(alpnValues) > 0 {
		norm := utils.NormalizeALPN(alpnValues[0])
		if norm != "" {
			q["alpn"] = []string{norm}
		} else {
			delete(q, "alpn")
		}
	}

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

// validateVLESSHostPort извлекает и проверяет хост и порт.
func (v *VLESSLink) validateVLESSHostPort(u *url.URL) (string, int, string) {
	host, port, err := utils.ParseHostPort(u)
	if err != nil {
		return "", 0, err.Error()
	}
	if !v.isValidPort(port) {
		return "", 0, "port out of range"
	}
	if !v.isValidHost(host) {
		return "", 0, "invalid host"
	}
	return host, port, ""
}

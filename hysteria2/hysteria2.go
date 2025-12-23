// Package hysteria2 обрабатывает ссылки формата hysteria2:// и hy2://
// и предоставляет парсер/нормализатор для Hysteria2 конфигураций.
package hysteria2

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// Hysteria2Link обрабатывает Hysteria2-URI (hysteria2://, hy2://).
//
//nolint:revive
type Hysteria2Link struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ruleValidator validator.Validator
}

// NewHysteria2Link создаёт новый обработчик Hysteria2.
func NewHysteria2Link(
	bw []string,
	vh func(string) bool,
	cb func(string) (bool, string),
	val validator.Validator,
) *Hysteria2Link {
	if val == nil {
		val = &validator.GenericValidator{}
	}
	return &Hysteria2Link{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
		ruleValidator: val,
	}
}

// Matches сообщает, соответствует ли строка формату Hysteria2 (hysteria2:// или hy2://).
func (h *Hysteria2Link) Matches(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://")
}

// Process парсит и нормализует Hysteria2 URI, возвращая нормализованную
// строку или причину отклонения.
func (h *Hysteria2Link) Process(s string) (string, string) {
	const maxURILength = 4096
	if len(s) > maxURILength {
		return "", "line too long"
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "invalid Hysteria2 URL format"
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return "", "invalid Hysteria2 scheme (expected 'hysteria2' or 'hy2')"
	}
	userinfo := u.User.String()
	if userinfo == "" {
		return "", "missing auth info (UUID or username) in Hysteria2"
	}
	host, port, ok := h.parseHostPort(u)
	if !ok {
		return "", "invalid host or port in Hysteria2"
	}
	if hasBad, reason := h.checkBadWords(u.Fragment); hasBad {
		return "", reason
	}

	q := u.Query()
	params := utils.ParamsFromValues(q)
	params = utils.NormalizeParams(params)

	if result := h.ruleValidator.Validate(params); !result.Valid {
		return "", "Hysteria2: " + result.Reason
	}

	var buf strings.Builder
	buf.WriteString(u.Scheme)
	buf.WriteString("://")
	buf.WriteString(userinfo)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
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

func (h *Hysteria2Link) parseHostPort(u *url.URL) (string, int, bool) {
	host, port, err := utils.ParseHostPort(u)
	if err != nil {
		return "", 0, false
	}
	if !h.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

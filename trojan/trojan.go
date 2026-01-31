// Package trojan содержит парсер и нормализатор для trojan:// ссылок.
package trojan

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// TrojanLink обрабатывает Trojan-URI (trojan://).
//
//nolint:revive
type TrojanLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (string, bool, string)
	ruleValidator validator.Validator
}

// NewTrojanLink создаёт новый обработчик Trojan.
func NewTrojanLink(
	bw []string,
	vh func(string) bool,
	cb func(string) (string, bool, string),
	val validator.Validator,
) *TrojanLink {
	if val == nil {
		val = &validator.GenericValidator{}
	}
	return &TrojanLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
		ruleValidator: val,
	}
}

// Matches сообщает, что строка соответствует формату Trojan URI (trojan://).
func (t *TrojanLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "trojan://")
}

// Process парсит и нормализует Trojan URI, возвращая нормализованную
// строку или причину отклонения.
func (t *TrojanLink) Process(s string) (string, string) {
	const maxURILength = 4096
	if len(s) > maxURILength {
		return "", "line too long"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "trojan" {
		return "", "invalid Trojan URL format"
	}
	password := u.User.Username()
	if password == "" {
		return "", "missing password"
	}
	host, port, ok := t.parseHostPort(u)
	if !ok {
		return "", "invalid host or port"
	}
	if newFrag, hasBad, reason := t.checkBadWords(u.Fragment); hasBad {
		return "", reason
	} else {
		u.Fragment = newFrag
	}

	q := u.Query()
	params := utils.ParamsFromValues(q)
	params = utils.NormalizeParams(params)

	if result := t.ruleValidator.Validate(params); !result.Valid {
		return "", "Trojan: " + result.Reason
	}

	var buf strings.Builder
	buf.WriteString("trojan://")
	buf.WriteString(password)
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

func (t *TrojanLink) parseHostPort(u *url.URL) (string, int, bool) {
	host, port, err := utils.ParseHostPort(u)
	if err != nil {
		return "", 0, false
	}
	if !t.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

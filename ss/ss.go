// Package ss обрабатывает Shadowsocks URI (ss://).
package ss

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// SSLink обрабатывает Shadowsocks-URI (ss://).
//
//nolint:revive
type SSLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (string, bool, string)
	ssCipherRe    *regexp.Regexp
	ruleValidator validator.Validator
}

// NewSSLink создаёт новый обработчик Shadowsocks.
func NewSSLink(
	bw []string,
	vh func(string) bool,
	cb func(string) (string, bool, string),
	val validator.Validator,
) *SSLink {
	if val == nil {
		val = &validator.EmptyValidator{}
	}
	return &SSLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
		ssCipherRe:    regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`),
		ruleValidator: val,
	}
}

// Matches возвращает true для строк, начинающихся с "ss://".
// Matches сообщает, является ли строка Shadowsocks-ссылкой.
func (s *SSLink) Matches(sLink string) bool {
	return strings.HasPrefix(strings.ToLower(sLink), "ss://")
}

// Process парсит и нормализует Shadowsocks URI, возвращая нормализованную
// ссылку или причину отклонения.
func (s *SSLink) Process(sLink string) (string, string) {
	const maxURILength = 4096
	const maxUserinfoLength = 1024
	const maxSSPasswordBytes = 256 // maxSSPasswordBytes ограничивает длину пароля в байтах
	if len(sLink) > maxURILength {
		return "", "line too long"
	}
	u, err := url.Parse(sLink)
	if err != nil || u.Scheme != "ss" {
		return "", "invalid Shadowsocks URL format"
	}
	userinfo := u.User.String()
	if userinfo == "" || len(userinfo) > maxUserinfoLength {
		return "", "missing or too long userinfo"
	}
	decoded, err := utils.DecodeUserInfo(userinfo)
	if err != nil {
		return "", "invalid Shadowsocks base64 encoding"
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "invalid cipher:password format"
	}
	cipher, password := parts[0], parts[1]
	if cipher == "" || password == "" || len(password) > maxSSPasswordBytes || !s.ssCipherRe.MatchString(cipher) {
		return "", "invalid cipher or password"
	}
	host, port, ok := s.parseHostPort(u)
	if !ok {
		return "", "invalid host or port"
	}
	if newFrag, hasBad, reason := s.checkBadWords(u.Fragment); hasBad {
		return "", reason
	} else {
		u.Fragment = newFrag
	}

	// SS не имеет query-параметров → валидатор получает пустой map
	if result := s.ruleValidator.Validate(map[string]string{}); !result.Valid {
		return "", "SS: " + result.Reason
	}

	newUser := utils.EncodeRawURBase64([]byte(cipher + ":" + password))
	var buf strings.Builder
	buf.WriteString("ss://")
	buf.WriteString(newUser)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String(), ""
}

func (s *SSLink) parseHostPort(u *url.URL) (string, int, bool) {
	host, port, err := utils.ParseHostPort(u)
	if err != nil {
		return "", 0, false
	}
	if !s.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

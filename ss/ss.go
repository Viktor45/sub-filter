package ss

import (
	"encoding/base64"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
)

type SSLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ssCipherRe    *regexp.Regexp
}

func NewSSLink(bw []string, vh func(string) bool, cb func(string) (bool, string)) *SSLink {
	return &SSLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
		ssCipherRe:    regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`),
	}
}

func (s *SSLink) Matches(sLink string) bool {
	return strings.HasPrefix(strings.ToLower(sLink), "ss://")
}

func (s *SSLink) Process(sLink string) (string, string) {
	const maxURILength = 4096
	const maxUserinfoLength = 1024
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
	if cipher == "" || password == "" || !s.ssCipherRe.MatchString(cipher) {
		return "", "invalid cipher or password"
	}
	host, port, ok := s.parseHostPort(u)
	if !ok {
		return "", "invalid host or port"
	}
	if hasBad, reason := s.checkBadWords(u.Fragment); hasBad {
		return "", reason
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
	return buf.String(), ""
}

func (s *SSLink) parseHostPort(u *url.URL) (string, int, bool) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || !s.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

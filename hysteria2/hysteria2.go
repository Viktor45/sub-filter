package hysteria2

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"sub-filter/internal/validator"
)

type Hysteria2Link struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ruleValidator validator.Validator
}

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

func (h *Hysteria2Link) Matches(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://")
}

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
	params := make(map[string]string, len(q))
	for k, vs := range q {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}

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
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || !h.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

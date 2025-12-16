package trojan

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"sub-filter/internal/validator"
)

type TrojanLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ruleValidator validator.Validator
}

func NewTrojanLink(
	bw []string,
	vh func(string) bool,
	cb func(string) (bool, string),
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

func (t *TrojanLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "trojan://")
}

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
	if hasBad, reason := t.checkBadWords(u.Fragment); hasBad {
		return "", reason
	}

	q := u.Query()
	params := make(map[string]string, len(q))
	for k, vs := range q {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}

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
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || !t.isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}

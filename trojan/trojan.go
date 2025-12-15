package trojan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type TrojanLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
}

func NewTrojanLink(bw []string, vh func(string) bool, cb func(string) (bool, string)) *TrojanLink {
	return &TrojanLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
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
	if reason := t.isSafeTrojanConfig(u.Query()); reason != "" {
		return "", fmt.Sprintf("Trojan: %s", reason)
	}
	var buf strings.Builder
	buf.WriteString("trojan://")
	buf.WriteString(password)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	q := u.Query()
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

func (t *TrojanLink) isSafeTrojanConfig(q url.Values) string {
	if q.Get("type") == "grpc" && q.Get("serviceName") == "" {
		return "gRPC requires serviceName"
	}
	return ""
}

package hysteria2

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Hysteria2Link struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
}

func NewHysteria2Link(bw []string, vh func(string) bool, cb func(string) (bool, string)) *Hysteria2Link {
	return &Hysteria2Link{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
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
	obfs := q.Get("obfs")
	if obfs == "" {
		return "", "Hysteria2: obfs parameter is missing (required for public subscriptions)"
	}
	if obfs != "salamander" {
		return "", fmt.Sprintf("Hysteria2: unsupported obfs method %q (only 'salamander' allowed)", obfs)
	}
	obfsPassword := q.Get("obfs-password")
	if obfsPassword == "" {
		return "", "Hysteria2: obfs-password is missing (required when obfs is used)"
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

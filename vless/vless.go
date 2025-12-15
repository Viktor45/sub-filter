package vless

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type VLESSLink struct {
	badWords       []string
	isValidHost    func(string) bool
	isValidPort    func(int) bool
	checkBadWords  func(string) (bool, string)
	hostRegex      *regexp.Regexp
	base64UrlRegex *regexp.Regexp
}

func NewVLESSLink(
	bw []string,
	vh func(string) bool,
	vp func(int) bool,
	cb func(string) (bool, string),
) *VLESSLink {
	return &VLESSLink{
		badWords:       bw,
		isValidHost:    vh,
		isValidPort:    vp,
		checkBadWords:  cb,
		hostRegex:      regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`),
		base64UrlRegex: regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`),
	}
}

func (v *VLESSLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vless://")
}

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

	if encryptionRaw := q.Get("encryption"); encryptionRaw != "" {
		encryptionDecoded, err := url.QueryUnescape(encryptionRaw)
		if err != nil {
			encryptionDecoded = encryptionRaw
		}
		normalized := strings.ToLower(strings.TrimRight(encryptionDecoded, " ="))
		if strings.HasPrefix(normalized, "none") {
			q.Set("encryption", "none")
		}
	} else {
		return "", "VLESS: encryption parameter is missing (outdated format)"
	}

	if err := v.validateVLESSParams(q); err != "" {
		return "", "VLESS: " + err
	}

	if alpnValues := q["alpn"]; len(alpnValues) > 0 {
		rawAlpn := alpnValues[0]
		var firstValid string
		if strings.HasPrefix(rawAlpn, "h3") {
			firstValid = "h3"
		} else if strings.HasPrefix(rawAlpn, "h2") {
			firstValid = "h2"
		} else if strings.HasPrefix(rawAlpn, "http/1.1") {
			firstValid = "http/1.1"
		} else {
			if idx := strings.IndexByte(rawAlpn, ','); idx != -1 {
				firstValid = rawAlpn[:idx]
			} else {
				firstValid = rawAlpn
			}
		}
		if firstValid != "" {
			q["alpn"] = []string{firstValid}
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

func (v *VLESSLink) validateVLESSHostPort(u *url.URL) (string, int, string) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, "missing port"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, "invalid port"
	}
	if !v.isValidPort(port) {
		return "", 0, "port out of range"
	}
	if !v.isValidHost(host) {
		return "", 0, "invalid host"
	}
	return host, port, ""
}

func (v *VLESSLink) isSafeVLESSConfig(q url.Values) string {
	flow := q.Get("flow")
	if flow != "" && q.Get("security") != "reality" {
		return "flow requires reality"
	}
	if q.Get("type") == "grpc" && q.Get("serviceName") == "" {
		return "gRPC requires serviceName"
	}
	return ""
}

func (v *VLESSLink) validateVLESSParams(q url.Values) string {
	security := q.Get("security")
	if security == "" {
		return "security parameter is missing (insecure)"
	}
	if security == "none" {
		return "security=none is not allowed"
	}
	if (security == "tls" || security == "reality") && q.Get("sni") == "" {
		return "sni is required for security=tls or reality"
	}
	if security == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			return "missing pbk (public key) for reality"
		}
		if !v.base64UrlRegex.MatchString(pbk) {
			return "invalid pbk format (must be 43-char base64url)"
		}
		if q.Get("type") == "xhttp" {
			mode := q.Get("mode")
			if mode != "" && mode != "packet" {
				return "invalid mode for xhttp (must be empty or 'packet')"
			}
		}
	}
	transportType := q.Get("type")
	headerType := q.Get("headerType")
	if headerType != "" && headerType != "none" && transportType != "kcp" && transportType != "quic" {
		return fmt.Sprintf("headerType is only allowed with kcp or quic (got type=%s, headerType=%s)", transportType, headerType)
	}
	if (transportType == "ws" || transportType == "httpupgrade" || transportType == "xhttp") && q.Get("path") == "" {
		return fmt.Sprintf("path is required when type=%s", transportType)
	}
	if reason := v.isSafeVLESSConfig(q); reason != "" {
		return reason
	}
	return ""
}

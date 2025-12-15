package vmess

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
)

type VMessLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
}

func NewVMessLink(bw []string, vh func(string) bool, cb func(string) (bool, string)) *VMessLink {
	return &VMessLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
	}
}

func (v *VMessLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vmess://")
}

func (v *VMessLink) Process(s string) (string, string) {
	const maxURILength = 4096
	if len(s) > maxURILength {
		return "", "line too long"
	}
	if !strings.HasPrefix(strings.ToLower(s), "vmess://") {
		return "", "not a VMess link"
	}
	b64 := strings.TrimPrefix(s, "vmess://")
	if b64 == "" {
		return "", "empty VMess payload"
	}
	decoded, err := utils.DecodeUserInfo(b64)
	if err != nil {
		return "", "invalid VMess base64 encoding"
	}
	var vm map[string]interface{}
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return "", "invalid VMess JSON format"
	}
	ps, _ := vm["ps"].(string)
	add, _ := vm["add"].(string)
	var port float64
	switch v := vm["port"].(type) {
	case float64:
		port = v
	case string:
		if p, err := strconv.ParseFloat(v, 64); err == nil {
			port = p
		} else {
			return "", "invalid port in VMess config"
		}
	default:
		return "", "missing or invalid port in VMess config"
	}
	id, _ := vm["id"].(string)
	if add == "" || id == "" {
		return "", "missing server address or UUID"
	}
	if int(port) <= 0 || int(port) > 65535 {
		return "", "invalid port number"
	}
	if !v.isValidHost(add) {
		return "", "invalid server host"
	}
	if ps != "" {
		if hasBad, reason := v.checkBadWords(ps); hasBad {
			return "", reason
		}
	}
	netType, _ := vm["net"].(string)
	if netType == "grpc" {
		svc, _ := vm["serviceName"].(string)
		if svc == "" {
			return "", "VMess gRPC requires serviceName"
		}
	}
	tls, _ := vm["tls"].(string)
	if netType != "grpc" && tls != "tls" {
		return "", "VMess without TLS is not allowed"
	}
	reencoded, err := json.Marshal(vm)
	if err != nil {
		return "", "failed to re-encode VMess config"
	}
	finalB64 := base64.StdEncoding.EncodeToString(reencoded)
	return "vmess://" + finalB64, ""
}

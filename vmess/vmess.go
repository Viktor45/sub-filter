// Package vmess обрабатывает VMess-ссылки (vmess://).
// Поддерживает только base64-encoded JSON payload.
package vmess

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// VMessLink реализует обработку VMess-ссылок.
type VMessLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ruleValidator validator.Validator
}

// NewVMessLink создаёт новый обработчик VMess.
// Принимает валидатор политик — если nil, используется пустой GenericValidator.
func NewVMessLink(
	bw []string,
	vh func(string) bool,
	cb func(string) (bool, string),
	val validator.Validator,
) *VMessLink {
	if val == nil {
		val = &validator.GenericValidator{}
	}
	return &VMessLink{
		badWords:      bw,
		isValidHost:   vh,
		checkBadWords: cb,
		ruleValidator: val,
	}
}

// Matches проверяет, является ли строка VMess-ссылкой.
func (v *VMessLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vmess://")
}

// Process парсит, валидирует и нормализует VMess-ссылку.
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
	switch vPort := vm["port"].(type) {
	case float64:
		port = vPort
	case string:
		if p, err := strconv.ParseFloat(vPort, 64); err == nil {
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

	// Преобразуем всё в map[string]string, включая пустые строки
	params := make(map[string]string)
	for k, vi := range vm {
		if s, ok := vi.(string); ok {
			params[k] = s // ← даже если s == ""
		} else if f, ok := vi.(float64); ok {
			// port and similar numeric fields should be integer when possible
			if math.Trunc(f) == f {
				params[k] = strconv.Itoa(int(f))
			} else {
				params[k] = strconv.FormatFloat(f, 'f', -1, 64)
			}
		}
	}

	// Делегируем валидацию политике
	if result := v.ruleValidator.Validate(params); !result.Valid {
		return "", "VMess: " + result.Reason
	}

	reencoded, err := json.Marshal(vm)
	if err != nil {
		return "", "failed to re-encode VMess config"
	}
	finalB64 := base64.StdEncoding.EncodeToString(reencoded)
	return "vmess://" + finalB64, ""
}

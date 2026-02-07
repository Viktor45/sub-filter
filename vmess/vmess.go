// Package vmess обрабатывает VMess-ссылки (vmess://).
// Поддерживает только base64-encoded JSON payload.
package vmess

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

// VMessLink обрабатывает VMess-ссылки (vmess://).
//
//nolint:revive
type VMessLink struct {
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (string, bool, string)
	ruleValidator validator.Validator
}

// NewVMessLink создаёт новый обработчик VMess.
// Принимает валидатор политик — если nil, используется пустой GenericValidator.
func NewVMessLink(
	bw []string,
	vh func(string) bool,
	cb func(string) (string, bool, string),
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
	// Извлекаем поля и валидируем минимальные требования
	ps, _ := vm["ps"].(string)
	add, _ := vm["add"].(string)
	id, _ := vm["id"].(string)
	// Порт может быть float64 или строкой
	var portF float64
	switch p := vm["port"].(type) {
	case float64:
		portF = p
	case string:
		if pf, err := strconv.ParseFloat(p, 64); err == nil {
			portF = pf
		} else {
			return "", "invalid port in VMess config"
		}
	default:
		return "", "missing or invalid port in VMess config"
	}
	if add == "" || id == "" {
		return "", "missing server address or UUID"
	}
	port := int(portF)
	if port <= 0 || port > 65535 {
		return "", "invalid port number"
	}
	if !v.isValidHost(add) {
		return "", "invalid server host"
	}
	if ps != "" {
		if newPs, hasBad, reason := v.checkBadWords(ps); hasBad {
			return "", reason
		} else {
			vm["ps"] = newPs
		}
	}

	// Собираем параметры строкового представления для валидатора
	params := utils.ParamsFromInterface(vm)
	params = utils.NormalizeParams(params, "tls") // Параметр 'tls' может быть пустым, но мы не хотим его удалять — он важен для политик, которые проверяют его наличие или значение.

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

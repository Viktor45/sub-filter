// Package validator содержит реализации валидаторов параметров протоколов.
package validator

import (
	"fmt"
	"strings"
)

// GenericValidator реализует базовую логику проверки параметров в соответствии с Rule.
// Он поддерживает required/allowed/forbidden параметров и условные правила.
type GenericValidator struct {
	Rule Rule
}

// Validate выполняет проверку переданных параметров по правилам, описанным в gv.Rule.
// Возвращает ValidationResult с полем Valid=true, если все проверки пройдены.
func (gv *GenericValidator) Validate(params map[string]string) ValidationResult {
	// Кэшируем lower-case версию параметров, чтобы избежать многократных вызовов ToLower
	lowerParams := make(map[string]string, len(params))
	for k, v := range params {
		lowerParams[k] = strings.ToLower(v)
	}
	// 1. Обязательные параметры (без изменений)
	for _, param := range gv.Rule.RequiredParams {
		if _, exists := params[param]; !exists {
			return ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("missing required parameter: %s", param),
			}
		}
	}

	// 2. Запрещённые значения — регистронезависимые
	for param, forbidden := range gv.Rule.ForbiddenValues {
		if value, exists := lowerParams[param]; exists {
			for _, f := range forbidden {
				if value == strings.ToLower(f) {
					return ValidationResult{
						Valid:  false,
						Reason: fmt.Sprintf("forbidden value for %s: %q", param, params[param]),
					}
				}
			}
		}
	}

	// 3. Разрешённые значения — регистронезависимые
	for param, allowed := range gv.Rule.AllowedValues {
		if value, exists := lowerParams[param]; exists {
			found := false
			for _, a := range allowed {
				if value == strings.ToLower(a) {
					found = true
					break
				}
			}
			if !found {
				return ValidationResult{
					Valid:  false,
					Reason: fmt.Sprintf("invalid value for %s: %q (allowed: %v)", param, params[param], allowed),
				}
			}
		}
	}

	// 4. Условные правила — ОСТАВЛЯЕМ чувствительными к регистру (т.к. это логические условия, а не пользовательский ввод)
	for _, cond := range gv.Rule.Conditional {
		match := true
		for k, v := range cond.When {
			if value, exists := params[k]; !exists || value != v {
				match = false
				break
			}
		}
		if match {
			for _, req := range cond.Require {
				if _, exists := params[req]; !exists {
					return ValidationResult{
						Valid:  false,
						Reason: fmt.Sprintf("missing required parameter %s when %v", req, cond.When),
					}
				}
			}
		}
	}

	return ValidationResult{Valid: true}
}

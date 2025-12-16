package validator

import "fmt"

type GenericValidator struct {
	Rule Rule
}

func (gv *GenericValidator) Validate(params map[string]string) ValidationResult {
	// 1. Обязательные параметры: проверяем существование ключа
	for _, param := range gv.Rule.RequiredParams {
		if _, exists := params[param]; !exists {
			return ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("missing required parameter: %s", param),
			}
		}
	}

	// 2. Разрешённые значения
	for param, allowed := range gv.Rule.AllowedValues {
		if value, exists := params[param]; exists {
			if !contains(allowed, value) {
				return ValidationResult{
					Valid:  false,
					Reason: fmt.Sprintf("invalid value for %s: %q (allowed: %v)", param, value, allowed),
				}
			}
		}
	}

	// 3. Запрещённые значения
	for param, forbidden := range gv.Rule.ForbiddenValues {
		if value, exists := params[param]; exists {
			if contains(forbidden, value) {
				return ValidationResult{
					Valid:  false,
					Reason: fmt.Sprintf("forbidden value for %s: %q", param, value),
				}
			}
		}
	}

	// 4. Условные правила
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

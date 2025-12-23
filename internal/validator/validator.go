package validator

// ValidationResult представляет результат валидации: флаг успешности
// и необязательная причина отказа.
type ValidationResult struct {
	Valid  bool
	Reason string
}

// Validator представляет политику валидации параметров протокола.
// Реализации должны возвращать ValidationResult{Valid:true}, когда
// параметры соответствуют требованиям политики, иначе задавать поле Reason.
type Validator interface {
	Validate(params map[string]string) ValidationResult
}

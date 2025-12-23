package validator

// EmptyValidator всегда возвращает успешный результат валидации.
// Используется как заглушка, когда правила отсутствуют.
type EmptyValidator struct{}

// Validate реализует интерфейс Validator и всегда возвращает Valid=true.
func (ev *EmptyValidator) Validate(_ map[string]string) ValidationResult {
	return ValidationResult{Valid: true}
}

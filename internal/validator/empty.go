package validator

type EmptyValidator struct{}

func (ev *EmptyValidator) Validate(_ map[string]string) ValidationResult {
	return ValidationResult{Valid: true}
}

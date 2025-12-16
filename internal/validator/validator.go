package validator

type ValidationResult struct {
	Valid  bool
	Reason string
}

type Validator interface {
	Validate(params map[string]string) ValidationResult
}

// internal/validator/types.go
package validator

type Rule struct {
	RequiredParams  []string            `mapstructure:"required_params"`
	AllowedValues   map[string][]string `mapstructure:"allowed_values"`
	ForbiddenValues map[string][]string `mapstructure:"forbidden_values"`
	Conditional     []Condition         `mapstructure:"conditional"`
}

type Condition struct {
	When    map[string]string `mapstructure:"when"`
	Require []string          `mapstructure:"require"`
}

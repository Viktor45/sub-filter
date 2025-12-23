// Package validator содержит типы и реализации валидации параметров
// проколов используемых в правилах (rules.yaml).
package validator

// Rule описывает ограничивающие правила для параметров протокола.
type Rule struct {
	RequiredParams  []string            `mapstructure:"required_params"`
	AllowedValues   map[string][]string `mapstructure:"allowed_values"`
	ForbiddenValues map[string][]string `mapstructure:"forbidden_values"`
	Conditional     []Condition         `mapstructure:"conditional"`
}

// Condition представляет условную зависимость: когда 'When' выполняется,
// то набор полей 'Require' становится обязательным.
type Condition struct {
	When    map[string]string `mapstructure:"when"`
	Require []string          `mapstructure:"require"`
}

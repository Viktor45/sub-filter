// Package validator содержит утилиты для загрузки и применения политик валидации.
package validator

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/viper"
)

// LoadRules загружает правила из YAML/JSON/TOML файла.
// Поддерживает только формат YAML для политик.
func LoadRules(path string) (map[string]Validator, error) {
	if path == "" {
		return make(map[string]Validator), nil
	}

	viper.Reset() // важно: сбросить предыдущую конфигурацию
	viper.SetConfigFile(path)
	ext := filepath.Ext(path)
	if ext == ".yaml" || ext == ".yml" {
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}

	var raw map[string]Rule
	if err := viper.Unmarshal(&raw); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	result := make(map[string]Validator, len(raw))
	for proto, rule := range raw {
		result[proto] = &GenericValidator{Rule: rule}
	}
	return result, nil
}

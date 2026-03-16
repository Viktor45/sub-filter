// pkg/errors/errors.go
// Пакет errors содержит типизированную систему обработки ошибок с поддержкой контекста,
// уровней серьёзности и цепочек ошибок (error chaining).
package errors

import (
	"fmt"
	"time"
)

// ErrorCode представляет стандартизированные категории ошибок
type ErrorCode string

const (
	// Ошибки конфигурации
	ErrCodeConfig   ErrorCode = "config_error"
	ErrCodeValidate ErrorCode = "validation_error"

	// Сетевые ошибки
	ErrCodeNetwork ErrorCode = "network_error"
	ErrCodeHTTP    ErrorCode = "http_error"

	// Ошибки парсинга
	ErrCodeParse ErrorCode = "parse_error"

	// Ошибки ввода-вывода
	ErrCodeIO     ErrorCode = "io_error"
	ErrCodeFileOp ErrorCode = "file_operation_error"

	// Логические ошибки
	ErrCodeLogic ErrorCode = "logic_error"
)

// Severity указывает на уровень серьёзности ошибки
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// FilterError - основной тип ошибки, используемый во всём приложении
type FilterError struct {
	Code      ErrorCode              // Категория ошибки
	Category  string                 // Тип ошибки, например "Parse", "HTTP", "Cache"
	Message   string                 // Человекочитаемое сообщение об ошибке
	Err       error                  // Обёрнутая ошибка (может быть nil)
	Severity  Severity               // Уровень серьёзности ошибки
	Timestamp time.Time              // Время возникновения ошибки
	Context   map[string]interface{} // Дополнительный контекст (sourceID, URL и т.д.)
}

// Error реализует интерфейс error
func (e *FilterError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s:%s] %s: %v", e.Code, e.Category, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Code, e.Category, e.Message)
}

// Unwrap позволяет проверить цепочку ошибок через errors.Is/As
func (e *FilterError) Unwrap() error {
	return e.Err
}

// NewFilterError создаёт новую FilterError со стандартными значениями
func NewFilterError(code ErrorCode, category, message string) *FilterError {
	return &FilterError{
		Code:      code,
		Category:  category,
		Message:   message,
		Severity:  SeverityError,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}
}

// WithCause оборачивает существующую ошибку
func (e *FilterError) WithCause(err error) *FilterError {
	e.Err = err
	return e
}

// WithContext добавляет контекстную информацию
func (e *FilterError) WithContext(key string, value interface{}) *FilterError {
	e.Context[key] = value
	return e
}

// WithSeverity устанавливает уровень серьёзности ошибки
func (e *FilterError) WithSeverity(s Severity) *FilterError {
	e.Severity = s
	return e
}

// IsRecoverable указывает, может ли быть восстановлена ошибка
func (e *FilterError) IsRecoverable() bool {
	switch e.Code {
	case ErrCodeNetwork, ErrCodeHTTP, ErrCodeIO:
		return true // Можна повторить
	case ErrCodeConfig, ErrCodeValidate:
		return false // Не может быть восстановлена
	default:
		return e.Severity != SeverityCritical
	}
}

// Вспомогательные функции для распространённых ошибок

// ParseError создаёт ошибку для сбоев парсинга
func ParseError(msg string, err error) *FilterError {
	return NewFilterError(ErrCodeParse, "Parse", msg).
		WithCause(err).
		WithSeverity(SeverityWarning)
}

// NetworkError создаёт ошибку для сетевых операций
func NetworkError(msg string, err error) *FilterError {
	return NewFilterError(ErrCodeNetwork, "Network", msg).
		WithCause(err).
		WithSeverity(SeverityWarning)
}

// ConfigError создаёт ошибку для проблем конфигурации
func ConfigError(msg string, err error) *FilterError {
	return NewFilterError(ErrCodeConfig, "Config", msg).
		WithCause(err).
		WithSeverity(SeverityError)
}

// ValidationError создаёт ошибку для сбоев валидации
func ValidationError(msg string) *FilterError {
	return NewFilterError(ErrCodeValidate, "Validate", msg).
		WithSeverity(SeverityInfo) // Сбои валидации ожидаемы и безвредны
}

// IOError создаёт ошибку для операций ввода-вывода
func IOError(msg string, err error) *FilterError {
	return NewFilterError(ErrCodeIO, "IO", msg).
		WithCause(err).
		WithSeverity(SeverityWarning)
}

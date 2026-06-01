// pkg/logger/logger.go
// Пакет logger предоставляет обёртку над slog с методами удобства
// и поддержкой JSON-форматирования логов.
package logger

import (
	"io"
	"log/slog"
	"os"
	"time"
)

// Logger обёртка над slog.Logger с методами удобства
type Logger struct {
	*slog.Logger
}

// New создаёт новый логгер с заданным обработчиком
func New(handler slog.Handler) *Logger {
	return &Logger{
		Logger: slog.New(handler),
	}
}

// NewDefault создаёт логгер с разумными стандартными параметрами
func NewDefault(level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewJSONHandler(os.Stderr, opts)
	return New(handler)
}

// NewTextLogger создаёт логгер с текстовым форматом (для разработки)
func NewTextLogger(w io.Writer, level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewTextHandler(w, opts)
	return New(handler)
}

// NewJSONLogger создаёт логгер с JSON-форматом и выводом в указанный io.Writer.
// Полезно для логирования в тестах или при желании перенаправить вывод.
func NewJSONLogger(w io.Writer, level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewJSONHandler(w, opts)
	return New(handler)
}

// ParseLevel распознаёт строку уровня логирования
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Методы удобства для часто используемых паттернов

// ErrorWithContext логирует ошибку с контекстной информацией
func (l *Logger) ErrorWithContext(msg string, err error, fields map[string]interface{}) {
	args := []interface{}{slog.Any("error", err)}
	for k, v := range fields {
		args = append(args, slog.Any(k, v))
	}
	l.Error(msg, args...)
}

// InfoWithContext логирует информацию с контекстной информацией
func (l *Logger) InfoWithContext(msg string, fields map[string]interface{}) {
	args := []interface{}{}
	for k, v := range fields {
		args = append(args, slog.Any(k, v))
	}
	l.Info(msg, args...)
}

// DebugWithContext логирует отладку с контекстной информацией
func (l *Logger) DebugWithContext(msg string, fields map[string]interface{}) {
	args := []interface{}{}
	for k, v := range fields {
		args = append(args, slog.Any(k, v))
	}
	l.Debug(msg, args...)
}

// Timed логирует длительность операции и любую ошибку
func (l *Logger) Timed(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)

	if err != nil {
		l.Error("operation failed",
			slog.String("operation", name),
			slog.Duration("duration", duration),
			slog.Any("error", err),
		)
		return err
	}

	l.Info("operation completed",
		slog.String("operation", name),
		slog.Duration("duration", duration),
	)
	return nil
}

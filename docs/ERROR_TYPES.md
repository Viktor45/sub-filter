# Типы ошибок

Проект использует типизированные ошибки для лучшей обработки и логирования.

## Структура ошибки

```go
type FilterError struct {
    Code     ErrorCode
    Severity Severity
    Message  string
    Context  map[string]interface{}
    Cause    error
}
```

## Коды ошибок

| Код                    | Описание                 |
| ---------------------- | ------------------------ |
| `config_error`         | Ошибки конфигурации      |
| `validation_error`     | Ошибки валидации данных  |
| `network_error`        | Сетевые ошибки           |
| `http_error`           | HTTP ошибки              |
| `parse_error`          | Ошибки парсинга          |
| `io_error`             | Ошибки ввода-вывода      |
| `file_operation_error` | Ошибки файловых операций |
| `logic_error`          | Логические ошибки        |

## Уровни серьезности

- `info`: Информационные сообщения
- `warning`: Предупреждения
- `error`: Ошибки
- `critical`: Критические ошибки

## Использование

```go
import "sub-filter/pkg/errors"

// Создание ошибки
err := errors.NewValidationError("invalid country code", "code", "XX")

// С контекстом
err = errors.ParseError("failed to parse YAML").WithContext("file", "config.yaml")

// Проверка типа
if filterErr, ok := err.(*errors.FilterError); ok {
    if filterErr.Code == errors.ErrCodeConfig {
        // Обработка ошибки конфигурации
    }
}
```
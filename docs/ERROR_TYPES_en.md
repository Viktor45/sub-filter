# Error Types

The project uses typed errors for better handling and logging.

## Error Structure

```go
type FilterError struct {
    Code     ErrorCode
    Severity Severity
    Message  string
    Context  map[string]interface{}
    Cause    error
}
```

## Error Codes

| Code                   | Description            |
|------------------------|------------------------|
| `config_error`         | Configuration errors   |
| `validation_error`     | Data validation errors |
| `network_error`        | Network errors         |
| `http_error`           | HTTP errors            |
| `parse_error`          | Parsing errors         |
| `io_error`             | I/O errors             |
| `file_operation_error` | File operation errors  |
| `logic_error`          | Logic errors           |

## Severity Levels

- `info`: Informational messages
- `warning`: Warnings
- `error`: Errors
- `critical`: Critical errors

## Usage

```go
import "sub-filter/pkg/errors"

// Create error
err := errors.NewValidationError("invalid country code", "code", "XX")

// With context
err = errors.ParseError("failed to parse YAML").WithContext("file", "config.yaml")

// Type check
if filterErr, ok := err.(*errors.FilterError); ok {
    if filterErr.Code == errors.ErrCodeConfig {
        // Handle config error
    }
}
```
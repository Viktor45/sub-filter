# 错误类型

项目使用类型化错误以更好地处理和记录。

## 错误结构

```go
type FilterError struct {
    Code     ErrorCode
    Severity Severity
    Message  string
    Context  map[string]interface{}
    Cause    error
}
```

## 错误代码

| 代码                     | 描述      |
|------------------------|---------|
| `config_error`         | 配置错误    |
| `validation_error`     | 数据验证错误  |
| `network_error`        | 网络错误    |
| `http_error`           | HTTP 错误 |
| `parse_error`          | 解析错误    |
| `io_error`             | I/O 错误  |
| `file_operation_error` | 文件操作错误  |
| `logic_error`          | 逻辑错误    |

## 使用方法

```go
import "sub-filter/pkg/errors"

// 创建错误
err := errors.NewValidationError("invalid country code", "code", "XX")
```
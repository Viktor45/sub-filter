# 错误类型

本项目采用类型化错误（Typed Errors）机制，以便于更好地进行错误处理与日志记录。

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

| 代码                     | 描述             |
|------------------------|----------------|
| `config_error`         | 配置错误           |
| `validation_error`     | 数据验证错误         |
| `network_error`        | 网络错误           |
| `http_error`           | HTTP 错误        |
| `parse_error`          | 解析错误           |
| `io_error`             | 输入/输出 (I/O) 错误 |
| `file_operation_error` | 文件操作错误         |
| `logic_error`          | 逻辑错误           |

## 严重级别

- `info`：信息性消息
- `warning`：警告
- `error`：常规错误
- `critical`：严重/致命错误

## 使用方法

```go
import "sub-filter/pkg/errors"

// 创建错误
err := errors.NewValidationError("invalid country code", "code", "XX")

// 附加上下文信息
err = errors.ParseError("failed to parse YAML").WithContext("file", "config.yaml")

// 类型断言与检查
if filterErr, ok := err.(*errors.FilterError); ok {
    if filterErr.Code == errors.ErrCodeConfig {
        // 处理配置错误
    }
}
```
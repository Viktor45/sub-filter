[EN](../DEVELOPMENT.md) / [RU](../ru/DEVELOPMENT.md) / [ZH](DEVELOPMENT.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [开发指南](#开发指南)
  * [项目结构](#项目结构)
  * [类型化错误（`pkg/errors`）](#类型化错误pkgerrors)
    * [错误结构](#错误结构)
    * [错误代码](#错误代码)
    * [严重级别](#严重级别)
    * [构造函数与辅助方法](#构造函数与辅助方法)
  * [添加新协议](#添加新协议)
    * [1. 实现 `ProxyLink`](#1-实现-proxylink)
    * [2. 注册处理器](#2-注册处理器)
    * [3. 添加校验规则](#3-添加校验规则)
    * [4. 添加 YAML 构建器](#4-添加-yaml-构建器)
    * [5. 编写测试](#5-编写测试)
  * [测试](#测试)
<!-- TOC -->

# 开发指南

扩展项目的说明。关于惯用的 Go 实践，请参阅
[`.github/instructions/go.instructions.md`](../../.github/instructions/go.instructions.md)。

## 项目结构

| 路径                                          | 用途                                                           |
|-----------------------------------------------|----------------------------------------------------------------|
| `main.go`                                     | 标志解析、配置加载、服务器/CLI 启动                            |
| `pkg/service`                                 | HTTP 处理器、过滤、merge、缓存、YAML 格式化                    |
| `pkg/config`                                  | 配置模式与加载（嵌套 YAML + 旧式扁平键）                       |
| `pkg/errors`                                  | 带代码与严重级别的类型化错误                                   |
| `pkg/logger`                                  | 基于 `slog` 的结构化日志封装                                   |
| `pkg/cache`                                   | 带命中/未命中统计的已编译 regex 缓存                           |
| `internal/validator`                          | 通用规则引擎（`required`/`allowed`/`forbidden`/`conditional`） |
| `internal/utils`                              | URL 规范化、主机/端口检查、国家查询、去重                      |
| `vless`、`vmess`、`trojan`、`ss`、`hysteria2` | 协议解析器/规范化器                                            |

## 类型化错误（`pkg/errors`）

应用使用统一的类型化错误，以实现一致的处理与日志记录。

### 错误结构

```go
type FilterError struct {
    Code      ErrorCode      // 错误类别
    Category  string         // 例如 "Parse"、"Network"、"Config"
    Message   string         // 人类可读的消息
    Err       error          // 被包装的原因（可能为 nil）
    Severity  Severity       // 严重级别
    Timestamp time.Time      // 创建时间
    Context   map[string]any // 附加上下文（sourceID、URL 等）
}
```

`FilterError` 实现了 `error` 和 `Unwrap()`，因此 `errors.Is`/`errors.As`
可以沿原因链工作。

### 错误代码

| 代码                   | 常量              | 说明                   |
| ---------------------- | ----------------- | ---------------------- |
| `config_error`         | `ErrCodeConfig`   | 配置错误               |
| `validation_error`     | `ErrCodeValidate` | 数据校验错误           |
| `network_error`        | `ErrCodeNetwork`  | 网络错误               |
| `http_error`           | `ErrCodeHTTP`     | HTTP 错误              |
| `parse_error`          | `ErrCodeParse`    | 解析错误               |
| `io_error`             | `ErrCodeIO`       | I/O 错误               |
| `file_operation_error` | `ErrCodeFileOp`   | 文件操作错误           |
| `logic_error`          | `ErrCodeLogic`    | 逻辑错误               |

### 严重级别

`info`、`warning`、`error`、`critical`
（常量 `SeverityInfo` … `SeverityCritical`）。

### 构造函数与辅助方法

```go
import "sub-filter/pkg/errors"

// 类型化构造函数
err := errors.ValidationError("invalid country code")
err = errors.ParseError("failed to parse YAML", cause)
err = errors.NetworkError("fetch failed", cause)
err = errors.ConfigError("bad config", cause)
err = errors.IOError("read failed", cause)

// 构建器方法
err = errors.ParseError("failed to parse", cause).
    WithContext("file", "config.yaml").
    WithSeverity(errors.SeverityWarning).
    WithCause(cause)

// 类型检查
var fe *errors.FilterError
if stderrors.As(err, &fe) {
    if fe.Code == errors.ErrCodeConfig {
        // 处理配置错误
    }
}

// 可恢复性提示（网络/IO 错误可重试）
if fe.IsRecoverable() { /* 重试 */ }
```

HTTP 处理器将错误代码映射为对客户端安全的响应
（`pkg/service` 中的 `writeProcessingError`）：校验错误 → `400`，
网络/解析错误 → `502`，其他 → `500` 且不暴露内部细节。

## 添加新协议

要支持新协议（例如 WireGuard），请按照以下步骤操作。

### 1. 实现 `ProxyLink`

创建一个包（例如 `wireguard/wireguard.go`）。处理器遵循现有协议使用的
依赖注入模式：

```go
package wireguard

import (
    "strings"

    "sub-filter/internal/validator"
)

type WireGuardLink struct {
    badWords      []string
    isValidHost   func(string) bool
    checkBadWords func(string) (string, bool, string)
    ruleValidator validator.Validator
}

func NewWireGuardLink(
    bw []string,
    vh func(string) bool,
    cb func(string) (string, bool, string),
    val validator.Validator,
) *WireGuardLink {
    if val == nil {
        val = &validator.GenericValidator{}
    }
    return &WireGuardLink{
        badWords:      bw,
        isValidHost:   vh,
        checkBadWords: cb,
        ruleValidator: val,
    }
}

// Matches 报告该行是否为本协议的链接。
func (w *WireGuardLink) Matches(s string) bool {
    const prefix = "wg://"
    return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// Process 解析、校验并规范化链接。
// 成功时返回（规范化链接, ""），拒绝时返回（"", 原因）。
func (w *WireGuardLink) Process(s string) (string, string) {
    // 解析 URL，用 w.isValidHost 检查主机/端口，
    // 用 w.checkBadWords 检查片段，
    // 用 w.ruleValidator 校验参数，
    // 然后重建规范化链接
    return s, ""
}
```

### 2. 注册处理器

处理器在 `pkg/service/service.go` 的 `createProxyProcessors()` 中收集
（是一个切片，不是 map）：

```go
return []ProxyLink{
    vless.NewVLESSLink(patterns, utils.IsValidHost, utils.IsValidPort, checkBadWords, getValidator("vless")),
    // ... 现有处理器 ...
    wireguard.NewWireGuardLink(patterns, utils.IsValidHost, checkBadWords, getValidator("wireguard")),
}
```

### 3. 添加校验规则

在 `config/rules.yaml` 中添加一节：

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

### 4. 添加 YAML 构建器

要支持 `format=yaml`，请在 `parseProxyToYAML` 的 switch 中添加该方案，
并在 `pkg/service/service.go` 中参照现有构建器实现 `buildWireGuardYAML`
构建器。在 `pkg/service/format_yaml_file_test.go` 中添加一个用例，以便对
参数丢失进行防护。

### 5. 编写测试

使用标准 `testing` 包创建 `wireguard/wireguard_test.go`：

```go
func TestWireGuardLink_Matches(t *testing.T) {
    wg := NewWireGuardLink(nil, nil, nil, nil)
    if !wg.Matches("wg://abc") {
        t.Error("expected wg:// link to match")
    }
    if wg.Matches("ss://abc") {
        t.Error("ss:// link must not match")
    }
}
```

## 测试

```bash
go test ./...                                   # 全部测试
go test ./pkg/service ./pkg/config ./internal/validator   # 核心包
go test ./ss ./vless ./vmess ./trojan ./hysteria2         # 协议包
go test -race ./...                             # 竞态检测
go test ./pkg/service/ -bench=. -benchmem -run='^$'       # 基准测试
```

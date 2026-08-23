[EN](DEVELOPMENT.md) / [RU](ru/DEVELOPMENT.md) / [ZH](zh/DEVELOPMENT.md)

<!-- TOC -->
* [Development guide](#development-guide)
  * [Project layout](#project-layout)
  * [Typed errors (`pkg/errors`)](#typed-errors-pkgerrors)
    * [Error structure](#error-structure)
    * [Error codes](#error-codes)
    * [Severity levels](#severity-levels)
    * [Constructors and helpers](#constructors-and-helpers)
  * [Adding a new protocol](#adding-a-new-protocol)
    * [1. Implement `ProxyLink`](#1-implement-proxylink)
    * [2. Register the processor](#2-register-the-processor)
    * [3. Add validation rules](#3-add-validation-rules)
    * [4. Add a YAML builder](#4-add-a-yaml-builder)
    * [5. Write tests](#5-write-tests)
  * [Testing](#testing)
<!-- TOC -->

# Development guide

Notes for extending the project. For idiomatic Go practices see
[`.github/instructions/go.instructions.md`](../.github/instructions/go.instructions.md).

## Project layout

| Path                                          | Purpose                                                              |
|-----------------------------------------------|----------------------------------------------------------------------|
| `main.go`                                     | Flag parsing, config loading, server/CLI bootstrap                   |
| `pkg/service`                                 | HTTP handlers, filtering, merge, caching, YAML formatting            |
| `pkg/config`                                  | Config schema and loading (nested YAML + legacy flat keys)           |
| `pkg/errors`                                  | Typed errors with codes and severity                                 |
| `pkg/logger`                                  | Structured logging wrapper over `slog`                               |
| `pkg/cache`                                   | Compiled-regex cache with hit/miss stats                             |
| `internal/validator`                          | Generic rule engine (`required`/`allowed`/`forbidden`/`conditional`) |
| `internal/utils`                              | URL normalization, host/port checks, country lookup, dedupe          |
| `vless`, `vmess`, `trojan`, `ss`, `hysteria2` | Protocol parsers/normalizers                                         |

## Typed errors (`pkg/errors`)

The application uses a single typed error for consistent handling and logging.

### Error structure

```go
type FilterError struct {
    Code      ErrorCode      // error category
    Category  string         // e.g. "Parse", "Network", "Config"
    Message   string         // human-readable message
    Err       error          // wrapped cause (may be nil)
    Severity  Severity       // severity level
    Timestamp time.Time      // creation time
    Context   map[string]any // extra context (sourceID, URL, ...)
}
```

`FilterError` implements `error` and `Unwrap()`, so `errors.Is`/`errors.As`
work through the cause chain.

### Error codes

| Code                   | Constant          | Description            |
| ---------------------- | ----------------- | ---------------------- |
| `config_error`         | `ErrCodeConfig`   | Configuration errors   |
| `validation_error`     | `ErrCodeValidate` | Data validation errors |
| `network_error`        | `ErrCodeNetwork`  | Network errors         |
| `http_error`           | `ErrCodeHTTP`     | HTTP errors            |
| `parse_error`          | `ErrCodeParse`    | Parsing errors         |
| `io_error`             | `ErrCodeIO`       | I/O errors             |
| `file_operation_error` | `ErrCodeFileOp`   | File operation errors  |
| `logic_error`          | `ErrCodeLogic`    | Logic errors           |

### Severity levels

`info`, `warning`, `error`, `critical`
(constants `SeverityInfo` … `SeverityCritical`).

### Constructors and helpers

```go
import "sub-filter/pkg/errors"

// Typed constructors
err := errors.ValidationError("invalid country code")
err = errors.ParseError("failed to parse YAML", cause)
err = errors.NetworkError("fetch failed", cause)
err = errors.ConfigError("bad config", cause)
err = errors.IOError("read failed", cause)

// Builder methods
err = errors.ParseError("failed to parse", cause).
    WithContext("file", "config.yaml").
    WithSeverity(errors.SeverityWarning).
    WithCause(cause)

// Type check
var fe *errors.FilterError
if stderrors.As(err, &fe) {
    if fe.Code == errors.ErrCodeConfig {
        // handle config error
    }
}

// Recoverability hint (network/IO errors are retryable)
if fe.IsRecoverable() { /* retry */ }
```

HTTP handlers map error codes to safe client responses
(`writeProcessingError` in `pkg/service`): validation errors → `400`,
network/parse errors → `502`, anything else → `500` without internal details.

## Adding a new protocol

To support a new protocol (e.g. WireGuard), follow these steps.

### 1. Implement `ProxyLink`

Create a package (e.g. `wireguard/wireguard.go`). Processors follow the
dependency-injection pattern used by the existing protocols:

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

// Matches reports whether the line is a link of this protocol.
func (w *WireGuardLink) Matches(s string) bool {
    const prefix = "wg://"
    return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// Process parses, validates and normalizes the link.
// Returns (normalized link, "") on success or ("", reason) on rejection.
func (w *WireGuardLink) Process(s string) (string, string) {
    // parse URL, check host/port with w.isValidHost,
    // check the fragment with w.checkBadWords,
    // validate parameters with w.ruleValidator,
    // then rebuild the normalized link
    return s, ""
}
```

### 2. Register the processor

Processors are collected in `createProxyProcessors()` in
`pkg/service/service.go` (a slice, not a map):

```go
return []ProxyLink{
    vless.NewVLESSLink(patterns, utils.IsValidHost, utils.IsValidPort, checkBadWords, getValidator("vless")),
    // ... existing processors ...
    wireguard.NewWireGuardLink(patterns, utils.IsValidHost, checkBadWords, getValidator("wireguard")),
}
```

### 3. Add validation rules

Add a section to `config/rules.yaml`:

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

### 4. Add a YAML builder

To support `format=yaml`, add the scheme to the switch in `parseProxyToYAML`
and implement a `buildWireGuardYAML` builder in `pkg/service/service.go`,
following the existing builders. Add a case to
`pkg/service/format_yaml_file_test.go` so parameter loss is guarded.

### 5. Write tests

Create `wireguard/wireguard_test.go` using the standard `testing` package:

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

## Testing

```bash
go test ./...                                   # all tests
go test ./pkg/service ./pkg/config ./internal/validator   # core packages
go test ./ss ./vless ./vmess ./trojan ./hysteria2         # protocol packages
go test -race ./...                             # race detector
go test ./pkg/service/ -bench=. -benchmem -run='^$'       # benchmarks
```

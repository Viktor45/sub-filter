[EN](../DEVELOPMENT.md) / [RU](DEVELOPMENT.md) / [ZH](../zh/DEVELOPMENT.md)

<!-- TOC -->
* [Руководство разработчика](#руководство-разработчика)
  * [Структура проекта](#структура-проекта)
  * [Типизированные ошибки (`pkg/errors`)](#типизированные-ошибки-pkgerrors)
    * [Структура ошибки](#структура-ошибки)
    * [Коды ошибок](#коды-ошибок)
    * [Уровни серьёзности](#уровни-серьёзности)
    * [Конструкторы и помощники](#конструкторы-и-помощники)
  * [Добавление нового протокола](#добавление-нового-протокола)
    * [1. Реализуйте `ProxyLink`](#1-реализуйте-proxylink)
    * [2. Зарегистрируйте процессор](#2-зарегистрируйте-процессор)
    * [3. Добавьте правила валидации](#3-добавьте-правила-валидации)
    * [4. Добавьте сборщик YAML](#4-добавьте-сборщик-yaml)
    * [5. Напишите тесты](#5-напишите-тесты)
  * [Тестирование](#тестирование)
<!-- TOC -->

# Руководство разработчика

Заметки по расширению проекта. Об идиоматичных практиках Go см.
[`.github/instructions/go.instructions.md`](../../.github/instructions/go.instructions.md).

## Структура проекта

| Путь                                          | Назначение                                                                   |
|-----------------------------------------------|------------------------------------------------------------------------------|
| `main.go`                                     | Разбор флагов, загрузка конфигурации, запуск сервера/CLI                     |
| `pkg/service`                                 | HTTP-обработчики, фильтрация, merge, кеширование, форматирование YAML        |
| `pkg/config`                                  | Схема и загрузка конфигурации (вложенный YAML + устаревшие плоские ключи)    |
| `pkg/errors`                                  | Типизированные ошибки с кодами и серьёзностью                                |
| `pkg/logger`                                  | Обёртка структурированного логирования поверх `slog`                         |
| `pkg/cache`                                   | Кэш скомпилированных regex со статистикой попаданий                          |
| `internal/validator`                          | Универсальный движок правил (`required`/`allowed`/`forbidden`/`conditional`) |
| `internal/utils`                              | Нормализация URL, проверка хостов/портов, справочник стран, дедупликация     |
| `vless`, `vmess`, `trojan`, `ss`, `hysteria2` | Парсеры/нормализаторы протоколов                                             |

## Типизированные ошибки (`pkg/errors`)

Приложение использует единую типизированную ошибку для единообразной обработки
и логирования.

### Структура ошибки

```go
type FilterError struct {
    Code      ErrorCode      // категория ошибки
    Category  string         // например, "Parse", "Network", "Config"
    Message   string         // человекочитаемое сообщение
    Err       error          // обёрнутая причина (может быть nil)
    Severity  Severity       // уровень серьёзности
    Timestamp time.Time      // время создания
    Context   map[string]any // дополнительный контекст (sourceID, URL, ...)
}
```

`FilterError` реализует `error` и `Unwrap()`, поэтому `errors.Is`/`errors.As`
работают по цепочке причин.

### Коды ошибок

| Код                    | Константа         | Описание                 |
|------------------------|-------------------|--------------------------|
| `config_error`         | `ErrCodeConfig`   | Ошибки конфигурации      |
| `validation_error`     | `ErrCodeValidate` | Ошибки валидации данных  |
| `network_error`        | `ErrCodeNetwork`  | Сетевые ошибки           |
| `http_error`           | `ErrCodeHTTP`     | Ошибки HTTP              |
| `parse_error`          | `ErrCodeParse`    | Ошибки разбора           |
| `io_error`             | `ErrCodeIO`       | Ошибки ввода-вывода      |
| `file_operation_error` | `ErrCodeFileOp`   | Ошибки файловых операций |
| `logic_error`          | `ErrCodeLogic`    | Логические ошибки        |

### Уровни серьёзности

`info`, `warning`, `error`, `critical`
(константы `SeverityInfo` … `SeverityCritical`).

### Конструкторы и помощники

```go
import "sub-filter/pkg/errors"

// Типизированные конструкторы
err := errors.ValidationError("invalid country code")
err = errors.ParseError("failed to parse YAML", cause)
err = errors.NetworkError("fetch failed", cause)
err = errors.ConfigError("bad config", cause)
err = errors.IOError("read failed", cause)

// Методы-строители
err = errors.ParseError("failed to parse", cause).
    WithContext("file", "config.yaml").
    WithSeverity(errors.SeverityWarning).
    WithCause(cause)

// Проверка типа
var fe *errors.FilterError
if stderrors.As(err, &fe) {
    if fe.Code == errors.ErrCodeConfig {
        // обработка ошибки конфигурации
    }
}

// Подсказка о восстановимости (сетевые/IO-ошибки повторимы)
if fe.IsRecoverable() { /* повторить */ }
```

HTTP-обработчики отображают коды ошибок в безопасные ответы клиенту
(`writeProcessingError` в `pkg/service`): ошибки валидации → `400`,
сетевые/ошибки разбора → `502`, всё остальное → `500` без внутренних
деталей.

## Добавление нового протокола

Чтобы поддержать новый протокол (например, WireGuard), выполните следующие
шаги.

### 1. Реализуйте `ProxyLink`

Создайте пакет (например, `wireguard/wireguard.go`). Процессоры следуют
паттерну внедрения зависимостей, используемому существующими протоколами:

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

// Matches сообщает, является ли строка ссылкой этого протокола.
func (w *WireGuardLink) Matches(s string) bool {
    const prefix = "wg://"
    return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// Process разбирает, валидирует и нормализует ссылку.
// Возвращает (нормализованная ссылка, "") при успехе или ("", причина) при отклонении.
func (w *WireGuardLink) Process(s string) (string, string) {
    // разбор URL, проверка хоста/порта через w.isValidHost,
    // проверка фрагмента через w.checkBadWords,
    // валидация параметров через w.ruleValidator,
    // затем сборка нормализованной ссылки
    return s, ""
}
```

### 2. Зарегистрируйте процессор

Процессоры собираются в `createProxyProcessors()` в
`pkg/service/service.go` (срез, а не карта):

```go
return []ProxyLink{
    vless.NewVLESSLink(patterns, utils.IsValidHost, utils.IsValidPort, checkBadWords, getValidator("vless")),
    // ... существующие процессоры ...
    wireguard.NewWireGuardLink(patterns, utils.IsValidHost, checkBadWords, getValidator("wireguard")),
}
```

### 3. Добавьте правила валидации

Добавьте секцию в `config/rules.yaml`:

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

### 4. Добавьте сборщик YAML

Для поддержки `format=yaml` добавьте схему в switch в `parseProxyToYAML` и
реализуйте сборщик `buildWireGuardYAML` в `pkg/service/service.go`, следуя
существующим сборщикам. Добавьте кейс в
`pkg/service/format_yaml_file_test.go`, чтобы потеря параметров была под
защитой теста.

### 5. Напишите тесты

Создайте `wireguard/wireguard_test.go`, используя стандартный пакет
`testing`:

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

## Тестирование

```bash
go test ./...                                   # все тесты
go test ./pkg/service ./pkg/config ./internal/validator   # основные пакеты
go test ./ss ./vless ./vmess ./trojan ./hysteria2         # пакеты протоколов
go test -race ./...                             # детектор гонок
go test ./pkg/service/ -bench=. -benchmem -run='^$'       # бенчмарки
```

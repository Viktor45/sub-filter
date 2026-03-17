# Расширение проекта

## Добавление нового протокола

Чтобы добавить поддержку нового протокола (например, WireGuard или SOCKS5), реализуйте интерфейс `ProxyLink`:

```go
// internal/wireguard/wireguard.go
package wireguard

import (
    "regexp"
    "strings"
)

type WireGuardLink struct{}

func (w WireGuardLink) Matches(s string) bool {
    return strings.HasPrefix(s, "wg://")
}

func (w WireGuardLink) Process(s string) (string, string) {
    // Парсинг и валидация WireGuard ссылки
    // Возвращает: (очищенная ссылка, страна)
    return s, "US" // пример
}
```

Затем зарегистрируйте в `pkg/service/service.go`:

```go
// В createProxyProcessors добавьте:
processors["wireguard"] = &wireguard.WireGuardLink{}
```

## Добавление нового правила валидации

Добавьте в `config/rules.yaml`:

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

## Тестирование

Создайте `wireguard_test.go` с unit тестами:

```go
func TestWireGuardLink_Matches(t *testing.T) {
    wg := WireGuardLink{}
    assert.True(t, wg.Matches("wg://..."))
    assert.False(t, wg.Matches("ss://..."))
}
```
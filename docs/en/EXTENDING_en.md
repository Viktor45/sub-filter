# Extending the Project

## Adding a New Protocol

To add support for a new protocol (e.g., WireGuard or SOCKS5), implement the `ProxyLink` interface:

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
    // Parse and validate WireGuard link
    // Returns: (cleaned link, country)
    return s, "US" // example
}
```

Then register in `pkg/service/service.go`:

```go
// In createProxyProcessors add:
processors["wireguard"] = &wireguard.WireGuardLink{}
```

## Adding a New Validation Rule

Add to `config/rules.yaml`:

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

## Testing

Create `wireguard_test.go` with unit tests:

```go
func TestWireGuardLink_Matches(t *testing.T) {
    wg := WireGuardLink{}
    assert.True(t, wg.Matches("wg://..."))
    assert.False(t, wg.Matches("ss://..."))
}
```
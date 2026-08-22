# 项目扩展

## 添加新协议
要添加对新协议（例如 WireGuard 或 SOCKS5）的支持，请实现 `ProxyLink` 接口：

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
    // 解析并验证 WireGuard 链接
    // 返回: (清理后的链接, 国家代码)
    return s, "US" // 示例
}
```

然后在 `pkg/service/service.go` 中进行注册：

```go
// 在 createProxyProcessors 中添加：
processors["wireguard"] = &wireguard.WireGuardLink{}
```

## 添加新的验证规则
在 `config/rules.yaml` 中添加相关配置：

```yaml
wireguard:
  required_params: [public_key, endpoint]
  forbidden_values:
    endpoint: ["localhost", "127.0.0.1"]
```

## 测试
创建 `wireguard_test.go` 文件并编写单元测试：

```go
func TestWireGuardLink_Matches(t *testing.T) {
    wg := WireGuardLink{}
    assert.True(t, wg.Matches("wg://..."))
    assert.False(t, wg.Matches("ss://..."))
}
```
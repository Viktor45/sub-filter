# 扩展项目

## 添加新协议

要添加对新协议的支持，实现 `ProxyLink` 接口：

```go
type WireGuardLink struct{}

func (w WireGuardLink) Matches(s string) bool {
    return strings.HasPrefix(s, "wg://")
}

func (w WireGuardLink) Process(s string) (string, string) {
    return s, "US"
}
```

然后在 `pkg/service/service.go` 中注册。}
[EN](../FORMAT_PARAMETER.md) / [RU](../ru/FORMAT_PARAMETER.md) / [ZH](FORMAT_PARAMETER.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [`format` 参数](#format-参数)
  * [支持的格式](#支持的格式)
    * [纯文本（默认）](#纯文本默认)
    * [YAML（Clash/Mihomo）](#yamlclashmihomo)
    * [Base64](#base64)
    * [组合：YAML + Base64](#组合yaml--base64)
  * [YAML 转换细节](#yaml-转换细节)
    * [代理名称](#代理名称)
    * [各协议字段](#各协议字段)
  * [响应头与文件名](#响应头与文件名)
  * [使用示例](#使用示例)
  * [故障排查](#故障排查)
<!-- TOC -->

# `format` 参数

`/filter` 和 `/merge` 的 `format=` 查询参数可将代理列表转换为适合不同
客户端的形式。

| 值                 | 结果                                          |
| ------------------ | --------------------------------------------- |
| *(空/缺省)*        | 纯文本，每行一个代理 URL                      |
| `yaml`             | 兼容 Clash/Mihomo 的 YAML 代理列表            |
| `base64`           | base64 编码的纯文本                           |
| `yaml+base64`      | YAML 代理列表，再进行 base64 编码             |

值不区分大小写。仅接受 `yaml` 和 `base64` 两个标记；其他任何值都返回
`400 Bad Request`。

> 📝 在 URL 查询字符串中，字面 `+` 会被解码为空格，因此
> `format=yaml+base64` 与 `format=yaml%20base64` 等价——两者均可接受。

## 支持的格式

### 纯文本（默认）

不带 `format` 时，响应为每行一个代理 URL：

```text
/filter?id=1
```

```text
ss://BASE64@example.com:8388#proxy1
vless://uuid@example.com:443?security=tls&sni=example.com#proxy2
```

### YAML（Clash/Mihomo）

`format=yaml` 将每条受支持的代理链接转换为结构化的 Clash/Mihomo 代理条目：

```text
/filter?id=1&format=yaml
/merge?ids=1,2&format=yaml
```

```yaml
proxies:
  - name: "proxy1"
    type: ss
    server: "example.com"
    port: 8388
    cipher: "2022-blake3-aes-256-gcm"
    password: "mypassword"
  - name: "proxy2"
    type: vless
    server: "example.com"
    port: 443
    uuid: "myuuid"
    network: "tcp"
    tls: true
    servername: "example.com"
```

若过滤后没有剩余代理，则返回最小的 `proxies: []` 文档。

### Base64

`format=base64` 对纯文本列表进行 base64 编码：

```text
/filter?id=1&format=base64
```

```text
c3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MQp2bGVzczo...
```

### 组合：YAML + Base64

两个标记可以按任意顺序给出（`yaml+base64` 或 `base64+yaml`）；始终先执行
YAML 转换，然后对结果进行 base64 编码：

```text
/filter?id=1&format=yaml+base64
```

```text
cHJveGllczoKICAtIG5hbWU6ICJwcm94eTEiCiAgICB0eXBlOiBzcwogICAg...
```

## YAML 转换细节

转换器解析的是协议包生成的**规范化**链接（SS 的 userinfo 是 base64 的
`cipher:password`，VMess 是 `vmess://BASE64(JSON)`）。

- 注释、空行和不受支持的方案（`ss`、`vless`、`vmess`、`trojan`、
  `hy2`/`hysteria2` 以外的任何内容）都会被跳过——绝不会转换为伪造条目。
- 所有字符串值都会加引号并转义，特殊字符不会破坏 YAML 结构。

### 代理名称

名称按以下顺序解析：

1. **VMess**：解码后 JSON 载荷的 `ps` 字段，其次是 URL 片段。
2. **其他协议**：URL 片段——若存在 `name=...` 部分则取之，否则取整个片段。
3. 查询参数 `remark=` 或 `desc=`。
4. 最后兜底为 `<hostname>-<index>`，再不行用 `proxy-<index>`。

### 各协议字段

| 协议        | 输出字段                                                                                                                                                                                            |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ss`        | `server`、`port`、`cipher`、`password`，可选 `plugin: obfs` + `plugin-opts.mode`、`udp`                                                                                                             |
| `vless`     | `server`、`port`、`uuid`、`network`、`tls`、`servername`、`reality-opts`（`public-key`、`short-id`）、`client-fingerprint`、`alpn`、`flow`、传输选项（`ws-opts`、`grpc-opts`、`xhttp-opts`）、`udp` |
| `vmess`     | `server`、`port`、`uuid`、`alterId`、`cipher`、`network`、`tls`、`servername`、传输选项（`ws-opts`、`h2-opts`、`grpc-opts`）                                                                        |
| `trojan`    | `server`、`port`、`password`、`sni`、`reality-opts`、`skip-cert-verify`、`alpn`、`network`、传输选项、`udp`                                                                                         |
| `hysteria2` | `server`、`port`、`password`、`obfs`（salamander）、`sni`、`skip-cert-verify`、`up`、`down`、`udp`                                                                                                  |

传输说明：Xray 的规范参数是 `type`（`network` 作为回退）；REALITY 字段映射为
`pbk`/`sid`/`fp`；Hysteria2 的密码取自 userinfo 或 `obfs-password`；旧式
`allowInsecure` 映射为 `skip-cert-verify`；速度限制读取 `upmbps`/`downmbps`
（回退为 `up`/`down`）。

## 响应头与文件名

响应以附件形式提供，并带有安全响应头
（`X-Content-Type-Options: nosniff`、RFC 5987 编码的文件名）。

| 格式            | Content-Type                        | 文件扩展名     |
| --------------- | ----------------------------------- | -------------- |
| 纯文本（默认）  | `text/plain; charset=utf-8`         | `.txt`         |
| YAML            | `application/x-yaml; charset=utf-8` | `.yaml`        |
| Base64          | `application/octet-stream`          | `.b64`         |
| YAML + Base64   | `application/octet-stream`          | `.yaml`        |

## 使用示例

```bash
# 纯文本（默认）
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP"

# Clash/Mihomo 的 YAML
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml" > profile.yaml

# 合并源并输出 YAML
curl -H "User-Agent: clash" "http://localhost:8000/merge?ids=1,2&format=yaml"

# base64 编码的 YAML（用于嵌入）
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml+base64"

# 带国家过滤和行数限制的 YAML
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP&format=yaml&lim=100"
```

> 🔐 所有端点仍然要求允许的 `User-Agent` 并受限流约束——见
> [主指南](README.md#请求保护)。

## 故障排查

| 现象                                 | 原因 / 解决方法                                                         |
| ------------------------------------ | ----------------------------------------------------------------------- |
| `format=` 返回 `400 Bad Request`     | 未知标记（例如 `json`）。仅允许 `yaml` 和 `base64`。                    |
| YAML 中的代理少于文本                | 不受支持的方案和无法解析的链接在转换时被跳过。                          |
| Base64 无法解码                      | 使用标准解码器（`base64 -d`）；确保传输过程中没有添加换行符。           |
| YAML 为空                            | 所有代理都被过滤掉了；响应为 `proxies: []`。                            |

**性能说明：** YAML 转换是对各行的一次遍历；base64 会使响应体积增加约 33%；
组合格式按顺序应用各转换。所有响应仍受限流和 `lim` 约束。

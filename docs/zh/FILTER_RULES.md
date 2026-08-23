[EN](../FILTER_RULES.md) / [RU](../ru/FILTER_RULES.md) / [ZH](FILTER_RULES.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [校验规则（`rules.yaml`）](#校验规则rulesyaml)
  * [校验如何工作](#校验如何工作)
  * [规则类型](#规则类型)
    * [required_params](#required_params)
    * [allowed_values](#allowed_values)
    * [forbidden_values](#forbidden_values)
    * [conditional](#conditional)
  * [VLESS](#vless)
  * [VMess](#vmess)
  * [Trojan](#trojan)
  * [Shadowsocks](#shadowsocks)
  * [Hysteria2](#hysteria2)
  * [调整严格程度](#调整严格程度)
  * [典型拒绝原因](#典型拒绝原因)
  * [参考链接](#参考链接)
<!-- TOC -->

# 校验规则（`rules.yaml`）

文件 [`config/rules.yaml`](../../config/rules.yaml) 定义哪些代理配置被视为
有效、哪些会被拒绝。它按协议分为若干节：`vless`、`vmess`、`trojan`、
`ss`、`hysteria2`。

您可以添加自己的规则或修改现有规则。编辑文件后请重启过滤器。

## 校验如何工作

每个协议的解析器提取链接参数，并交给通用规则引擎
（`internal/validator`）。检查按以下顺序执行：

1. **`required_params`** — 列出的每个参数都必须存在。
2. **`forbidden_values`** — 若列出的参数具有禁止值，则拒绝该链接。
   不区分大小写；通配符 `"*"` 禁止任何值。
3. **`allowed_values`** — 若列出的参数存在，其值必须在允许列表中。
   不区分大小写。
4. **`conditional`** — 当所有 `when` 条件匹配时，`require` 中的参数变为
   必需。条件值**区分大小写**比较（它们是逻辑条件，不是用户输入）。

未通过任何检查的链接都会被拒绝，并连同原因记录在缓存文件
`rejected_*.txt` 中。

> 📝 自带 `rules.yaml` 中的部分 `required_params` 条目是故意注释掉的——
> 默认设置刻意宽松（「安全优先于数量」）。见[调整严格程度](#调整严格程度)。

## 规则类型

### required_params

链接中必须存在的参数列表。

```yaml
vless:
  required_params:
    - sni
```

缺少任何参数即拒绝链接。此检查最先执行。

### allowed_values

参数的可接受值。仅在参数存在时检查。

```yaml
ss:
  allowed_values:
    method:
      - "aes-256-gcm"
      - "chacha20-poly1305"
```

比较不区分大小写（`aes-256-gcm` = `AES-256-GCM`）。值不在列表中即拒绝链接。

### forbidden_values

参数的禁止值。仅在参数存在时检查。优先于 `allowed_values`。

```yaml
vless:
  forbidden_values:
    security: ["none"]      # 禁止 security=none
    authority: [""]         # 禁止空 authority

trojan:
  forbidden_values:
    flow: ["*"]             # 禁止任何 flow 值
```

通配符 `"*"` 禁止该参数的任何值。

### conditional

仅在满足特定条件时应用的规则：

```yaml
conditional:
  - when: { security: "reality" }
    require: ["pbk"]
  - when: { type: "grpc" }
    require: ["serviceName"]
```

`when` 中的所有条目必须全部匹配（逻辑与）；随后 `require` 中的每个参数
变为必需。

---

## VLESS

```yaml
vless:
  required_params:
    - sni
    # encryption 在 URI 中是可选的；取消注释以强制要求
    # - encryption
  forbidden_values:
    security: ["none"]
    authority: [""]
  allowed_values:
    security: ["tls", "reality"]
    type: ["tcp", "ws", "httpupgrade", "grpc", "xhttp", "splithttp"]
    flow:
      - "xtls-rprx-vision"
      - "xtls-rprx-vision-udp443"
      - "xtls-rprx-vision-direct"
    mode: ["gun", "multi"]
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: "ws" }
      require: ["path"]
    - when: { type: "httpupgrade" }
      require: ["path"]
    - when: { type: "xhttp" }
      require: ["path"]
    - when: { type: "splithttp" }
      require: ["path"]
```

| 方面       | 规则                                                                                                    |
|------------|---------------------------------------------------------------------------------------------------------|
| 必需       | `sni`                                                                                                   |
| `security` | 仅 `tls` 或 `reality`；禁止 `none`。缺少 `security` 时解析器按 `none` 处理并拒绝                        |
| `type`     | `tcp`、`ws`、`httpupgrade`、`grpc`、`xhttp`、`splithttp`                                                |
| `flow`     | `xtls-rprx-vision`、`xtls-rprx-vision-udp443`、`xtls-rprx-vision-direct`                                |
| `mode`     | `gun`、`multi`（gRPC 模式）                                                                             |
| 条件       | `security=reality` → `pbk`；`type=grpc` → `serviceName`；`type=ws/httpupgrade/xhttp/splithttp` → `path` |

**有效示例：**

```text
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp
vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path
```

---

## VMess

```yaml
vmess:
  # uuid 默认不要求（部分实现会省略它）；取消注释以强制要求
  # required_params:
  #   - uuid
  forbidden_values:
    security: ["null", "zero", "none"]
    scy: ["null"]
  allowed_values:
    net: ["tcp", "ws", "grpc", "httpupgrade", "h2", "xhttp", "splithttp"]
    security: ["auto", "aes-128-gcm", "chacha20-poly1305"]
  conditional:
    - when: { net: "grpc" }
      require: ["serviceName"]
    - when: { net: "ws" }
      require: ["path"]
    - when: { net: "httpupgrade" }
      require: ["path"]
    - when: { net: "xhttp" }
      require: ["path"]
    - when: { net: "splithttp" }
      require: ["path"]
```

| 方面       | 规则                                                                                    |
|------------|-----------------------------------------------------------------------------------------|
| 必需       | 默认无（服务器地址和 UUID 仍由解析器本身强制检查）                                      |
| `security` | `auto`、`aes-128-gcm`、`chacha20-poly1305`；`none`、`zero`、`null` **被禁止**（未加密） |
| `scy`      | 禁止 `null`                                                                             |
| `net`      | `tcp`、`ws`、`grpc`、`httpupgrade`、`h2`、`xhttp`、`splithttp`                          |
| 条件       | `net=grpc` → `serviceName`；`net=ws/httpupgrade/xhttp/splithttp` → `path`               |

> ⚠️ 与旧版规则集不同，`zero` 和 `none` 加密会被拒绝，而不是被容忍。

---

## Trojan

```yaml
trojan:
  # password 默认不要求；取消注释以强制要求
  # required_params:
  #   - password
  forbidden_values:
    flow: ["*"]   # flow 已在 Xray-core 2024+ 中从 Trojan 移除
  allowed_values:
    type: ["tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp"]
    security: ["tls", "reality"]
    mode: ["gun", "multi"]
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: "ws" }
      require: ["path"]
    - when: { type: "httpupgrade" }
      require: ["path"]
    - when: { type: "xhttp" }
      require: ["path"]
    - when: { type: "splithttp" }
      require: ["path"]
```

| 方面       | 规则                                                                                                    |
|------------|---------------------------------------------------------------------------------------------------------|
| 必需       | 默认无（解析器仍要求有效的主机/端口）                                                                   |
| `flow`     | **禁止任何值** — 已在 Xray-core 2024+ 中从 Trojan 移除                                                  |
| `type`     | `tcp`、`ws`、`grpc`、`httpupgrade`、`xhttp`、`splithttp`                                                |
| `security` | `tls`、`reality`                                                                                        |
| `mode`     | `gun`、`multi`（gRPC 模式）                                                                             |
| 条件       | `security=reality` → `pbk`；`type=grpc` → `serviceName`；`type=ws/httpupgrade/xhttp/splithttp` → `path` |

**有效示例：**

```text
trojan://password@example.com:443?security=tls&type=tcp
trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun
```

❌ 拒绝 — 包含已移除的 `flow` 参数：

```text
trojan://password@example.com:443?flow=xtls-rprx-vision
```

---

## Shadowsocks

```yaml
ss:
  required_params:
    # password 和 method 默认不要求；取消注释以加强安全
    # - password
    # - method
  forbidden_values:
    # 已废弃的流式加密（已从 Xray-core 2024+ 移除）
    method:
      - "aes-128-cfb"
      - "aes-256-cfb"
      - "aes-128-ctr"
      - "aes-256-ctr"
  allowed_values:
    method:
      # AEAD 加密（现代标准）
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "xchacha20-poly1305"
      # Shadowsocks 2022（Blake3）
      - "2022-blake3-aes-128-gcm"
      - "2022-blake3-aes-256-gcm"
      - "2022-blake3-chacha20-poly1305"
      # 未加密；默认禁用
      # - "none"
```

| 方面   | 规则                                                                                                                                                                         |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 必需   | 默认无（解析器仍会校验加密语法）                                                                                                                                             |
| 允许   | AEAD：`aes-128-gcm`、`aes-256-gcm`、`chacha20-poly1305`、`xchacha20-poly1305`；SS2022：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305` |
| 禁止   | `aes-128-cfb`、`aes-256-cfb`、`aes-128-ctr`、`aes-256-ctr`（已从 Xray-core 2024+ 移除）                                                                                      |
| `none` | 默认**不允许**（在自带规则中被注释掉）                                                                                                                                       |

**推荐：** `2022-blake3-aes-256-gcm`（最安全、最现代）或
`aes-256-gcm`（传统 AEAD）。

```text
ss://2022-blake3-aes-256-gcm:password@example.com:8388   ✅
ss://aes-256-gcm:password@example.com:8388               ✅
ss://aes-256-cfb:password@example.com:8388               ❌ 拒绝（已废弃的加密）
```

---

## Hysteria2

```yaml
hysteria2:
  forbidden_values:
    insecure: ["1", "true"]
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

| 方面        | 规则                                                            |
| ----------- | --------------------------------------------------------------- |
| 必需        | `obfs`、`obfs-password`（混淆为必需）                           |
| `obfs`      | 仅 `salamander`                                                 |
| `insecure`  | 禁止 `1` / `true`（必须保持证书校验开启）                       |

**有效示例：**

```text
hy2://password@example.com:443?obfs=salamander&obfs-password=secret
```

---

## 调整严格程度

自带规则刻意严格。您可以自行调整：

- **放宽**：从 `forbidden_values` 或 `conditional` 中删除条目。
- **加强**：取消注释 `required_params` 条目（VLESS 的 `encryption`、
  VMess 的 `uuid`、Trojan 的 `password`、SS 的 `password`/`method`），
  或为 Shadowsocks 重新启用未加密的 `none` 方法。

任何修改都需要重启程序才能生效。

## 典型拒绝原因

这些拒绝跟随上游 Xray-core 的变更，也是公共订阅丢失条目的最常见原因：

| 协议        | 拒绝条件                                     | 原因                                  |
|-------------|----------------------------------------------|---------------------------------------|
| VLESS       | `security=none` 或缺少 `security`            | 未加密流量                            |
| VMess       | `security` 为 `none`/`zero`/`null`           | 未加密流量                            |
| Trojan      | 任何 `flow` 参数                             | 已在 Xray-core 2024+ 中从 Trojan 移除 |
| Shadowsocks | CFB/CTR 加密                                 | 已从 Xray-core 2024+ 移除             |
| Hysteria2   | 缺少 `obfs`/`obfs-password`，或 `insecure=1` | 混淆为必需；必须保持 TLS 校验开启     |

## 参考链接

- Xray-core: https://xtls.github.io/
- Trojan: https://trojan-gfw.github.io/
- Shadowsocks: https://shadowsocks.org/

[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES.md) / [ZH](FILTER_RULES_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [`rules.yaml` 文档](#rulesyaml-文档)
  * [结构与核心概念](#结构与核心概念)
    * [1. `required_params` — 必需参数](#1-required_params--必需参数)
    * [2. `allowed_values` — 允许的值](#2-allowed_values--允许的值)
    * [3. `forbidden_values` — 禁止的值](#3-forbidden_values--禁止的值)
    * [4. `conditional` — 条件规则](#4-conditional--条件规则)
  * [VLESS — 完整文档](#vless--完整文档)
    * [规则结构](#规则结构)
    * [必需参数](#必需参数)
    * [允许的参数](#允许的参数)
    * [禁止的参数](#禁止的参数)
    * [条件规则](#条件规则)
    * [有效链接示例](#有效链接示例)
  * [VMess — 完整文档](#vmess--完整文档)
    * [规则结构](#规则结构-1)
    * [必需参数](#必需参数-1)
    * [允许的参数](#允许的参数-1)
    * [禁止的参数](#禁止的参数-1)
    * [条件规则](#条件规则-1)
    * [有效链接示例](#有效链接示例-1)
  * [Trojan — 完整文档](#trojan--完整文档)
    * [规则结构](#规则结构-2)
    * [必需参数](#必需参数-2)
    * [允许的参数](#允许的参数-2)
    * [🔴 禁止的参数](#-禁止的参数)
    * [条件规则](#条件规则-2)
    * [有效链接示例](#有效链接示例-2)
  * [Shadowsocks (SS) — 完整文档](#shadowsocks-ss--完整文档)
    * [规则结构](#规则结构-3)
    * [必需参数](#必需参数-3)
    * [允许的加密方法](#允许的加密方法)
    * [🔴 禁止的方法（已在 Xray-core 2024+ 中移除）](#-禁止的方法已在-xray-core-2024-中移除)
    * [有效链接示例](#有效链接示例-3)
  * [Hysteria2 — 完整文档](#hysteria2--完整文档)
    * [规则结构](#规则结构-4)
    * [必需参数](#必需参数-4)
    * [允许的参数](#允许的参数-3)
    * [有效链接示例](#有效链接示例-4)
  * [关键变更 (2026年2月)](#关键变更-2026年2月)
    * [🔴 Trojan：不再支持 `flow` 参数](#-trojan不再支持-flow-参数)
    * [🔴 Shadowsocks：不再支持 CFB 和 CTR 方法](#-shadowsocks不再支持-cfb-和-ctr-方法)
  * [附加资源](#附加资源)
<!-- TOC -->

# `rules.yaml` 文档

## 结构与核心概念
`config/rules.yaml` 文件包含所有受支持代理协议的验证规则。这些规则定义了哪些配置被视为有效，哪些将被拒绝。

该文件按协议划分为不同的部分：
- `vless` — VLESS 协议
- `vmess` — VMess 协议
- `trojan` — Trojan 协议
- `ss` — Shadowsocks 协议
- `hysteria2` — Hysteria2 协议

### 1. `required_params` — 必需参数
链接中必须存在的参数列表。

**行为：**
- 如果缺少至少一个参数，则链接将被拒绝。
- 此检查在所有其他规则之前优先执行。

**示例：**
```yaml
vless:
  required_params:
    - encryption
    - sni
```
**解释：** VLESS 链接必须包含 `encryption` 和 `sni` 参数。如果缺少其中任何一个，链接将被拒绝。

### 2. `allowed_values` — 允许的值
特定参数可接受的值列表。

**行为：**
- 仅在参数存在时进行检查。
- 如果参数的值不在列表中，则链接将被拒绝。
- 比较不区分大小写（`aes-256-gcm` = `AES-256-GCM`）。
- 优先级低于 `forbidden_values`。

**示例：**
```yaml
ss:
  allowed_values:
    method:
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "2022-blake3-aes-256-gcm"
```
**解释：** 对于 Shadowsocks，仅允许使用这些加密方法。如果指定了其他方法（例如 `aes-128-cfb`），链接将被拒绝。

### 3. `forbidden_values` — 禁止的值
特定参数被禁止使用的值列表。

**行为：**
- 仅在参数存在时进行检查。
- 如果值在列表中，则链接将被拒绝。
- 优先级高于 `allowed_values`（优先检查）。
- 比较不区分大小写。
- 支持通配符 `"*"` — 禁止该参数的任何值。

**示例：**
```yaml
vless:
  forbidden_values:
    security: ["none"]      # 禁止 security=none
    authority: [""]         # 禁止 authority 为空

trojan:
  forbidden_values:
    flow: ["*"]             # 禁止所有 flow 值（参数已完全移除）
```
**解释：**
- 带有 `security=none` 的 VLESS 将被拒绝。
- 带有任何 `flow` 值的 Trojan 将被拒绝（该参数在 Xray-core 2024+ 中已弃用）。

⚠️ **重要提示：** `forbidden_values` 具有全局作用域。要允许例外情况（例如，仅对特定类型允许 `security=none`），请使用 `conditional` 规则。

### 4. `conditional` — 条件规则
仅在满足特定条件时才应用的规则。

**结构：**
```yaml
conditional:
  - when: { 参数: 值 }
    require: [必需参数列表]
```
**行为：**
- 在 `required_params`、`allowed_values` 和 `forbidden_values` 之后进行检查。
- `when` 条件充当逻辑与（所有条件必须为真）。
- 如果满足条件，则 `require` 中的参数将变为必需。

**示例：**
```yaml
conditional:
  # 如果 security=reality，则 pbk 是必需的
  - when: { security: "reality" }
    require: ["pbk"]

  # 如果 type=grpc，则 serviceName 是必需的
  - when: { type: "grpc" }
    require: ["serviceName"]

  # 如果 type=ws，则 path 是必需的
  - when: { type: "ws" }
    require: ["path"]
```
**解释：**
- 带有 `security=reality` 的 VLESS 必须包含 `pbk` 参数。
- 带有 `type=grpc` 的 VLESS 必须包含 `serviceName` 参数。
- 带有 `type=ws` 的 VLESS 必须包含 `path` 参数。

---

## VLESS — 完整文档

### 规则结构
```yaml
vless:
  required_params:
    - sni
    # encryption 在 URI 中是可选的，但为了兼容性，建议明确指定 "none"。
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

### 必需参数
| 参数           | 描述                      |
|--------------|-------------------------|
| `encryption` | 加密方法（可选，但建议明确指定 `none`） |
| `sni`        | 服务器名称指示（TLS/REALITY 必需） |

### 允许的参数
| 参数         | 允许的值                                                                     | 描述                  |
|------------|--------------------------------------------------------------------------|---------------------|
| `security` | `tls`, `reality`                                                         | 安全类型。**禁止：** `none` |
| `type`     | `tcp`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `splithttp`                 | 传输类型                |
| `flow`     | `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, `xtls-rprx-vision-direct` | XTLS 流控（仅限 REALITY） |
| `mode`     | `gun`, `multi`                                                           | gRPC 模式             |

### 禁止的参数
| 参数          | 禁止的值    | 原因         |
|-------------|---------|------------|
| `security`  | `none`  | 无安全性 — 不安全 |
| `authority` | `""`（空） | 违反 gRPC 规范 |

🔎 如果缺少 `security` 参数，它在 VLESS 解析器层将被自动视为 `none`，然后被 `forbidden_values` 规则拒绝。

### 条件规则
| 条件                 | 必需参数          | 描述                |
|--------------------|---------------|-------------------|
| `security=reality` | `pbk`         | REALITY 需要公钥      |
| `type=grpc`        | `serviceName` | gRPC 需要服务名称       |
| `type=ws`          | `path`        | WebSocket 需要路径    |
| `type=httpupgrade` | `path`        | HTTP Upgrade 需要路径 |
| `type=xhttp`       | `path`        | XHTTP 需要路径        |
| `type=splithttp`   | `path`        | SplitHTTP 需要路径    |

### 有效链接示例
✅ **带有 TLS 的 VLESS TCP：**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp`

✅ **带有 REALITY 的 VLESS gRPC：**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun`

✅ **VLESS WebSocket：**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path`

---

## VMess — 完整文档

### 规则结构
```yaml
vmess:
  required_params:
    - uuid
  forbidden_values:
    security: ["none"]
  allowed_values:
    net: ["tcp", "ws", "grpc", "httpupgrade", "h2", "xhttp", "splithttp"]
    security: ["auto", "aes-128-gcm", "chacha20-poly1305", "zero", "none"]
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

### 必需参数
| 参数     | 描述           |
|--------|--------------|
| `uuid` | 客户端 UUID（必需） |

### 允许的参数
| 参数         | 允许的值                                                           | 描述   |
|------------|----------------------------------------------------------------|------|
| `net`      | `tcp`, `ws`, `grpc`, `httpupgrade`, `h2`, `xhttp`, `splithttp` | 传输类型 |
| `security` | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `zero`, `none`     | 加密方法 |

### 禁止的参数
| 参数         | 禁止的值   | 原因        |
|------------|--------|-----------|
| `security` | `none` | 无加密 — 不安全 |

⚠️ **注意：** 为了向后兼容，`zero` 和 `none` 安全值包含在 `allowed_values` 中，但被放入 `forbidden_values` 中进行拒绝 — 即它们在事实上是被禁止的。

### 条件规则
| 条件                | 必需参数          | 描述                |
|-------------------|---------------|-------------------|
| `net=grpc`        | `serviceName` | gRPC 需要服务名称       |
| `net=ws`          | `path`        | WebSocket 需要路径    |
| `net=httpupgrade` | `path`        | HTTP Upgrade 需要路径 |
| `net=xhttp`       | `path`        | XHTTP 需要路径        |
| `net=splithttp`   | `path`        | SplitHTTP 需要路径    |

### 有效链接示例
✅ **带有 AES-128-GCM 的 VMess TCP：**
`vmess://uuid@example.com:10086?net=tcp&security=aes-128-gcm&tls=tls`

✅ **VMess WebSocket：**
`vmess://uuid@example.com:80?net=ws&security=auto&path=/api`

---

## Trojan — 完整文档

### 规则结构
```yaml
trojan:
  required_params:
    - password
  forbidden_values:
    flow: ["*"]  # 禁止任何 flow 值（参数在 Xray-core 2024+ 中已移除）
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

### 必需参数
| 参数         | 描述         |
|------------|------------|
| `password` | 身份验证密码（必需） |

### 允许的参数
| 参数         | 允许的值                                                     | 描述      |
|------------|----------------------------------------------------------|---------|
| `type`     | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp` | 传输类型    |
| `security` | `tls`, `reality`                                         | 安全类型    |
| `mode`     | `gun`, `multi`                                           | gRPC 模式 |

### 🔴 禁止的参数
| 参数     | 禁止的值         | 原因                       |
|--------|--------------|--------------------------|
| `flow` | 所有值（通配符 `*`） | ❌ 已在 Xray-core 2024+ 中移除 |

⚠️ **严重警告：** 现代版本的 Xray-core 不再支持 `flow` 参数。任何带有 `flow` 参数的 Trojan 配置将在过滤期间被自动拒绝。

### 条件规则
| 条件                 | 必需参数          | 描述                |
|--------------------|---------------|-------------------|
| `security=reality` | `pbk`         | REALITY 需要公钥      |
| `type=grpc`        | `serviceName` | gRPC 需要服务名称       |
| `type=ws`          | `path`        | WebSocket 需要路径    |
| `type=httpupgrade` | `path`        | HTTP Upgrade 需要路径 |
| `type=xhttp`       | `path`        | XHTTP 需要路径        |
| `type=splithttp`   | `path`        | SplitHTTP 需要路径    |

### 有效链接示例
✅ **带有 TLS 的 Trojan TCP：**
`trojan://password@example.com:443?security=tls&type=tcp`

✅ **Trojan gRPC：**
`trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun`

❌ **无效 — 包含被禁止的 `flow` 参数：**
`trojan://password@example.com:443?flow=xtls-rprx-vision` ← 被拒绝

---

## Shadowsocks (SS) — 完整文档

### 规则结构
```yaml
ss:
  required_params:
    - password
    - method
  forbidden_values:
    method:
      - "aes-128-cfb"
      - "aes-256-cfb"
      - "aes-128-ctr"
      - "aes-256-ctr"
  allowed_values:
    method:
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "xchacha20-poly1305"
      - "2022-blake3-aes-128-gcm"
      - "2022-blake3-aes-256-gcm"
      - "2022-blake3-chacha20-poly1305"
      - "none"
```

### 必需参数
| 参数         | 描述         |
|------------|------------|
| `password` | 身份验证密码（必需） |
| `method`   | 加密方法（必需）   |

### 允许的加密方法
✅ **AEAD 加密（现代标准）**
| 方法 | 建议 |
| --- | --- |
| `aes-128-gcm` | ✅ 支持，但安全性低于 256 位 |
| `aes-256-gcm` | ✅ **推荐** — 安全性与性能的良好平衡 |
| `chacha20-poly1305` | ✅ 支持，AES 的替代方案（对 CPU 友好） |
| `xchacha20-poly1305` | ✅ 支持，ChaCha20 的增强版本 |

✅ **Shadowsocks 2022（带有 Blake3 的新标准）**
| 方法 | 建议 |
| --- | --- |
| `2022-blake3-aes-128-gcm` | ✅ 支持（SS 2022 规范） |
| `2022-blake3-aes-256-gcm` | ✅ **推荐** — 最安全且最现代 |
| `2022-blake3-chacha20-poly1305` | ✅ 支持（SS 2022 规范） |

✅ **特殊方法**
| 方法 | 建议 |
| --- | --- |
| `none` | ⚠️ 无加密 — 极少使用，仅用于测试 |

### 🔴 禁止的方法（已在 Xray-core 2024+ 中移除）
| 方法            | 移除原因      |
|---------------|-----------|
| `aes-128-cfb` | ❌ 已弃用的流密码 |
| `aes-256-cfb` | ❌ 已弃用的流密码 |
| `aes-128-ctr` | ❌ 已弃用的流密码 |
| `aes-256-ctr` | ❌ 已弃用的流密码 |

⚠️ **严重警告：** Xray-core 2024+ 不再实现 CFB 和 CTR 方法。任何带有这些方法的 Shadowsocks 配置将在过滤期间被自动拒绝。

### 有效链接示例
✅ **推荐 — 带有 Blake3 的 SS 2022：**
`ss://2022-blake3-aes-256-gcm:password@example.com:8388`

✅ **带有 AES-256-GCM 的 Shadowsocks：**
`ss://aes-256-gcm:password@example.com:8388`

❌ **无效 — 包含已弃用的 CFB 方法：**
`ss://aes-256-cfb:password@example.com:8388` ← 被拒绝（方法已移除）

---

## Hysteria2 — 完整文档

### 规则结构
```yaml
hysteria2:
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

### 必需参数
| 参数              | 描述       |
|-----------------|----------|
| `obfs`          | 混淆方法（必需） |
| `obfs-password` | 混淆密码（必需） |

### 允许的参数
| 参数     | 允许的值         | 描述         |
|--------|--------------|------------|
| `obfs` | `salamander` | 唯一受支持的混淆方法 |

### 有效链接示例
✅ **带有混淆的 Hysteria2：**
`hy2://password@example.com:443?obfs=salamander&obfs-password=secret`

---

## 关键变更 (2026年2月)

### 🔴 Trojan：不再支持 `flow` 参数
**变更内容：**
- 在 Xray-core 2024+ 中，`flow` 参数已从 Trojan 协议中移除。
- 添加到 `rules.yaml`：`forbidden_values: { flow: ["*"] }`。
- 任何带有 `flow` 参数的 Trojan 配置都将被拒绝。

**被拒绝的链接示例：**
❌ `trojan://password@example.com:443?flow=xtls-rprx-vision`
❌ `trojan://password@example.com:443?type=tcp&flow=xtls-rprx-vision-udp443`

**应对措施：**
- 更新您的配置：从 URL 中删除 `flow` 参数。
- **正确的链接：**
  ✅ `trojan://password@example.com:443?security=tls&type=tcp`

### 🔴 Shadowsocks：不再支持 CFB 和 CTR 方法
**变更内容：**
- 在 Xray-core 2024+ 中，移除了 `aes-128-cfb`、`aes-256-cfb`、`aes-128-ctr` 和 `aes-256-ctr` 方法。
- 添加到 `rules.yaml`：`forbidden_values: { method: [aes-128-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr] }`。
- 任何带有这些方法的 Shadowsocks 配置都将被拒绝。

**被拒绝的链接示例：**
❌ `ss://aes-128-cfb:password@example.com:8388`
❌ `ss://aes-256-ctr:password@example.com:8388`

**推荐的方法：**
- **最佳选择：** `ss://2022-blake3-aes-256-gcm:password@example.com:8388`（现代标准）
- **替代方案：** `ss://aes-256-gcm:password@example.com:8388`（传统 AEAD）

**应对措施：**
- 更新您的配置：替换加密方法。
- **正确的链接：**
  ✅ `ss://2022-blake3-aes-256-gcm:password@example.com:8388`
  ✅ `ss://aes-256-gcm:password@example.com:8388`
  ✅ `ss://chacha20-poly1305:password@example.com:8388`

---

## 附加资源
- **Xray-core 规范：** https://xtls.github.io/
- **VLESS 规范：** https://github.com/XTLS/Xray-core/blob/main/features/inbound/vless/encoding.go
- **Trojan 规范：** https://trojan-gfw.github.io/
- **Shadowsocks 规范：** https://shadowsocks.org/

*文档版本：2.1 (2026年5月)*
*兼容性：Xray-core 2024+ (98%+)*
*最后更新：2026年5月31日*
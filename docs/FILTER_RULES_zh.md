[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md) / [ZH](FILTER_RULES_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

- [`rules.yaml` 文档](#rulesyaml-文档)
  - [文件结构](#文件结构)
  - [1. `required_params` — 必填参数](#1-required_params--必填参数)
  - [2. `allowed_values` — 允许的值](#2-allowed_values--允许的值)
  - [3. `forbidden_values` — 禁止的值](#3-forbidden_values--禁止的值)
  - [4. `conditional` — 条件规则](#4-conditional--条件规则)
  - [VLESS 的最新示例 (2026年2月)](#vless-的最新示例-2026年2月)
  - [验证细节](#验证细节)

## `rules.yaml` 文档

`rules.yaml` 文件是 `sub-filter` 程序的一套**规则**。这些规则定义了哪些代理链接被视为**有效且安全**，哪些是**无效**的并应被移除。

可以把 `sub-filter` 想象成一个**智能净水器**，而 `rules.yaml` 就是它的**使用说明书**：告诉它该去除哪些杂质，该放行哪些干净的水。

---

### 文件结构

文件按**协议**划分为多个**部分**。支持的协议有：

- `vless`
- `vmess`
- `trojan`
- `hysteria2`
- `ss`

每个部分可以包含**四种类型的规则**：

---

### 1. `required_params` — 必填参数

一个在链接中**必须存在**的参数列表。

- 如果缺少其中任何一个参数，该链接将被拒绝。
- **VLESS 示例：**
  ```yaml
  required_params: [encryption, sni]
  ```

---

### 2. `allowed_values` — 允许的值

为特定参数指定一个**允许的值**列表。

- 如果参数的值**不在列表中**，该链接将被拒绝。
- **示例：**
  ```yaml
  allowed_values:
    security: [tls, reality]
    type: [tcp, ws, httpupgrade, grpc, xhttp]
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
  ```

> ⚠️ 此规则**仅在参数存在时**应用。缺失的参数通过 `required_params` 进行检查。

---

### 3. `forbidden_values` — 禁止的值

为特定参数指定一个**禁止的值**列表。

- 如果参数的值**在列表中**，该链接将被拒绝。
- **此规则优先于 `allowed_values`**。
- **示例：**
  ```yaml
  forbidden_values:
    security: [none]
    authority: [""] # 阻止空的 authority
  ```

> ⚠️ 此规则会**全局禁止**所列的值。如果要允许例外情况（例如，仅对 `type=ws` 允许 `security=none`），请使用**条件规则**。

---

### 4. `conditional` — 条件规则

**仅在满足特定条件时**才应用的规则。

结构：
- `when` — 激活条件（所有条件都必须为真）
- `require` — 必填参数（如果条件满足）
- `forbidden_values` — 禁止的值（如果条件满足）

**示例：**
```yaml
conditional:
  # 如果 security=reality，则必须提供 pbk
  - when: { security: 'reality' }
    require: [pbk]

  # 如果 type=grpc，则必须提供 serviceName
  - when: { type: 'grpc' }
    require: [serviceName]

  # 如果 type 不是 ws，则禁止 security=none
  - when: { type: { not: 'ws' } }
    forbidden_values: { security: ['none'] }
```

---

### VLESS 的最新示例 (2026年2月)

```yaml
vless:
  required_params:
    - encryption
    - sni
  forbidden_values:
    security: [none]
    authority: [""] # 过滤 gRPC 中的常见错误
  allowed_values:
    security: [tls, reality]
    type: [tcp, ws, httpupgrade, grpc, xhttp] # 明确列出所有支持的传输方式
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
      - 'xtls-rprx-vision-direct'
    mode: [gun, multi] # gRPC 的官方模式
  conditional:
    - when: { security: 'reality' }
      require: [pbk]

    - when: { type: 'grpc' }
      require: [serviceName]

    - when: { type: 'ws' }
      require: [path]

    - when: { type: 'httpupgrade' }
      require: [path]

    - when: { type: 'xhttp' }
      require: [path]

    - when: { type: 'xhttp', mode: 'packet' }
      require: []
```

**说明：**

1. 所有 VLESS 链接都**必须**包含 `encryption` 和 `sni`。
2. `security` 参数只能是 `tls` 或 `reality`；`none` 被全局禁止。
3. 仅明确允许已知且受支持的传输方式 (`type`)。
4. 对于 `security=reality`，`pbk` 是必需的。
5. 对于 `type=grpc`，`serviceName` 是必需的。
6. 对于所有类 HTTP 传输 (`ws`, `httpupgrade`, `xhttp`)，`path` 是必需的。
7. 空的 `authority=` 参数（gRPC 中的常见错误）会被自动过滤掉。
8. `gRPC + REALITY` 的支持现在已是官方标准，规则已正确体现这一点 [[1]], [[10]]。

---

### 验证细节

- 对于 VLESS，如果 `security` 参数**缺失**，它将被**自动视为 `none`**。
- 规则**仅对存在的参数**应用。
- 检查顺序：  
  `forbidden_values` → `allowed_values` → `conditional`
- 所有值的比较都是**区分大小写**的（请使用规范中的确切值）。
- **无效的 `type` 值（例如 `raw`, `h2`, `kcp`）如果未在 `allowed_values.type` 中列出，将会被拒绝**。
- `mode` 参数仅对 `type=grpc` 有意义，但验证器会全局检查其值，因此重要的是只列出官方模式 (`gun`, `multi`)。

---

> 💡 **建议**：始终明确指定 `allowed_values.type`。这可以防止订阅生成器出错，并确保与现代客户端（Xray-core, Sing-box, Mihomo）的兼容性。
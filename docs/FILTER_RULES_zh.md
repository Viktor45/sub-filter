[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md) / [ZH](FILTER_RULES_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

- [`rules.yaml` 配置文档](#rulesyaml-配置文档)
  - [文件结构](#文件结构)
  - [1. `required_params` — 必需参数](#1-required_params--必需参数)
  - [2. `allowed_values` — 允许的值](#2-allowed_values--允许的值)
  - [3. `forbidden_values` — 禁止的值](#3-forbidden_values--禁止的值)
  - [4. `conditional` — 条件规则](#4-conditional--条件规则)
  - [VLESS 完整示例](#vless-完整示例)
  - [验证细节](#验证细节)

# `rules.yaml` 配置文档

`rules.yaml` 文件是 `sub-filter` 程序的**验证规则集**。它定义了哪些代理链接是**有效且安全的**，哪些是**无效的**并应被移除。

可以将 `sub-filter` 想象成一个**智能净水器**，而 `rules.yaml` 就是它的**使用说明书**：哪些杂质需要过滤掉，哪些干净的水可以放行。

---

### 文件结构

文件按**协议类型**划分为多个部分。支持的协议包括：

- `vless`
- `vmess`
- `trojan`
- `hysteria2`
- `ss`（Shadowsocks）

每个协议部分可包含**四种规则类型**：

---

### 1. `required_params` — 必需参数

指定链接中**必须存在的参数**列表。

- 如果**缺少任一必需参数**，该链接将被拒绝。
- **VLESS 示例：**
  ```yaml
  required_params: [encryption, sni]
  ```

---

### 2. `allowed_values` — 允许的值

指定某个参数的**合法取值范围**。

- 如果参数值**不在该列表中**，链接将被拒绝。
- **示例：**
  ```yaml
  allowed_values:
    security: [tls, reality]
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
  ```

> ⚠️ 此规则**仅在参数存在时生效**。缺失参数的检查由 `required_params` 负责。

---

### 3. `forbidden_values` — 禁止的值

指定某个参数的**非法取值列表**。

- 如果参数值**在此列表中**，链接将被拒绝。
- **优先级高于 `allowed_values`**。
- **示例：**
  ```yaml
  forbidden_values:
    security: [none]
  ```

> ⚠️ 此规则**全局禁止** `security=none`。  
> 若要**仅允许 `type=ws` 时使用 `security=none`**，请使用**条件规则**。

---

### 4. `conditional` — 条件规则

**仅在特定条件下**生效的规则。

结构说明：

- `when` — 触发条件（所有条件必须同时满足）
- `require` — 条件满足时的必需参数
- `forbidden_values` — 条件满足时的禁止值

**示例：**

```yaml
conditional:
  # 当 security=reality 时，必须包含 pbk
  - when: { security: 'reality' }
    require: [pbk]

  # 当 type=grpc 时，必须包含 serviceName
  - when: { type: 'grpc' }
    require: [serviceName]

  # 当 type 不是 ws 时，禁止 security=none
  - when: { type: { not: 'ws' } }
    forbidden_values: { security: ['none'] }
```

---

### VLESS 完整示例

```yaml
vless:
  required_params:
    - encryption
    - sni
  allowed_values:
    security: ['tls', 'reality']
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
  conditional:
    - when: { security: 'reality' }
      require: ['pbk']
    - when: { type: 'grpc' }
      require: ['serviceName']
    - when: { type: { not: 'ws' } }
      forbidden_values: { security: ['none'] }
```

**规则说明：**

1. **所有 VLESS 链接** 必须包含 `encryption` 和 `sni`。
2. `security` 参数**只能是** `tls` 或 `reality`。
3. 若 `security=reality`，**必须提供** `pbk`。
4. 若 `type=grpc`，**必须提供** `serviceName`。
5. **仅当 `type=ws` 时**，允许省略 `security`（程序会将其视为 `security=none`）。  
   其他所有连接类型**禁止使用 `security=none`**。

---

### 验证细节

- 在 VLESS 中，如果**未指定 `security` 参数**，程序会**自动将其视为 `none`**。
- 规则**仅对存在的参数生效**。
- 验证顺序：  
  `forbidden_values` → `allowed_values` → `conditional`
- 所有值的比较均为**区分大小写**（请使用协议规范中的精确值）。

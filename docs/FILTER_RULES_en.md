[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md) / [ZH](FILTER_RULES_zh.md)

This translation was made using AI.

- [Documentation for `rules.yaml`](#documentation-for-rulesyaml)
  - [File Structure](#file-structure)
  - [1. `required_params` — Required Parameters](#1-required_params--required-parameters)
  - [2. `allowed_values` — Allowed Values](#2-allowed_values--allowed-values)
  - [3. `forbidden_values` — Forbidden Values](#3-forbidden_values--forbidden-values)
  - [4. `conditional` — Conditional Rules](#4-conditional--conditional-rules)
  - [Up-to-Date Example for VLESS (February 2026)](#up-to-date-example-for-vless-february-2026)
  - [Validation Details](#validation-details)

## Documentation for `rules.yaml`

The `rules.yaml` file is a **set of rules** for the `sub-filter` program. These rules define which proxy links are considered **valid and secure**, and which are **invalid** and should be removed.

Think of `sub-filter` as a **smart water filter**, and `rules.yaml` as its **instruction manual**: what impurities to remove and what clean water to let through.

---

### File Structure

The file is divided into **sections by protocol**. Supported protocols are:

- `vless`
- `vmess`
- `trojan`
- `hysteria2`
- `ss`

Each section can contain **four types of rules**:

---

### 1. `required_params` — Required Parameters

A list of parameters that **must be present** in the link.

- If even one parameter is **missing**, the link is rejected.
- **Example for VLESS:**
  ```yaml
  required_params: [encryption, sni]
  ```

---

### 2. `allowed_values` — Allowed Values

A list of **permitted values** for a specific parameter.

- If the parameter's value is **not in the list**, the link is rejected.
- **Example:**
  ```yaml
  allowed_values:
    security: [tls, reality]
    type: [tcp, ws, httpupgrade, grpc, xhttp]
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
  ```

> ⚠️ This rule is applied **only if the parameter is present**. Missing parameters are checked via `required_params`.

---

### 3. `forbidden_values` — Forbidden Values

A list of **prohibited values** for a specific parameter.

- If the value **is in the list**, the link is rejected.
- **Takes precedence over `allowed_values`**.
- **Example:**
  ```yaml
  forbidden_values:
    security: [none]
    authority: [""] # blocks empty authority
  ```

> ⚠️ This rule **globally forbids** the specified values in all cases. To allow an exception (e.g., `security=none` only for `type=ws`), use **conditional rules**.

---

### 4. `conditional` — Conditional Rules

Rules that are applied **only when certain conditions are met**.

Structure:
- `when` — activation conditions (all must be true)
- `require` — required parameters (if the condition is met)
- `forbidden_values` — forbidden values (if the condition is met)

**Examples:**
```yaml
conditional:
  # If security=reality, pbk is mandatory
  - when: { security: 'reality' }
    require: [pbk]

  # If type=grpc, serviceName is mandatory
  - when: { type: 'grpc' }
    require: [serviceName]

  # If type is NOT ws, forbid security=none
  - when: { type: { not: 'ws' } }
    forbidden_values: { security: ['none'] }
```

---

### Up-to-Date Example for VLESS (February 2026)

```yaml
vless:
  required_params:
    - encryption
    - sni
  forbidden_values:
    security: [none]
    authority: [""] # filters out a common gRPC error
  allowed_values:
    security: [tls, reality]
    type: [tcp, ws, httpupgrade, grpc, xhttp] # explicitly lists all supported transports
    flow:
      - 'xtls-rprx-vision'
      - 'xtls-rprx-vision-udp443'
      - 'xtls-rprx-vision-direct'
    mode: [gun, multi] # official modes for gRPC
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

**Explanation:**

1. All VLESS links **must** have `encryption` and `sni`.
2. The `security` parameter can only be `tls` or `reality`; `none` is globally forbidden.
3. Only known and supported transports (`type`) are explicitly allowed.
4. For `security=reality`, `pbk` is mandatory.
5. For `type=grpc`, `serviceName` is mandatory.
6. For all HTTP-like transports (`ws`, `httpupgrade`, `xhttp`), `path` is mandatory.
7. An empty `authority=` parameter (a common gRPC mistake) is automatically filtered out.
8. Support for `gRPC + REALITY` is now official, and the rules correctly reflect this [[1]], [[10]].

---

### Validation Details

- For VLESS, if the `security` parameter is **missing**, it is **automatically treated as `none`**.
- Rules are applied **only to present parameters**.
- Order of checks:  
  `forbidden_values` → `allowed_values` → `conditional`
- All value comparisons are **case-sensitive** (use exact values from specifications).
- **Invalid `type` values (e.g., `raw`, `h2`, `kcp`) will be rejected** if they are not listed in `allowed_values.type`.
- The `mode` parameter is only relevant for `type=grpc`, but the validator checks its value globally, so it's important to list only official modes (`gun`, `multi`).

---

> 💡 **Recommendation**: Always explicitly specify `allowed_values.type`. This protects against subscription generator errors and ensures compatibility with modern clients (Xray-core, Sing-box, Mihomo).


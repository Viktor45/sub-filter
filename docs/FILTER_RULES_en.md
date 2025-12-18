[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md)  / [ZH](FILTER_RULES_zh.md) 

This translation was made using AI.

- [Documentation for `rules.yaml`](#documentation-for-rulesyaml)
    - [File Structure](#file-structure)
    - [1. `required_params` — Required Parameters](#1-required_params--required-parameters)
    - [2. `allowed_values` — Allowed Values](#2-allowed_values--allowed-values)
    - [3. `forbidden_values` — Forbidden Values](#3-forbidden_values--forbidden-values)
    - [4. `conditional` — Conditional Rules](#4-conditional--conditional-rules)
    - [Current Example for VLESS](#current-example-for-vless)
    - [Validation Details](#validation-details)


# Documentation for `rules.yaml`

The `rules.yaml` file is a **set of validation rules** for the `sub-filter` program. These rules define which proxy links are considered **valid and secure**, and which are **invalid** and must be removed.

Think of `sub-filter` as a **smart water filter**, and `rules.yaml` as its **instruction manual**: what impurities to remove and what clean water to let through.

---

### File Structure

The file is divided into **protocol-specific sections**. Supported protocols:

- `vless`
- `vmess`
- `trojan`
- `hysteria2`
- `ss` (Shadowsocks)

Each section may contain **four types of rules**:

---

### 1. `required_params` — Required Parameters

A list of parameters that **must be present** in the link.

- If **any required parameter is missing**, the link is rejected.
- **Example for VLESS:**
  ```yaml
  required_params: [encryption, sni]
  ```

---

### 2. `allowed_values` — Allowed Values

A list of **permitted values** for a specific parameter.

- If the parameter’s value is **not in this list**, the link is rejected.
- **Example:**
  ```yaml
  allowed_values:
    security: [tls, reality]
    flow:
      - "xtls-rprx-vision"
      - "xtls-rprx-vision-udp443"
  ```

> ⚠️ This rule **only applies if the parameter exists**. Missing parameters are checked only by `required_params`.

---

### 3. `forbidden_values` — Forbidden Values

A list of **prohibited values** for a specific parameter.

- If the value is **in this list**, the link is rejected.
- **Takes precedence over `allowed_values`**.
- **Example:**
  ```yaml
  forbidden_values:
    security: [none]
  ```

> ⚠️ This rule **globally forbids** `security=none` in all cases.  
> To allow `security=none` only for `type=ws`, use a **conditional rule**.

---

### 4. `conditional` — Conditional Rules

Rules that apply **only when specific conditions are met**.

Structure:
- `when` — activation conditions (all must be true)
- `require` — required parameters (if condition is met)
- `forbidden_values` — forbidden values (if condition is met)

**Examples:**
```yaml
conditional:
  # If security=reality, pbk is mandatory
  - when: { security: "reality" }
    require: [pbk]

  # If type=grpc, serviceName is mandatory
  - when: { type: "grpc" }
    require: [serviceName]

  # If type is NOT ws, forbid security=none
  - when: { type: { not: "ws" } }
    forbidden_values: { security: ["none"] }
```

---

### Current Example for VLESS

```yaml
vless:
  required_params:
    - encryption
    - sni
  allowed_values:
    security: ["tls", "reality"]
    flow:
      - "xtls-rprx-vision"
      - "xtls-rprx-vision-udp443"
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: { not: "ws" } }
      forbidden_values: { security: ["none"] }
```

**Explanation:**
1. **All VLESS links** must include `encryption` and `sni`.
2. The `security` parameter may only be `tls` or `reality`.
3. If `security=reality`, `pbk` **must be present**.
4. If `type=grpc`, `serviceName` **must be present**.
5. **Only for `type=ws`** is the absence of `security` allowed (interpreted as `security=none`).  
   For all other connection types, `security=none` is **forbidden**.

---

### Validation Details

- In VLESS, if the `security` parameter is **missing**, it is **automatically treated as `none`**.
- Rules apply **only to existing parameters**.
- Validation order:  
  `forbidden_values` → `allowed_values` → `conditional`
- All value comparisons are **case-sensitive** (use exact values from protocol specifications).

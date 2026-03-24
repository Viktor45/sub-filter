[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES.md) / [ZH](FILTER_RULES_zh.md)

This translation was made using AI.

<!-- TOC -->
* [Documentation for `rules.yaml`](#documentation-for-rulesyaml)
  * [Structure and Core Concepts](#structure-and-core-concepts)
  * [1. `required_params` — Required Parameters](#1-required_params--required-parameters)
  * [2. `allowed_values` — Allowed Values](#2-allowed_values--allowed-values)
  * [3. `forbidden_values` — Forbidden Values](#3-forbidden_values--forbidden-values)
  * [4. `conditional` — Conditional Rules](#4-conditional--conditional-rules)
  * [VLESS — Complete Documentation](#vless--complete-documentation)
    * [Rules Structure](#rules-structure)
    * [Required Parameters](#required-parameters)
    * [Allowed Parameters](#allowed-parameters)
    * [Forbidden Parameters](#forbidden-parameters)
    * [Conditional Rules](#conditional-rules)
    * [Examples of Valid Links](#examples-of-valid-links)
  * [VMess — Complete Documentation](#vmess--complete-documentation)
    * [Rules Structure](#rules-structure-1)
    * [Required Parameters](#required-parameters-1)
    * [Allowed Parameters](#allowed-parameters-1)
    * [Forbidden Parameters](#forbidden-parameters-1)
    * [Conditional Rules](#conditional-rules-1)
    * [Examples of Valid Links](#examples-of-valid-links-1)
  * [Trojan — Complete Documentation](#trojan--complete-documentation)
    * [Rules Structure](#rules-structure-2)
    * [Required Parameters](#required-parameters-2)
    * [Allowed Parameters](#allowed-parameters-2)
    * [🔴 Forbidden Parameters](#-forbidden-parameters)
    * [Conditional Rules](#conditional-rules-2)
    * [Examples of Valid Links](#examples-of-valid-links-2)
  * [Shadowsocks (SS) — Complete Documentation](#shadowsocks-ss--complete-documentation)
    * [Rules Structure](#rules-structure-3)
    * [Required Parameters](#required-parameters-3)
    * [Allowed Encryption Methods](#allowed-encryption-methods)
      * [✅ AEAD Methods (Modern Standard)](#-aead-methods-modern-standard)
      * [✅ Shadowsocks 2022 (New Standard with Blake3)](#-shadowsocks-2022-new-standard-with-blake3)
      * [✅ Special Method](#-special-method)
    * [🔴 Forbidden Methods (REMOVED in Xray-core 2024+)](#-forbidden-methods-removed-in-xray-core-2024)
    * [Examples of Valid Links](#examples-of-valid-links-3)
  * [Hysteria2 — Complete Documentation](#hysteria2--complete-documentation)
    * [Rules Structure](#rules-structure-4)
    * [Required Parameters](#required-parameters-4)
    * [Allowed Parameters](#allowed-parameters-3)
    * [Examples of Valid Links](#examples-of-valid-links-4)
  * [Critical Changes (February 2026)](#critical-changes-february-2026)
    * [🔴 Trojan: The `flow` parameter is no longer supported](#-trojan-the-flow-parameter-is-no-longer-supported)
    * [🔴 Shadowsocks: CFB and CTR methods are no longer supported](#-shadowsocks-cfb-and-ctr-methods-are-no-longer-supported)
  * [Additional Resources](#additional-resources)
<!-- TOC -->

# Documentation for `rules.yaml`

---

## Structure and Core Concepts

The file `config/rules.yaml` contains **validation rules** for all supported proxy protocols. These rules define which configurations are considered **valid** and which are subject to **rejection**.

The file is divided into **protocol-specific sections**:
- `vless` — VLESS protocol
- `vmess` — VMess protocol
- `trojan` — Trojan protocol
- `ss` — Shadowsocks protocol
- `hysteria2` — Hysteria2 protocol

---
## 1. `required_params` — Required Parameters

A list of parameters that **must be present** in the link.

**Behavior:**
- If even one parameter is **missing**, the link is **rejected**.
- This check is performed **first**, before all other rules.

**Example:**
```yaml
vless:
  required_params:
    - encryption
    - sni
```
**Interpretation:** A VLESS link must contain the `encryption` and `sni` parameters. If either is missing, the link will be rejected.

---
## 2. `allowed_values` — Allowed Values

A list of **permitted values** for a specific parameter.

**Behavior:**
- Checked **only if the parameter is present**.
- If the parameter's value is **not in the list**, the link is **rejected**.
- Comparison is **case-insensitive** (e.g., `aes-256-gcm` = `AES-256-GCM`).
- Priority: **lower than `forbidden_values`**.

**Example:**
```yaml
ss:
  allowed_values:
    method:
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "2022-blake3-aes-256-gcm"
```
**Interpretation:** Only these encryption methods are allowed for Shadowsocks. If another method is specified (e.g., `aes-128-cfb`), the link is rejected.

---
## 3. `forbidden_values` — Forbidden Values

A list of **prohibited values** for a specific parameter.

**Behavior:**
- Checked **only if the parameter is present**.
- If the value **is in the list**, the link is **rejected**.
- **Takes precedence over `allowed_values`** (checked first).
- Comparison is **case-insensitive**.
- Supports **wildcard** `"*"` — means **any** value for the parameter is forbidden.

**Examples:**
```yaml
vless:
  forbidden_values:
    security: ["none"]      # security=none is forbidden
    authority: [""]         # empty authority is forbidden
trojan:
  forbidden_values:
    flow: ["*"]             # ALL values for flow are forbidden (parameter is deprecated)
```
**Interpretation:**
- VLESS with `security=none` is rejected.
- Trojan with any `flow` value is rejected (the parameter was deprecated in Xray-core 2024+).

> ⚠️ **Important:** `forbidden_values` has a **global** scope. To allow an exception (e.g., `security=none` only for a specific type), use **conditional rules** `conditional`.

---
## 4. `conditional` — Conditional Rules

Rules that are applied **only when specific conditions are met**.

**Structure:**
```yaml
conditional:
  - when: { parameter: value }
    require: [list_of_required_parameters]
```
**Behavior:**
- Checked **after** `required_params`, `allowed_values`, and `forbidden_values`.
- The `when` condition acts as a logical AND (all conditions must be true).
- If the condition is met, the parameters in `require` become **mandatory**.

**Examples:**
```yaml
conditional:
  # If security=reality, pbk is mandatory
  - when: { security: "reality" }
    require: ["pbk"]
  # If type=grpc, serviceName is mandatory
  - when: { type: "grpc" }
    require: ["serviceName"]
  # If type=ws, path is mandatory
  - when: { type: "ws" }
    require: ["path"]
```
**Interpretation:**
- VLESS with `security=reality` must contain the `pbk` parameter.
- VLESS with `type=grpc` must contain the `serviceName` parameter.
- VLESS with `type=ws` must contain the `path` parameter.

---
## VLESS — Complete Documentation

### Rules Structure
```yaml
vless:
  required_params:
    - encryption
    - sni
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

### Required Parameters
| Parameter    | Description                        |
|--------------|------------------------------------|
| `encryption` | Encryption method (mandatory)      |
| `sni`        | Server Name Indication (mandatory) |

### Allowed Parameters
| Parameter  | Allowed Values                                                           | Description                          |
|------------|--------------------------------------------------------------------------|--------------------------------------|
| `security` | `tls`, `reality`                                                         | Security type. **Forbidden:** `none` |
| `type`     | `tcp`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `splithttp`                 | Transport type                       |
| `flow`     | `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, `xtls-rprx-vision-direct` | XTLS flow (REALITY only)             |
| `mode`     | `gun`, `multi`                                                           | gRPC mode                            |

### Forbidden Parameters
| Parameter   | Forbidden Values | Reason                      |
|-------------|------------------|-----------------------------|
| `security`  | `none`           | No security — insecure      |
| `authority` | `` (empty)       | Violates gRPC specification |

### Conditional Rules
| Condition          | Required Parameter | Description                   |
|--------------------|--------------------|-------------------------------|
| `security=reality` | `pbk`              | REALITY requires a public key |
| `type=grpc`        | `serviceName`      | gRPC requires a service name  |
| `type=ws`          | `path`             | WebSocket requires a path     |
| `type=httpupgrade` | `path`             | HTTP Upgrade requires a path  |
| `type=xhttp`       | `path`             | XHTTP requires a path         |
| `type=splithttp`   | `path`             | SplitHTTP requires a path     |

### Examples of Valid Links
✅ VLESS TCP with TLS:
```
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp
```
✅ VLESS gRPC with REALITY:
```
vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun
```
✅ VLESS WebSocket:
```
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path
```
---
## VMess — Complete Documentation

### Rules Structure
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

### Required Parameters
| Parameter | Description             |
|-----------|-------------------------|
| `uuid`    | Client UUID (mandatory) |

### Allowed Parameters
| Parameter  | Allowed Values                                                 | Description       |
|------------|----------------------------------------------------------------|-------------------|
| `net`      | `tcp`, `ws`, `grpc`, `httpupgrade`, `h2`, `xhttp`, `splithttp` | Transport type    |
| `security` | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `zero`, `none`     | Encryption method |

### Forbidden Parameters
| Parameter  | Forbidden Values | Reason                   |
|------------|------------------|--------------------------|
| `security` | `none`           | No encryption — insecure |

> ⚠️ **Note:** The `zero` and `none` values for security are included in `allowed_values` for **backward compatibility**, but are listed in `forbidden_values` for **rejection** — i.e., they are de facto prohibited.

### Conditional Rules
| Condition         | Required Parameter | Description                  |
|-------------------|--------------------|------------------------------|
| `net=grpc`        | `serviceName`      | gRPC requires a service name |
| `net=ws`          | `path`             | WebSocket requires a path    |
| `net=httpupgrade` | `path`             | HTTP Upgrade requires a path |
| `net=xhttp`       | `path`             | XHTTP requires a path        |
| `net=splithttp`   | `path`             | SplitHTTP requires a path    |

### Examples of Valid Links
✅ VMess TCP with AES-128-GCM:
```
vmess://uuid@example.com:10086?net=tcp&security=aes-128-gcm&tls=tls
```
✅ VMess WebSocket:
```
vmess://uuid@example.com:80?net=ws&security=auto&path=/api
```

---
## Trojan — Complete Documentation

### Rules Structure
```yaml
trojan:
  required_params:
    - password
  forbidden_values:
    flow: ["*"] # Any value for flow is forbidden (parameter removed in Xray-core 2024+)
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

### Required Parameters
| Parameter  | Description                         |
|------------|-------------------------------------|
| `password` | Authentication password (mandatory) |

### Allowed Parameters
| Parameter  | Allowed Values                                           | Description    |
|------------|----------------------------------------------------------|----------------|
| `type`     | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp` | Transport type |
| `security` | `tls`, `reality`                                         | Security type  |
| `mode`     | `gun`, `multi`                                           | gRPC mode      |

### 🔴 Forbidden Parameters
| Parameter | Forbidden Values              | Reason                           |
|-----------|-------------------------------|----------------------------------|
| `flow`    | **ALL** values (wildcard `*`) | ❌ **REMOVED in Xray-core 2024+** |

> ⚠️ **CRITICAL:** The `flow` parameter is **no longer supported** in modern versions of Xray-core. Any Trojan config containing the `flow` parameter will be **automatically rejected** during filtering.

### Conditional Rules
| Condition          | Required Parameter | Description                   |
|--------------------|--------------------|-------------------------------|
| `security=reality` | `pbk`              | REALITY requires a public key |
| `type=grpc`        | `serviceName`      | gRPC requires a service name  |
| `type=ws`          | `path`             | WebSocket requires a path     |
| `type=httpupgrade` | `path`             | HTTP Upgrade requires a path  |
| `type=xhttp`       | `path`             | XHTTP requires a path         |
| `type=splithttp`   | `path`             | SplitHTTP requires a path     |

### Examples of Valid Links
✅ Trojan TCP with TLS:
```
trojan://password@example.com:443?security=tls&type=tcp
```
✅ Trojan gRPC:
```
trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun
```
❌ **INVALID** — contains the forbidden `flow` parameter:
```
trojan://password@example.com:443?flow=xtls-rprx-vision  ← REJECTED
```

---
## Shadowsocks (SS) — Complete Documentation

### Rules Structure
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

### Required Parameters
| Parameter  | Description                         |
|------------|-------------------------------------|
| `password` | Authentication password (mandatory) |
| `method`   | Encryption method (mandatory)       |

### Allowed Encryption Methods
#### ✅ AEAD Methods (Modern Standard)
| Method               | Recommendation                                               |
|----------------------|--------------------------------------------------------------|
| `aes-128-gcm`        | ✅ Supported, but less secure than 256-bit                    |
| `aes-256-gcm`        | ✅ **RECOMMENDED** — good balance of security and performance |
| `chacha20-poly1305`  | ✅ Supported, an alternative to AES (per SP 800-38D)          |
| `xchacha20-poly1305` | ✅ Supported, a hardened version of ChaCha20                  |

#### ✅ Shadowsocks 2022 (New Standard with Blake3)
| Method                          | Recommendation                             |
|---------------------------------|--------------------------------------------|
| `2022-blake3-aes-128-gcm`       | ✅ Supported (SS 2022 specification)        |
| `2022-blake3-aes-256-gcm`       | ✅ **RECOMMENDED** — most secure and modern |
| `2022-blake3-chacha20-poly1305` | ✅ Supported (SS 2022 specification)        |

#### ✅ Special Method
| Method | Recommendation                                            |
|--------|-----------------------------------------------------------|
| `none` | ⚠️ No encryption — rarely used, only for testing purposes |

### 🔴 Forbidden Methods (REMOVED in Xray-core 2024+)
| Method        | Reason for Removal       |
|---------------|--------------------------|
| `aes-128-cfb` | ❌ Obsolete stream cipher |
| `aes-256-cfb` | ❌ Obsolete stream cipher |
| `aes-128-ctr` | ❌ Obsolete stream cipher |
| `aes-256-ctr` | ❌ Obsolete stream cipher |

> ⚠️ **CRITICAL:** CFB and CTR methods are **no longer implemented** in Xray-core 2024+. Any Shadowsocks config using these methods will be **automatically rejected** during filtering.

### Examples of Valid Links
✅ **RECOMMENDED** — SS 2022 with Blake3:
```
ss://2022-blake3-aes-256-gcm:password@example.com:8388
```
✅ Shadowsocks with AES-256-GCM:
```
ss://aes-256-gcm:password@example.com:8388
```
❌ **INVALID** — contains an obsolete CFB method:
```
ss://aes-256-cfb:password@example.com:8388  ← REJECTED (method removed)
```

---
## Hysteria2 — Complete Documentation

### Rules Structure
```yaml
hysteria2:
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

### Required Parameters
| Parameter       | Description                      |
|-----------------|----------------------------------|
| `obfs`          | Obfuscation method (mandatory)   |
| `obfs-password` | Obfuscation password (mandatory) |

### Allowed Parameters
| Parameter | Allowed Values | Description                           |
|-----------|----------------|---------------------------------------|
| `obfs`    | `salamander`   | The only supported obfuscation method |

### Examples of Valid Links
✅ Hysteria2 with obfuscation:
```
hy2://password@example.com:443?obfs=salamander&obfs-password=secret
```

---
## Critical Changes (February 2026)

### 🔴 Trojan: The `flow` parameter is no longer supported
**What changed:**
- In Xray-core 2024+, the `flow` parameter was **removed** from the Trojan protocol.
- In `rules.yaml`, this is enforced by: `forbidden_values: { flow: ["*"] }`.
- Any Trojan config with a `flow` parameter will be **rejected**.

**Examples of rejected links:**
```
❌ trojan://password@example.com:443?flow=xtls-rprx-vision
❌ trojan://password@example.com:443?type=tcp&flow=xtls-rprx-vision-udp443
```

**What to do:**
1.  **Update your configs:** Remove the `flow` parameter from the URL.
2.  **Correct link:**
```
✅ trojan://password@example.com:443?security=tls&type=tcp
```

---
### 🔴 Shadowsocks: CFB and CTR methods are no longer supported
**What changed:**
- In Xray-core 2024+, the methods `aes-128-cfb`, `aes-256-cfb`, `aes-128-ctr`, and `aes-256-ctr` were removed.
- In `rules.yaml`, this is enforced by: `forbidden_values: { method: [aes-128-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr] }`.
- Any Shadowsocks config with these methods will be **rejected**.

**Examples of rejected links:**
```
❌ ss://aes-128-cfb:password@example.com:8388
❌ ss://aes-256-ctr:password@example.com:8388
```

**Recommended methods:**
- **Best choice:** `ss://2022-blake3-aes-256-gcm:password@example.com:8388` (modern standard)
- **Alternative:** `ss://aes-256-gcm:password@example.com:8388` (traditional AEAD)

**What to do:**
1.  **Update your configs:** Replace the encryption method.
2.  **Correct links:**
```
✅ ss://2022-blake3-aes-256-gcm:password@example.com:8388
✅ ss://aes-256-gcm:password@example.com:8388
✅ ss://chacha20-poly1305:password@example.com:8388
```

---
## Additional Resources
- **Xray-core Specification:** https://xtls.github.io/
- **VLESS Specification:** https://github.com/XTLS/Xray-core/blob/main/features/inbound/vless/encoding.go
- **Trojan Specification:** https://trojan-gfw.github.io/
- **Shadowsocks Specification:** https://shadowsocks.org/

---
**Documentation Version:** 2.1 (February 2026)
**Compatibility:** Xray-core 2024+ (98%+)
**Last Updated:** February 4, 2026
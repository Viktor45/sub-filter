[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES.md) / [ZH](FILTER_RULES_zh.md)

This translation was made using AI.

<!-- TOC -->
* [Documentation for `rules.yaml`](#documentation-for-rulesyaml)
  * [Structure and Core Concepts](#structure-and-core-concepts)
    * [1. `required_params` — Mandatory Parameters](#1-required_params--mandatory-parameters)
    * [2. `allowed_values` — Permitted Values](#2-allowed_values--permitted-values)
    * [3. `forbidden_values` — Prohibited Values](#3-forbidden_values--prohibited-values)
    * [4. `conditional` — Conditional Rules](#4-conditional--conditional-rules)
  * [VLESS — Full Documentation](#vless--full-documentation)
    * [Rules Structure](#rules-structure)
    * [Mandatory Parameters](#mandatory-parameters)
    * [Permitted Parameters](#permitted-parameters)
    * [Prohibited Parameters](#prohibited-parameters)
    * [Conditional Rules](#conditional-rules)
    * [Examples of Valid Links](#examples-of-valid-links)
  * [VMess — Full Documentation](#vmess--full-documentation)
    * [Rules Structure](#rules-structure-1)
    * [Mandatory Parameters](#mandatory-parameters-1)
    * [Permitted Parameters](#permitted-parameters-1)
    * [Prohibited Parameters](#prohibited-parameters-1)
    * [Conditional Rules](#conditional-rules-1)
    * [Examples of Valid Links](#examples-of-valid-links-1)
  * [Trojan — Full Documentation](#trojan--full-documentation)
    * [Rules Structure](#rules-structure-2)
    * [Mandatory Parameters](#mandatory-parameters-2)
    * [Permitted Parameters](#permitted-parameters-2)
    * [🔴 Prohibited Parameters](#-prohibited-parameters)
    * [Conditional Rules](#conditional-rules-2)
    * [Examples of Valid Links](#examples-of-valid-links-2)
  * [Shadowsocks (SS) — Full Documentation](#shadowsocks-ss--full-documentation)
    * [Rules Structure](#rules-structure-3)
    * [Mandatory Parameters](#mandatory-parameters-3)
    * [Permitted Encryption Methods](#permitted-encryption-methods)
    * [🔴 Prohibited Methods (REMOVED in Xray-core 2024+)](#-prohibited-methods-removed-in-xray-core-2024)
    * [Examples of Valid Links](#examples-of-valid-links-3)
  * [Hysteria2 — Full Documentation](#hysteria2--full-documentation)
    * [Rules Structure](#rules-structure-4)
    * [Mandatory Parameters](#mandatory-parameters-4)
    * [Permitted Parameters](#permitted-parameters-3)
    * [Examples of Valid Links](#examples-of-valid-links-4)
  * [Critical Changes (February 2026)](#critical-changes-february-2026)
    * [🔴 Trojan: The `flow` parameter is no longer supported](#-trojan-the-flow-parameter-is-no-longer-supported)
    * [🔴 Shadowsocks: CFB and CTR methods are no longer supported](#-shadowsocks-cfb-and-ctr-methods-are-no-longer-supported)
  * [Additional Resources](#additional-resources)
<!-- TOC -->

# Documentation for `rules.yaml`

## Structure and Core Concepts
The `config/rules.yaml` file contains validation rules for all supported proxy protocols. These rules define which configurations are considered valid and which are subject to rejection.

The file is divided into protocol-specific sections:
- `vless` — VLESS protocol
- `vmess` — VMess protocol
- `trojan` — Trojan protocol
- `ss` — Shadowsocks protocol
- `hysteria2` — Hysteria2 protocol

### 1. `required_params` — Mandatory Parameters
A list of parameters that must be present in the link.

**Behavior:**
- If at least one parameter is missing, the link is rejected.
- This check is performed first, before all other rules.

**Example:**
```yaml
vless:
  required_params:
    - encryption
    - sni
```
**Interpretation:** A VLESS link must contain the `encryption` and `sni` parameters. If either is missing, the link will be rejected.

### 2. `allowed_values` — Permitted Values
A list of acceptable values for a specific parameter.

**Behavior:**
- Checked only if the parameter is present.
- If the parameter's value is not in the list, the link is rejected.
- Comparison is case-insensitive (`aes-256-gcm` = `AES-256-GCM`).
- Priority is lower than `forbidden_values`.

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
**Interpretation:** For Shadowsocks, only these encryption methods are allowed. If a different method is specified (e.g., `aes-128-cfb`), the link is rejected.

### 3. `forbidden_values` — Prohibited Values
A list of prohibited values for a specific parameter.

**Behavior:**
- Checked only if the parameter is present.
- If the value is in the list, the link is rejected.
- Takes precedence over `allowed_values` (checked first).
- Comparison is case-insensitive.
- Supports the wildcard `"*"` — prohibits any value for the parameter.

**Examples:**
```yaml
vless:
  forbidden_values:
    security: ["none"]      # security=none is prohibited
    authority: [""]         # empty authority is prohibited

trojan:
  forbidden_values:
    flow: ["*"]             # ALL flow values are prohibited (parameter completely removed)
```
**Interpretation:**
- VLESS with `security=none` is rejected.
- Trojan with any `flow` value is rejected (the parameter is deprecated in Xray-core 2024+).

⚠️ **Important:** `forbidden_values` has a global scope. To allow an exception (e.g., `security=none` only for a specific type), use `conditional` rules.

### 4. `conditional` — Conditional Rules
Rules that are applied only when specific conditions are met.

**Structure:**
```yaml
conditional:
  - when: { parameter: value }
    require: [list_of_mandatory_parameters]
```
**Behavior:**
- Checked after `required_params`, `allowed_values`, and `forbidden_values`.
- The `when` condition acts as a logical AND (all conditions must be true).
- If the condition is met, the parameters in `require` become mandatory.

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

## VLESS — Full Documentation

### Rules Structure
```yaml
vless:
  required_params:
    - sni
    # encryption is optional in URI, but explicitly specifying "none" is recommended for compatibility.
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

### Mandatory Parameters
| Parameter    | Description                                                                   |
|--------------|-------------------------------------------------------------------------------|
| `encryption` | Encryption method (optional, but explicitly specifying `none` is recommended) |
| `sni`        | Server Name Indication (mandatory for TLS/REALITY)                            |

### Permitted Parameters
| Parameter  | Allowed Values                                                           | Description                           |
|------------|--------------------------------------------------------------------------|---------------------------------------|
| `security` | `tls`, `reality`                                                         | Security type. **Prohibited:** `none` |
| `type`     | `tcp`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `splithttp`                 | Transport type                        |
| `flow`     | `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, `xtls-rprx-vision-direct` | XTLS flow (REALITY only)              |
| `mode`     | `gun`, `multi`                                                           | Mode for gRPC                         |

### Prohibited Parameters
| Parameter   | Prohibited Values | Reason                       |
|-------------|-------------------|------------------------------|
| `security`  | `none`            | No security — insecure       |
| `authority` | `""` (empty)      | Violates gRPC specifications |

🔎 If the `security` parameter is missing, it is automatically treated as `none` at the VLESS parser level and then rejected by the `forbidden_values` rules.

### Conditional Rules
| Condition          | Mandatory Parameter | Description                   |
|--------------------|---------------------|-------------------------------|
| `security=reality` | `pbk`               | REALITY requires a public key |
| `type=grpc`        | `serviceName`       | gRPC requires a service name  |
| `type=ws`          | `path`              | WebSocket requires a path     |
| `type=httpupgrade` | `path`              | HTTP Upgrade requires a path  |
| `type=xhttp`       | `path`              | XHTTP requires a path         |
| `type=splithttp`   | `path`              | SplitHTTP requires a path     |

### Examples of Valid Links
✅ **VLESS TCP with TLS:**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp`

✅ **VLESS gRPC with REALITY:**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun`

✅ **VLESS WebSocket:**
`vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path`

---

## VMess — Full Documentation

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

### Mandatory Parameters
| Parameter | Description             |
|-----------|-------------------------|
| `uuid`    | Client UUID (mandatory) |

### Permitted Parameters
| Parameter  | Allowed Values                                                 | Description       |
|------------|----------------------------------------------------------------|-------------------|
| `net`      | `tcp`, `ws`, `grpc`, `httpupgrade`, `h2`, `xhttp`, `splithttp` | Transport type    |
| `security` | `auto`, `aes-128-gcm`, `chacha20-poly1305`, `zero`, `none`     | Encryption method |

### Prohibited Parameters
| Parameter  | Prohibited Values | Reason                   |
|------------|-------------------|--------------------------|
| `security` | `none`            | No encryption — insecure |

⚠️ **Note:** The values `zero` and `none` for security are included in `allowed_values` for backward compatibility but are placed in `forbidden_values` for rejection — i.e., they are de facto prohibited.

### Conditional Rules
| Condition         | Mandatory Parameter | Description                  |
|-------------------|---------------------|------------------------------|
| `net=grpc`        | `serviceName`       | gRPC requires a service name |
| `net=ws`          | `path`              | WebSocket requires a path    |
| `net=httpupgrade` | `path`              | HTTP Upgrade requires a path |
| `net=xhttp`       | `path`              | XHTTP requires a path        |
| `net=splithttp`   | `path`              | SplitHTTP requires a path    |

### Examples of Valid Links
✅ **VMess TCP with AES-128-GCM:**
`vmess://uuid@example.com:10086?net=tcp&security=aes-128-gcm&tls=tls`

✅ **VMess WebSocket:**
`vmess://uuid@example.com:80?net=ws&security=auto&path=/api`

---

## Trojan — Full Documentation

### Rules Structure
```yaml
trojan:
  required_params:
    - password
  forbidden_values:
    flow: ["*"]  # Any flow value is prohibited (parameter removed in Xray-core 2024+)
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

### Mandatory Parameters
| Parameter  | Description                         |
|------------|-------------------------------------|
| `password` | Authentication password (mandatory) |

### Permitted Parameters
| Parameter  | Allowed Values                                           | Description    |
|------------|----------------------------------------------------------|----------------|
| `type`     | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp` | Transport type |
| `security` | `tls`, `reality`                                         | Security type  |
| `mode`     | `gun`, `multi`                                           | Mode for gRPC  |

### 🔴 Prohibited Parameters
| Parameter | Prohibited Values         | Reason                       |
|-----------|---------------------------|------------------------------|
| `flow`    | ALL values (wildcard `*`) | ❌ REMOVED in Xray-core 2024+ |

⚠️ **CRITICAL:** The `flow` parameter is no longer supported in modern versions of Xray-core. Any Trojan configuration with the `flow` parameter will be automatically rejected during filtering.

### Conditional Rules
| Condition          | Mandatory Parameter | Description                   |
|--------------------|---------------------|-------------------------------|
| `security=reality` | `pbk`               | REALITY requires a public key |
| `type=grpc`        | `serviceName`       | gRPC requires a service name  |
| `type=ws`          | `path`              | WebSocket requires a path     |
| `type=httpupgrade` | `path`              | HTTP Upgrade requires a path  |
| `type=xhttp`       | `path`              | XHTTP requires a path         |
| `type=splithttp`   | `path`              | SplitHTTP requires a path     |

### Examples of Valid Links
✅ **Trojan TCP with TLS:**
`trojan://password@example.com:443?security=tls&type=tcp`

✅ **Trojan gRPC:**
`trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun`

❌ **INVALID — contains the prohibited `flow` parameter:**
`trojan://password@example.com:443?flow=xtls-rprx-vision` ← REJECTED

---

## Shadowsocks (SS) — Full Documentation

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

### Mandatory Parameters
| Parameter  | Description                         |
|------------|-------------------------------------|
| `password` | Authentication password (mandatory) |
| `method`   | Encryption method (mandatory)       |

### Permitted Encryption Methods
✅ **AEAD Ciphers (Modern Standard)**
| Method | Recommendation |
| --- | --- |
| `aes-128-gcm` | ✅ Supported, but less secure than 256-bit |
| `aes-256-gcm` | ✅ **RECOMMENDED** — good balance of security and performance |
| `chacha20-poly1305` | ✅ Supported, alternative to AES (CPU-friendly) |
| `xchacha20-poly1305` | ✅ Supported, enhanced version of ChaCha20 |

✅ **Shadowsocks 2022 (New Standard with Blake3)**
| Method | Recommendation |
| --- | --- |
| `2022-blake3-aes-128-gcm` | ✅ Supported (SS 2022 specification) |
| `2022-blake3-aes-256-gcm` | ✅ **RECOMMENDED** — most secure and modern |
| `2022-blake3-chacha20-poly1305` | ✅ Supported (SS 2022 specification) |

✅ **Special Method**
| Method | Recommendation |
| --- | --- |
| `none` | ⚠️ No encryption — rarely used, only for testing |

### 🔴 Prohibited Methods (REMOVED in Xray-core 2024+)
| Method        | Reason for Removal         |
|---------------|----------------------------|
| `aes-128-cfb` | ❌ Deprecated stream cipher |
| `aes-256-cfb` | ❌ Deprecated stream cipher |
| `aes-128-ctr` | ❌ Deprecated stream cipher |
| `aes-256-ctr` | ❌ Deprecated stream cipher |

⚠️ **CRITICAL:** CFB and CTR methods are no longer implemented in Xray-core 2024+. Any Shadowsocks configuration with these methods will be automatically rejected during filtering.

### Examples of Valid Links
✅ **RECOMMENDED — SS 2022 with Blake3:**
`ss://2022-blake3-aes-256-gcm:password@example.com:8388`

✅ **Shadowsocks with AES-256-GCM:**
`ss://aes-256-gcm:password@example.com:8388`

❌ **INVALID — contains deprecated CFB method:**
`ss://aes-256-cfb:password@example.com:8388` ← REJECTED (method removed)

---

## Hysteria2 — Full Documentation

### Rules Structure
```yaml
hysteria2:
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

### Mandatory Parameters
| Parameter       | Description                      |
|-----------------|----------------------------------|
| `obfs`          | Obfuscation method (mandatory)   |
| `obfs-password` | Obfuscation password (mandatory) |

### Permitted Parameters
| Parameter | Allowed Values | Description                           |
|-----------|----------------|---------------------------------------|
| `obfs`    | `salamander`   | The only supported obfuscation method |

### Examples of Valid Links
✅ **Hysteria2 with Obfuscation:**
`hy2://password@example.com:443?obfs=salamander&obfs-password=secret`

---

## Critical Changes (February 2026)

### 🔴 Trojan: The `flow` parameter is no longer supported
**What changed:**
- In Xray-core 2024+, the `flow` parameter was removed from the Trojan protocol.
- Added to `rules.yaml`: `forbidden_values: { flow: ["*"] }`.
- Any Trojan configuration with the `flow` parameter will be rejected.

**Examples of rejected links:**
❌ `trojan://password@example.com:443?flow=xtls-rprx-vision`
❌ `trojan://password@example.com:443?type=tcp&flow=xtls-rprx-vision-udp443`

**What to do:**
- Update your configurations: remove the `flow` parameter from the URL.
- **Correct link:**
  ✅ `trojan://password@example.com:443?security=tls&type=tcp`

### 🔴 Shadowsocks: CFB and CTR methods are no longer supported
**What changed:**
- In Xray-core 2024+, the methods `aes-128-cfb`, `aes-256-cfb`, `aes-128-ctr`, and `aes-256-ctr` were removed.
- Added to `rules.yaml`: `forbidden_values: { method: [aes-128-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr] }`.
- Any Shadowsocks configuration with these methods will be rejected.

**Examples of rejected links:**
❌ `ss://aes-128-cfb:password@example.com:8388`
❌ `ss://aes-256-ctr:password@example.com:8388`

**Recommended methods:**
- **Best choice:** `ss://2022-blake3-aes-256-gcm:password@example.com:8388` (modern standard)
- **Alternative:** `ss://aes-256-gcm:password@example.com:8388` (traditional AEAD)

**What to do:**
- Update your configurations: replace the encryption method.
- **Correct links:**
  ✅ `ss://2022-blake3-aes-256-gcm:password@example.com:8388`
  ✅ `ss://aes-256-gcm:password@example.com:8388`
  ✅ `ss://chacha20-poly1305:password@example.com:8388`

---

## Additional Resources
- **Xray-core specification:** https://xtls.github.io/
- **VLESS specification:** https://github.com/XTLS/Xray-core/blob/main/features/inbound/vless/encoding.go
- **Trojan specification:** https://trojan-gfw.github.io/
- **Shadowsocks specification:** https://shadowsocks.org/

*Documentation Version: 2.1 (May 2026)*
*Compatibility: Xray-core 2024+ (98%+)*
*Last Updated: May 31, 2026*
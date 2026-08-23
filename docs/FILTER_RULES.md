[EN](FILTER_RULES.md) / [RU](ru/FILTER_RULES.md) / [ZH](zh/FILTER_RULES.md)

<!-- TOC -->
* [Validation rules (`rules.yaml`)](#validation-rules-rulesyaml)
  * [How validation works](#how-validation-works)
  * [Rule types](#rule-types)
    * [required_params](#required_params)
    * [allowed_values](#allowed_values)
    * [forbidden_values](#forbidden_values)
    * [conditional](#conditional)
  * [VLESS](#vless)
  * [VMess](#vmess)
  * [Trojan](#trojan)
  * [Shadowsocks](#shadowsocks)
  * [Hysteria2](#hysteria2)
  * [Tuning the strictness](#tuning-the-strictness)
  * [Notable rejections](#notable-rejections)
  * [References](#references)
<!-- TOC -->

# Validation rules (`rules.yaml`)

The file [`config/rules.yaml`](../config/rules.yaml) defines which proxy
configurations are considered valid and which are rejected. It is split into
per-protocol sections: `vless`, `vmess`, `trojan`, `ss`, `hysteria2`.

You can add your own rules or modify existing ones. Restart the filter after
editing the file.

## How validation works

Each protocol parser extracts the link parameters and hands them to a generic
rule engine (`internal/validator`). Checks run in this order:

1. **`required_params`** — every listed parameter must be present.
2. **`forbidden_values`** — if a listed parameter has a forbidden value, the
   link is rejected. Case-insensitive; the wildcard `"*"` forbids any value.
3. **`allowed_values`** — if a listed parameter is present, its value must be
   in the allow-list. Case-insensitive.
4. **`conditional`** — when all `when` conditions match, the `require`
   parameters become mandatory. Condition values are compared
   **case-sensitively** (they are logical conditions, not user input).

A link that fails any check is rejected and recorded in the
`rejected_*.txt` cache file with the reason.

> 📝 Some `required_params` entries in the bundled `rules.yaml` are commented
> out on purpose — the defaults are deliberately lenient ("security over
> quantity"). See [Tuning the strictness](#tuning-the-strictness).

## Rule types

### required_params

A list of parameters that must be present in the link.

```yaml
vless:
  required_params:
    - sni
```

If any parameter is missing, the link is rejected. This check runs first.

### allowed_values

Acceptable values for a parameter. Checked only when the parameter is present.

```yaml
ss:
  allowed_values:
    method:
      - "aes-256-gcm"
      - "chacha20-poly1305"
```

Comparison is case-insensitive (`aes-256-gcm` = `AES-256-GCM`). A value not in
the list rejects the link.

### forbidden_values

Prohibited values for a parameter. Checked only when the parameter is present.
Takes precedence over `allowed_values`.

```yaml
vless:
  forbidden_values:
    security: ["none"]      # security=none is prohibited
    authority: [""]         # empty authority is prohibited

trojan:
  forbidden_values:
    flow: ["*"]             # ANY flow value is prohibited
```

The wildcard `"*"` forbids the parameter with any value.

### conditional

Rules applied only when specific conditions are met:

```yaml
conditional:
  - when: { security: "reality" }
    require: ["pbk"]
  - when: { type: "grpc" }
    require: ["serviceName"]
```

All entries in `when` must match (logical AND); then every parameter in
`require` becomes mandatory.

---

## VLESS

```yaml
vless:
  required_params:
    - sni
    # encryption is optional in the URI; uncomment to require it
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

| Aspect      | Rule                                                                                                               |
|-------------|--------------------------------------------------------------------------------------------------------------------|
| Required    | `sni`                                                                                                              |
| `security`  | `tls` or `reality` only; `none` is forbidden. A missing `security` is treated as `none` by the parser and rejected |
| `type`      | `tcp`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `splithttp`                                                           |
| `flow`      | `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, `xtls-rprx-vision-direct`                                           |
| `mode`      | `gun`, `multi` (gRPC modes)                                                                                        |
| Conditional | `security=reality` → `pbk`; `type=grpc` → `serviceName`; `type=ws/httpupgrade/xhttp/splithttp` → `path`            |

**Valid examples:**

```text
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp
vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path
```

---

## VMess

```yaml
vmess:
  # uuid is not required by default (some implementations omit it);
  # uncomment to require it
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

| Aspect      | Rule                                                                                               |
|-------------|----------------------------------------------------------------------------------------------------|
| Required    | none by default (server address and UUID are still enforced by the parser itself)                  |
| `security`  | `auto`, `aes-128-gcm`, `chacha20-poly1305`; `none`, `zero`, `null` are **forbidden** (unencrypted) |
| `scy`       | `null` is forbidden                                                                                |
| `net`       | `tcp`, `ws`, `grpc`, `httpupgrade`, `h2`, `xhttp`, `splithttp`                                     |
| Conditional | `net=grpc` → `serviceName`; `net=ws/httpupgrade/xhttp/splithttp` → `path`                          |

> ⚠️ Unlike older rule sets, `zero` and `none` encryption are rejected, not
> tolerated.

---

## Trojan

```yaml
trojan:
  # password is not required by default; uncomment to require it
  # required_params:
  #   - password
  forbidden_values:
    flow: ["*"]   # flow was removed from Trojan in Xray-core 2024+
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

| Aspect      | Rule                                                                                                    |
|-------------|---------------------------------------------------------------------------------------------------------|
| Required    | none by default (the parser still requires a valid host/port)                                           |
| `flow`      | **forbidden with any value** — removed from Trojan in Xray-core 2024+                                   |
| `type`      | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp`                                                |
| `security`  | `tls`, `reality`                                                                                        |
| `mode`      | `gun`, `multi` (gRPC modes)                                                                             |
| Conditional | `security=reality` → `pbk`; `type=grpc` → `serviceName`; `type=ws/httpupgrade/xhttp/splithttp` → `path` |

**Valid examples:**

```text
trojan://password@example.com:443?security=tls&type=tcp
trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun
```

❌ Rejected — contains the removed `flow` parameter:

```text
trojan://password@example.com:443?flow=xtls-rprx-vision
```

---

## Shadowsocks

```yaml
ss:
  required_params:
    # password and method are not required by default;
    # uncomment to strengthen security
    # - password
    # - method
  forbidden_values:
    # deprecated stream ciphers (removed from Xray-core 2024+)
    method:
      - "aes-128-cfb"
      - "aes-256-cfb"
      - "aes-128-ctr"
      - "aes-256-ctr"
  allowed_values:
    method:
      # AEAD ciphers (modern standard)
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "xchacha20-poly1305"
      # Shadowsocks 2022 (Blake3)
      - "2022-blake3-aes-128-gcm"
      - "2022-blake3-aes-256-gcm"
      - "2022-blake3-chacha20-poly1305"
      # unencrypted; disabled by default
      # - "none"
```

| Aspect    | Rule                                                                                                                                                                         |
|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Required  | none by default (the parser still validates the cipher syntax)                                                                                                               |
| Allowed   | AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `xchacha20-poly1305`; SS2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| Forbidden | `aes-128-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-256-ctr` (removed from Xray-core 2024+)                                                                                    |
| `none`    | **not allowed** by default (commented out in the bundled rules)                                                                                                              |

**Recommended:** `2022-blake3-aes-256-gcm` (most secure and modern) or
`aes-256-gcm` (traditional AEAD).

```text
ss://2022-blake3-aes-256-gcm:password@example.com:8388   ✅
ss://aes-256-gcm:password@example.com:8388               ✅
ss://aes-256-cfb:password@example.com:8388               ❌ rejected (deprecated cipher)
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

| Aspect     | Rule                                                               |
|------------|--------------------------------------------------------------------|
| Required   | `obfs`, `obfs-password` (obfuscation is mandatory)                 |
| `obfs`     | `salamander` only                                                  |
| `insecure` | `1` / `true` are forbidden (certificate verification must stay on) |

**Valid example:**

```text
hy2://password@example.com:443?obfs=salamander&obfs-password=secret
```

---

## Tuning the strictness

The bundled rules are intentionally strict. You can adjust them:

- **Relax**: remove entries from `forbidden_values` or `conditional`.
- **Strengthen**: uncomment the `required_params` entries (`encryption` for
  VLESS, `uuid` for VMess, `password` for Trojan, `password`/`method` for SS)
  or re-enable the unencrypted `none` method for Shadowsocks.

Any change requires a restart to take effect.

## Notable rejections

These rejections follow upstream Xray-core changes and are the most common
reason public subscriptions lose entries:

| Protocol    | Rejected when                                   | Why                                                 |
|-------------|-------------------------------------------------|-----------------------------------------------------|
| VLESS       | `security=none` or missing `security`           | Unencrypted traffic                                 |
| VMess       | `security` is `none`/`zero`/`null`              | Unencrypted traffic                                 |
| Trojan      | any `flow` parameter                            | Removed from Trojan in Xray-core 2024+              |
| Shadowsocks | CFB/CTR ciphers                                 | Removed from Xray-core 2024+                        |
| Hysteria2   | missing `obfs`/`obfs-password`, or `insecure=1` | Obfuscation required; TLS verification must stay on |

## References

- Xray-core: https://xtls.github.io/
- Trojan: https://trojan-gfw.github.io/
- Shadowsocks: https://shadowsocks.org/

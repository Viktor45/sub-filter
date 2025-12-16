[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md)  / [ZH](FILTER_RULES_zh.md) 

This translation was made using AI.

# Proxy Validation Rules (`rules.yaml`)

The `rules.yaml` file lets you **flexibly control proxy filtering rules without recompiling the code**.  
All validation logic — including required parameters, forbidden values, and conditional dependencies — is now defined **exclusively in this file**.

> ⚠️ **Important**: If no policy is defined for a protocol, a **"null validator"** is used, which **allows everything**.  
> However, **basic structural validation** (host, port, UUID, password) remains hardcoded and **cannot be disabled**.

---

## 🧩 General Structure

```yaml
<protocol>:
  required_params: [list of mandatory query parameters]
  allowed_values:
    <parameter>: [allowed values]
  forbidden_values:
    <parameter>: [forbidden values]
  conditional:
    - when: { <parameter>: <value>, ... }
      require: [parameters required under this condition]
```

---

## ✅ Supported Protocols

### `vless`
- **Required**: `encryption`, `sni`
- **Forbidden**: `security=none`
- **Allowed**: `security=tls|reality`
- **`flow` values**: only permitted when `security=reality`
- **Conditional rules**:
  - `security=reality` → requires `pbk`
  - `type=grpc` → requires `serviceName`
  - `type=ws|httpupgrade|xhttp` → requires `path`

> 💡 The `encryption` field is retained for **backward compatibility**, even though modern VLESS links often omit it.

### `vmess`
- **Required**: `tls=tls`
- **Conditional**: if `net=grpc` → requires `serviceName`
- Note: other fields (`add`, `id`, `port`) are validated at the code level

### `hysteria2`
- **Required**: `obfs`, `obfs-password`
- **Allowed only**: `obfs: salamander`
- This aligns with the **original design intent** for public subscriptions

### `trojan`
- **Conditional**: if `type=grpc` → requires `serviceName`
- Password and host are validated in code

### `ss` (Shadowsocks)
- Policy is **empty** (`{}`), as Shadowsocks **does not use query parameters**
- All validation (cipher, password, host, port) is handled in code

---

## 🔧 Configuration Examples

### Allow VLESS without `encryption` (for legacy subscriptions)

```yaml
vless:
  required_params: [sni]  # removed 'encryption'
  allowed_values:
    security: ["tls", "reality"]
```

### Allow Hysteria2 with `obfs=none` (for internal networks)

```yaml
hysteria2:
  required_params: [obfs]  # 'obfs-password' not required when obfs=none
  allowed_values:
    obfs: ["salamander", "none"]
```

> ⚠️ If you allow `obfs=none`, ensure your handler **does not require `obfs-password`** — in the current implementation, this is **only enforced via policy**, so the configuration will be accepted.

---

## 📂 How to Use

1. Create `./config/rules.yaml` (see example in `./config/`)
2. Reference it in your main config:
   ```yaml
   rules_file: "./config/rules.yaml"
   ```
3. Launch with `--config config.yaml`

> If no file is specified, **built-in defaults** are used — but behavior **may differ** from expectations.  
> **It is strongly recommended to always provide an explicit `rules.yaml`** for predictable and controllable validation.

---

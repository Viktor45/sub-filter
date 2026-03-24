[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES.md) / [ZH](FILTER_RULES_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [`rules.yaml` 文件說明](#rulesyaml-文件說明)
  * [結構與核心概念](#結構與核心概念)
  * [1. `required_params` — 必填參數](#1-required_params--必填參數)
  * [2. `allowed_values` — 允許的值](#2-allowed_values--允許的值)
  * [3. `forbidden_values` — 禁止的值](#3-forbidden_values--禁止的值)
  * [4. `conditional` — 條件規則](#4-conditional--條件規則)
  * [---](#---)
    * [**Trojan — 完整文件**](#trojan--完整文件)
      * [規則結構](#規則結構)
      * [必填參數](#必填參數)
      * [允許的參數](#允許的參數)
      * [🔴 禁止的參數](#-禁止的參數)
      * [條件規則](#條件規則)
      * [有效連結範例](#有效連結範例)
    * [**Shadowsocks (SS) — 完整文件**](#shadowsocks-ss--完整文件)
      * [規則結構](#規則結構-1)
      * [必填參數](#必填參數-1)
      * [允許的加密方法](#允許的加密方法)
        * [✅ AEAD 方法（現代標準）](#-aead-方法現代標準)
        * [✅ Shadowsocks 2022（使用 Blake3 的新標準）](#-shadowsocks-2022使用-blake3-的新標準)
        * [✅ 特殊方法](#-特殊方法)
      * [🔴 禁止的方法（已在 Xray-core 2024+ 中移除）](#-禁止的方法已在-xray-core-2024-中移除)
      * [有效連結範例](#有效連結範例-1)
    * [**Hysteria2 — 完整文件**](#hysteria2--完整文件)
      * [規則結構](#規則結構-2)
      * [必填參數](#必填參數-2)
      * [允許的參數](#允許的參數-1)
      * [有效連結範例](#有效連結範例-2)
    * [**重大變更（2026 年 2 月）**](#重大變更2026-年-2-月)
      * [🔴 Trojan：`flow` 參數已不再支援](#-trojanflow-參數已不再支援)
      * [🔴 Shadowsocks：CFB 和 CTR 方法已不再支援](#-shadowsockscfb-和-ctr-方法已不再支援)
    * [**其他資源**](#其他資源)
<!-- TOC -->

# `rules.yaml` 文件說明

---
## 結構與核心概念

`config/rules.yaml` 文件包含所有支援代理協定的**驗證規則**。這些規則定義了哪些設定被視為**有效**，哪些將被**拒絕**。

該文件按**協定類型**分為以下幾個區塊：
- `vless` — VLESS 協定
- `vmess` — VMess 協定
- `trojan` — Trojan 協定
- `ss` — Shadowsocks 協定
- `hysteria2` — Hysteria2 協定

---
## 1. `required_params` — 必填參數

一個在連結中**必須存在**的參數列表。

**行為：**
- 如果缺少其中任何一個參數，該連結將被**拒絕**。
- 此檢查在所有其他規則之前**首先執行**。

**範例：**
```yaml
vless:
  required_params:
    - encryption
    - sni
```
**解讀：** VLESS 連結必須包含 `encryption` 和 `sni` 參數。如果缺少其中任何一個，該連結將被拒絕。

---
## 2. `allowed_values` — 允許的值

為特定參數指定一個**允許的值**列表。

**行為：**
- **僅在參數存在時**進行檢查。
- 如果參數的值**不在列表中**，該連結將被**拒絕**。
- 比較是**不區分大小寫**的（例如，`aes-256-gcm` = `AES-256-GCM`）。
- 優先順序：**低於 `forbidden_values`**。

**範例：**
```yaml
ss:
  allowed_values:
    method:
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "2022-blake3-aes-256-gcm"
```
**解讀：** Shadowsocks 僅允許這些加密方法。如果指定了其他方法（例如 `aes-128-cfb`），該連結將被拒絕。

---
## 3. `forbidden_values` — 禁止的值

為特定參數指定一個**禁止的值**列表。

**行為：**
- **僅在參數存在時**進行檢查。
- 如果該值**在列表中**，該連結將被**拒絕**。
- **優先於 `allowed_values`**（先進行此檢查）。
- 比較是**不區分大小寫**的。
- 支援**萬用字元** `"*"` — 表示禁止該參數的**任何**值。

**範例：**
```yaml
vless:
  forbidden_values:
    security: ["none"]      # 禁止 security=none
    authority: [""]         # 禁止空的 authority
trojan:
  forbidden_values:
    flow: ["*"]             # 禁止所有 flow 值（該參數已被棄用）
```
**解讀：**
- `security=none` 的 VLESS 將被拒絕。
- 任何帶有 `flow` 值的 Trojan 都會被拒絕（該參數已在 Xray-core 2024+ 中棄用）。

> ⚠️ **重要：** `forbidden_values` 具有**全域**作用域。若要允許例外情況（例如，僅對特定類型允許 `security=none`），請使用**條件規則** `conditional`。

---
## 4. `conditional` — 條件規則

**僅在滿足特定條件時**才應用的規則。

**結構：**
```yaml
conditional:
  - when: { parameter: value }
    require: [list_of_required_parameters]
```
**行為：**
- 在 `required_params`、`allowed_values` 和 `forbidden_values` **之後**進行檢查。
- `when` 條件的作用如同邏輯 AND（所有條件都必須為真）。
- 如果條件成立，`require` 中的參數將成為**必填項**。

**範例：**
```yaml
conditional:
  # 如果 security=reality，則 pbk 是必填的
  - when: { security: "reality" }
    require: ["pbk"]
  # 如果 type=grpc，則 serviceName 是必填的
  - when: { type: "grpc" }
    require: ["serviceName"]
  # 如果 type=ws，則 path 是必填的
  - when: { type: "ws" }
    require: ["path"]
```
**解讀：**
- `security=reality` 的 VLESS 必須包含 `pbk` 參數。
- `type=grpc` 的 VLESS 必須包含 `serviceName` 參數。
- `type=ws` 的 VLESS 必須包含 `path` 參數。

---
---

### **Trojan — 完整文件**

#### 規則結構
```yaml
trojan:
  required_params:
    - password
  forbidden_values:
    flow: ["*"]  # 任何 flow 值均被禁止（該參數已在 Xray-core 2024+ 中移除）
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

#### 必填參數
| 參數         | 說明       |
|------------|----------|
| `password` | 驗證密碼（必填） |

#### 允許的參數
| 參數         | 允許的值                                                     | 說明      |
|------------|----------------------------------------------------------|---------|
| `type`     | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp` | 傳輸類型    |
| `security` | `tls`, `reality`                                         | 安全類型    |
| `mode`     | `gun`, `multi`                                           | gRPC 模式 |

#### 🔴 禁止的參數
| 參數     | 禁止的值              | 原因                           |
|--------|-------------------|------------------------------|
| `flow` | **所有**值（萬用字元 `*`） | ❌ **已在 Xray-core 2024+ 中移除** |

> ⚠️ **嚴重警告：** `flow` 參數在現代版 Xray-core 中已**不再支援**。任何包含 `flow` 參數的 Trojan 設定都將在過濾時被**自動拒絕**。

#### 條件規則
| 條件                 | 必填參數          | 說明                |
|--------------------|---------------|-------------------|
| `security=reality` | `pbk`         | REALITY 需要公鑰      |
| `type=grpc`        | `serviceName` | gRPC 需要服務名稱       |
| `type=ws`          | `path`        | WebSocket 需要路徑    |
| `type=httpupgrade` | `path`        | HTTP Upgrade 需要路徑 |
| `type=xhttp`       | `path`        | XHTTP 需要路徑        |
| `type=splithttp`   | `path`        | SplitHTTP 需要路徑    |

#### 有效連結範例
✅ 使用 TLS 的 Trojan TCP：
```
trojan://password@example.com:443?security=tls&type=tcp
```
✅ Trojan gRPC：
```
trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun
```
❌ **無效** — 包含被禁止的 `flow` 參數：
```
trojan://password@example.com:443?flow=xtls-rprx-vision  ← 已拒絕
```

---
### **Shadowsocks (SS) — 完整文件**

#### 規則結構
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

#### 必填參數
| 參數         | 說明       |
|------------|----------|
| `password` | 驗證密碼（必填） |
| `method`   | 加密方法（必填） |

#### 允許的加密方法
##### ✅ AEAD 方法（現代標準）
| 方法                   | 建議                            |
|----------------------|-------------------------------|
| `aes-128-gcm`        | ✅ 支援，但安全性低於 256 位元            |
| `aes-256-gcm`        | ✅ **推薦** — 安全性與效能的良好平衡        |
| `chacha20-poly1305`  | ✅ 支援，AES 的替代方案（符合 SP 800-38D） |
| `xchacha20-poly1305` | ✅ 支援，ChaCha20 的強化版本           |

##### ✅ Shadowsocks 2022（使用 Blake3 的新標準）
| 方法                              | 建議                 |
|---------------------------------|--------------------|
| `2022-blake3-aes-128-gcm`       | ✅ 支援（SS 2022 規格）   |
| `2022-blake3-aes-256-gcm`       | ✅ **推薦** — 最安全且現代化 |
| `2022-blake3-chacha20-poly1305` | ✅ 支援（SS 2022 規格）   |

##### ✅ 特殊方法
| 方法     | 建議                    |
|--------|-----------------------|
| `none` | ⚠️ 無加密 — 很少使用，僅用於測試目的 |

#### 🔴 禁止的方法（已在 Xray-core 2024+ 中移除）
| 方法            | 移除原因       |
|---------------|------------|
| `aes-128-cfb` | ❌ 過時的串流加密法 |
| `aes-256-cfb` | ❌ 過時的串流加密法 |
| `aes-128-ctr` | ❌ 過時的串流加密法 |
| `aes-256-ctr` | ❌ 過時的串流加密法 |

> ⚠️ **嚴重警告：** CFB 和 CTR 方法在 Xray-core 2024+ 中已**不再實作**。任何使用這些方法的 Shadowsocks 設定都將在過濾時被**自動拒絕**。

#### 有效連結範例
✅ **推薦** — 使用 Blake3 的 SS 2022：
```
ss://2022-blake3-aes-256-gcm:password@example.com:8388
```
✅ 使用 AES-256-GCM 的 Shadowsocks：
```
ss://aes-256-gcm:password@example.com:8388
```
❌ **無效** — 包含過時的 CFB 方法：
```
ss://aes-256-cfb:password@example.com:8388  ← 已拒絕（方法已移除）
```

---
### **Hysteria2 — 完整文件**

#### 規則結構
```yaml
hysteria2:
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

#### 必填參數
| 參數              | 說明       |
|-----------------|----------|
| `obfs`          | 混淆方法（必填） |
| `obfs-password` | 混淆密碼（必填） |

#### 允許的參數
| 參數     | 允許的值         | 說明        |
|--------|--------------|-----------|
| `obfs` | `salamander` | 唯一支援的混淆方法 |

#### 有效連結範例
✅ 帶混淆的 Hysteria2：
```
hy2://password@example.com:443?obfs=salamander&obfs-password=secret
```

---
### **重大變更（2026 年 2 月）**

#### 🔴 Trojan：`flow` 參數已不再支援
**變更內容：**
- 在 Xray-core 2024+ 中，`flow` 參數已從 Trojan 協定中**移除**。
- 在 `rules.yaml` 中，透過 `forbidden_values: { flow: ["*"] }` 強制執行。
- 任何包含 `flow` 參數的 Trojan 設定都將被**拒絕**。

**被拒絕的連結範例：**
```
❌ trojan://password@example.com:443?flow=xtls-rprx-vision
❌ trojan://password@example.com:443?type=tcp&flow=xtls-rprx-vision-udp443
```

**應對措施：**
1.  **更新您的設定：** 從 URL 中移除 `flow` 參數。
2.  **正確的連結：**
```
✅ trojan://password@example.com:443?security=tls&type=tcp
```

---
#### 🔴 Shadowsocks：CFB 和 CTR 方法已不再支援
**變更內容：**
- 在 Xray-core 2024+ 中，已移除 `aes-128-cfb`、`aes-256-cfb`、`aes-128-ctr` 和 `aes-256-ctr` 方法。
- 在 `rules.yaml` 中，透過 `forbidden_values: { method: [aes-128-cfb, aes-256-cfb, aes-128-ctr, aes-256-ctr] }` 強制執行。
- 任何使用這些方法的 Shadowsocks 設定都將被**拒絕**。

**被拒絕的連結範例：**
```
❌ ss://aes-128-cfb:password@example.com:8388
❌ ss://aes-256-ctr:password@example.com:8388
```

**推薦方法：**
- **最佳選擇：** `ss://2022-blake3-aes-256-gcm:password@example.com:8388`（現代標準）
- **替代方案：** `ss://aes-256-gcm:password@example.com:8388`（傳統 AEAD）

**應對措施：**
1.  **更新您的設定：** 替換加密方法。
2.  **正確的連結：**
```
✅ ss://2022-blake3-aes-256-gcm:password@example.com:8388
✅ ss://aes-256-gcm:password@example.com:8388
✅ ss://chacha20-poly1305:password@example.com:8388
```

---
### **其他資源**
- **Xray-core 規格：** https://xtls.github.io/
- **VLESS 規格：** https://github.com/XTLS/Xray-core/blob/main/features/inbound/vless/encoding.go
- **Trojan 規格：** https://trojan-gfw.github.io/
- **Shadowsocks 規格：** https://shadowsocks.org/

---
**文件版本：** 2.1 (2026 年 2 月)
**相容性：** Xray-core 2024+ (98%+)
**最後更新日期：** 2026 年 2 月 4 日
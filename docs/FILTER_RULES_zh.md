[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md)  / [ZH](FILTER_RULES_zh.md) 

此翻译由神经网络完成，如有任何错误，敬请谅解。

# 代理验证规则（`rules.yaml`）

`rules.yaml` 文件让您**无需重新编译代码**，就能灵活控制代理链接的过滤规则。  
所有验证逻辑——包括哪些参数是必填的、哪些值被禁止、哪些参数之间存在依赖关系——现在都**只在这个文件中定义**。

> ⚠️ **注意**：如果某个协议**没有定义规则**，系统会使用一个**“空验证器”**，它会**允许所有配置**。  
> 但**基础结构验证**（如主机地址、端口、UUID、密码）仍由程序内部执行，**无法关闭**。

---

## 🧩 文件结构

```yaml
<协议名称>:
  required_params: [必填的查询参数列表]
  allowed_values:
    <参数名>: [允许的取值]
  forbidden_values:
    <参数名>: [禁止的取值]
  conditional:
    - when: { <参数名>: <值>, ... }
      require: [在此条件下必须提供的参数列表]
```

---

## ✅ 支持的协议

### `vless`
- **必填**：`encryption`、`sni`
- **禁止**：`security=none`
- **允许**：`security=tls` 或 `security=reality`
- **流控（`flow`）**：仅在 `security=reality` 时可用
- **条件依赖**：
  - `security=reality` → 必须提供 `pbk`
  - `type=grpc` → 必须提供 `serviceName`
  - `type=ws|httpupgrade|xhttp` → 必须提供 `path`

> 💡 `encryption` 字段为**向后兼容**而保留，尽管现代 VLESS 链接通常省略它。

### `vmess`
- **必填**：`tls=tls`
- **条件**：若 `net=grpc` → 必须提供 `serviceName`
- 其他字段（如 `add`、`id`、`port`）由程序内部验证

### `hysteria2`
- **必填**：`obfs`、`obfs-password`
- **仅允许**：`obfs: salamander`
- 此设计符合**公共订阅**的原始使用场景

### `trojan`
- **条件**：若 `type=grpc` → 必须提供 `serviceName`
- 密码和主机地址由程序验证

### `ss`（Shadowsocks）
- 规则为空（`{}`），因为 Shadowsocks **不使用查询参数**
- 所有验证（加密方式、密码、主机、端口）均在程序内部完成

---

## 🔧 配置示例

### 允许不含 `encryption` 的 VLESS（用于旧订阅）

```yaml
vless:
  required_params: [sni]  # 不再要求 encryption
  allowed_values:
    security: ["tls", "reality"]
```

### 允许 `obfs=none` 的 Hysteria2（用于内网）

```yaml
hysteria2:
  required_params: [obfs]  # 当 obfs=none 时，obfs-password 非必需
  allowed_values:
    obfs: ["salamander", "none"]
```

> ⚠️ 如果允许 `obfs=none`，请确保您的处理程序**不要求 `obfs-password`** —— 当前实现中，该检查**仅通过规则策略执行**，因此上述配置会被接受。

---

## 📂 使用方法

1. 创建文件 `./config/rules.yaml`（参考 `./config/` 中的示例）
2. 在主配置中指定路径：
   ```yaml
   rules_file: "./config/rules.yaml"
   ```
3. 启动时使用：`--config config.yaml`

> 若未指定规则文件，程序将使用**内置默认规则**，但行为**可能不符合预期**。  
> **强烈建议始终显式提供 `rules.yaml`**，以便完全掌控验证逻辑。
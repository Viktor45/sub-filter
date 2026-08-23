[EN](../BADWORDS.md) / [RU](../ru/BADWORDS.md) / [ZH](BADWORDS.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [「违禁词」规则（`badwords.yaml`）](#违禁词规则badwordsyaml)
  * [什么是「违禁词」？](#什么是违禁词)
  * [文件结构](#文件结构)
  * [动作](#动作)
    * [strip](#strip)
    * [delete](#delete)
    * [replace](#replace)
  * [规则应用位置](#规则应用位置)
  * [安全限制](#安全限制)
  * [正则表达式](#正则表达式)
    * [YAML 转义](#yaml-转义)
    * [不区分大小写的匹配](#不区分大小写的匹配)
  * [实用示例](#实用示例)
  * [模式编写技巧](#模式编写技巧)
  * [调试](#调试)
<!-- TOC -->

# 「违禁词」规则（`badwords.yaml`）

文件 [`config/badwords.yaml`](../../config/badwords.yaml) 包含用于清理代理
**名称**（链接片段）的规则，对于 `replace` 则作用于整个链接。可以把它理解
为一本「违禁词」词典——目的不是审查，而是从服务器名称中移除无用、推广性
或危险的信息。

## 什么是「违禁词」？

出现在代理名称中、且不希望出现在最终列表里的模式（单词、短语或正则
表达式）。示例：

- `[TEST]` — 测试服务器标记
- `[SPAM]` — 明确的垃圾信息标记
- `192.168.x.x` — 私有 IP，解析错误的迹象
- `v1.2.3` — 使名称杂乱的版本号

## 文件结构

文件是一个 YAML 规则数组：

```yaml
- pattern: "从名称中切除的正则"
  action: strip

- pattern: "拒绝整行的正则"
  action: delete

- pattern: "fp=chrome"
  action: replace
  replacement: "fp=firefox"
```

| 字段          | 类型   | 是否必需        | 说明                                     |
| ------------- | ------ | --------------- | ---------------------------------------- |
| `pattern`     | 字符串 | ✅ 是           | 正则表达式（Go `regexp` 语法）           |
| `action`      | 字符串 | ✅ 是           | `strip`、`delete` 或 `replace`           |
| `replacement` | 字符串 | `replace` 必需  | 替换字符串                               |
| `comment`     | 字符串 | 否              | 自由格式的备注（程序忽略）               |

未知或缺失的 `action` 按 `delete` 处理。

## 动作

### strip

从名称中移除匹配的子串；服务器**保留**在列表中。移除后会合并多余空格并
修剪名称两端。

用于轻微垃圾信息：版本号（`v1.2.3`）、test/demo 标记、广告尾巴。

```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: strip
```

`"Server v1.2.3 Fast"` → `"Server Fast"` ✅ 接受

### delete

拒绝**整行**；服务器被排除出列表，并连同匹配的规则作为原因记录在
`rejected_*.txt` 中。

用于严重问题：垃圾/恶意软件标记、私有 IP、无效端口。

```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: delete
```

`"Server [SPAM] in US"` → ❌ 拒绝

### replace

用 `replacement` 字符串替换匹配内容；服务器保留在列表中。与 `strip`/
`delete`（作用于解码后的名称）不同，`replace` 作用于**整个规范化链接**，
因此可以修正 URL 中任意位置的参数。

```yaml
- pattern: "fp=chrome"
  action: replace
  replacement: "fp=firefox"
```

## 规则应用位置

- `strip` 和 `delete` 在协议处理期间作用于每条链接的 **URL 解码后的片段**
  （`#名称` 部分）。
- `replace` 在协议处理之后、国家过滤之前作用于**完整的规范化链接**。

## 安全限制

模式在启动时编译一次，并带有保护性限制：

- 最多使用 **20 个模式**（超出部分会被忽略并给出警告）；
- 超过 **100 个字符**的模式会被跳过；
- 含有易导致 ReDoS 的嵌套量词（例如 `(.*)+`）或捕获组超过 3 个的模式
  会被拒绝；
- 无效的正则会被跳过（记录日志）。

## 正则表达式

`sub-filter` 使用 Go 的 `regexp` 包（RE2 语法）。

### YAML 转义

YAML 本身会解释双引号字符串中的反斜杠，因此要么将其双写，要么使用
单引号：

```yaml
# 错误 — YAML 会吃掉一个反斜杠：
pattern: "\[TEST\]"

# 正确 — 双写反斜杠：
pattern: "\\[TEST\\]"

# 正确 — 单引号，无需 YAML 转义：
pattern: '\[TEST\]'
```

### 不区分大小写的匹配

在模式开头添加内联标志 `(?i)`：

```yaml
- pattern: '(?i)\[demo\]'   # 匹配 [DEMO]、[demo]、[Demo]
  action: strip
```

## 实用示例

移除版本号：

```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: strip
```

移除任意括号风格的 demo 标记：

```yaml
- pattern: '(?i)\[demo\]|\(demo\)|<demo>'
  action: strip
```

拒绝含私有 IP 的行（解析错误的迹象）：

```yaml
- pattern: '(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)'
  action: delete
```

拒绝垃圾/欺诈/恶意软件标记：

```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: delete
```

拒绝无效端口（0 或 > 65535）：

```yaml
- pattern: ':(?:0|6553[6-9]|655[4-9]\d|65[6-9]\d{2}|6[6-9]\d{3}|[7-9]\d{4}|[1-9]\d{5,})'
  action: delete
```

## 模式编写技巧

- 对完整单词使用单词边界：`\btest\b` 匹配 `test` 但不匹配 `testing`。
- 转义特殊字符：`\[TEST\]`、`example\.com`。
- 优先使用 `(?i)`，而不是列举每种大小写变体。
- 对备选项分组：`(?i)(spam|fraud|malware)`。
- `delete` 规则要严格，`strip` 规则要谨慎——过于宽泛的 `delete` 模式会
  悄无声息地删掉好的服务器。
- 按逻辑排列规则：先 `strip`（清理），后 `delete`（拦截）。

## 调试

- 在 [regex101.com](https://regex101.com) 上用 **Go** 方言测试模式。
- 运行 `./sub-filter --cli`——如果文件能解析，配置即加载成功；无效模式
  会记录到日志并被跳过。
- 检查缓存目录中的 `rejected_<id>.txt`：每条被拒绝的行都连同原因保存在
  那里，包括命中的「违禁词」规则。

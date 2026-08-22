[EN](../en/FORMAT_PARAMETER_en.md) / [RU](../FORMAT_PARAMETER.md) / [ZH](FORMAT_PARAMETER_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
* [`format` 参数文档](#format-参数文档)
  * [概述](#概述)
  * [支持的格式](#支持的格式)
    * [1. 默认格式（纯文本）](#1-默认格式纯文本)
    * [2. YAML 格式](#2-yaml-格式)
    * [3. Base64 编码](#3-base64-编码)
    * [4. 组合格式](#4-组合格式)
      * [YAML + Base64](#yaml--base64)
  * [使用示例](#使用示例)
    * [使用默认格式的基本过滤](#使用默认格式的基本过滤)
    * [为 Clash 过滤为 YAML](#为-clash-过滤为-yaml)
    * [将多个源合并为 YAML](#将多个源合并为-yaml)
    * [Base64 编码的 YAML（用于嵌入配置）](#base64-编码的-yaml用于嵌入配置)
    * [带国家代码和格式的过滤](#带国家代码和格式的过滤)
  * [与客户端集成](#与客户端集成)
    * [Clash / Mihomo](#clash--mihomo)
    * [用于嵌入的 Base64](#用于嵌入的-base64)
  * [查询参数参考](#查询参数参考)
  * [故障排除](#故障排除)
    * [YAML 格式问题](#yaml-格式问题)
    * [Base64 解码问题](#base64-解码问题)
  * [性能注意事项](#性能注意事项)
  * [兼容性](#兼容性)
<!-- TOC -->

# `format` 参数文档

## 概述
`format=` 参数允许您将 `/filter` 和 `/merge` 端点的代理列表响应转换为适合各种客户端的不同格式。

## 支持的格式

### 1. 默认格式（纯文本）
当未指定 `format` 参数或参数为空时，响应每行包含一个代理 URL。

**示例：**
```
/filter?id=1
```

**输出：**
```
ss://example.com:8388#proxy1
vless://example.com:443#proxy2
trojan://example.com:443#proxy3
```

| 参数         | 值                          |
| ------------ | --------------------------- |
| Content-Type | `text/plain; charset=utf-8` |
| 文件扩展名   | `.txt`                      |

### 2. YAML 格式
指定 `format=yaml` 会将代理列表转换为与 **Clash** 和 **Mihomo** 客户端兼容的 YAML 格式。

**示例：**
```
/filter?id=1&format=yaml
/merge?ids=1,2&format=yaml
```

**输出：**
```yaml
proxies:
  - name: "example.com-0"
    url: "ss://example.com:8388#proxy1"
  - name: "example.com-1"
    url: "vless://example.com:443#proxy2"
  - name: "example.com-2"
    url: "trojan://example.com:443#proxy3"
```

| 参数         | 值                                  |
| ------------ | ----------------------------------- |
| Content-Type | `application/x-yaml; charset=utf-8` |
| 文件扩展名   | `.yaml`                             |

📌 **注意：** 代理名称自动从以下位置提取：
- URL 片段（例如 `#name=MyProxy`）
- 查询参数（`remark=`、`desc=`）
- URL 中的主机名
- 如果以上都不可用，则生成为 `proxy-N`

### 3. Base64 编码
指定 `format=base64` 会将响应编码为 base64。可以与其他格式组合使用。

**示例：**
```
/filter?id=1&format=base64
```

**输出：**
```
c3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MQp2bGVzczo...
```

| 参数         | 值                         |
| ------------ | -------------------------- |
| Content-Type | `application/octet-stream` |
| 文件扩展名   | `.b64`                     |

### 4. 组合格式
您可以使用 `+` 分隔符组合格式，或用逗号分隔。格式按指定顺序应用。

**示例：**

#### YAML + Base64
```
/filter?id=1&format=yaml+base64
```
首先转换为 YAML，然后将结果编码为 base64。

**输出：**
```
cHJveGllczoKICAtIG5hbWU6ICJleGFtcGxlLmNvbS0wIgogICAgdXJsOiAic3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MSI=
```

| 参数         | 值                         |
| ------------ | -------------------------- |
| Content-Type | `application/octet-stream` |
| 文件扩展名   | `.yaml.b64`                |

## 使用示例

### 使用默认格式的基本过滤
```bash
curl "http://localhost:8080/filter?id=1&c=US,JP"
```

### 为 Clash 过滤为 YAML
```bash
curl "http://localhost:8080/filter?id=1&format=yaml" | cat > profile.yaml
```

### 将多个源合并为 YAML
```bash
curl "http://localhost:8080/merge?ids=1,2&format=yaml"
```

### Base64 编码的 YAML（用于嵌入配置）
```bash
curl "http://localhost:8080/filter?id=1&format=yaml+base64"
```

### 带国家代码和格式的过滤
```bash
curl "http://localhost:8080/filter?id=1&c=US,JP,CN&format=yaml"
```

## 与客户端集成

### Clash / Mihomo
使用 `format=yaml` 获取与 Clash 和 Mihomo 兼容的 YAML 输出：
```bash
curl "http://localhost:8080/filter?id=1&format=yaml" > clash-proxy.yaml
```
然后在您的 Clash 配置中导入此 YAML 文件。

### 用于嵌入的 Base64
当您需要将代理列表嵌入到期望 base64 编码数据的其他配置或工具中时：
```bash
# 获取 base64 编码的纯文本代理
ENCODED=$(curl "http://localhost:8080/filter?id=1&format=base64")

# 获取 base64 编码的 YAML
YAML_ENCODED=$(curl "http://localhost:8080/filter?id=1&format=yaml+base64")
```

## 查询参数参考

| 参数     | 值                                             | 示例           |
| -------- | ---------------------------------------------- | -------------- |
| `format` | `yaml`、`base64`、`yaml+base64`、`base64+yaml` | `?format=yaml` |
| `id`     | 源 ID                                          | `?id=1`        |
| `ids`    | 逗号分隔的源 ID                                | `?ids=1,2`     |
| `c`      | 国家代码                                       | `?c=US,JP`     |
| `lim`    | 行数限制                                       | `?lim=100`     |

## 故障排除

### YAML 格式问题
- `format` 参数会被验证：无效值（例如 `json`）将返回 `400 Bad Request`
- YAML 输出包含结构化的代理字段（`server`、`port`、`password`、`uuid` 等），适用于 Clash/Mihomo
- 注释、空行以及不受支持的协议（除 `ss`、`vless`、`vmess`、`trojan`、`hy2`/`hysteria2` 之外的所有协议）将被忽略
- 如果没有剩余代理，将返回最小文档 `proxies: []`

### Base64 解码问题
- 使用标准 base64 解码器：Linux/Mac 上的 `base64 -d` 或 Python 的 `base64` 模块
- 确保在传输过程中未添加换行符
- base64 响应的 Content-Type 为 `application/octet-stream`

## 性能注意事项
- YAML 转换增加的开销很小，因为它只遍历一次行
- Base64 编码会使响应大小增加约 **33%**
- 组合格式按顺序应用转换
- 所有响应仍受速率限制和大小限制的约束

## 兼容性

| 格式       | 兼容性                                              |
| ---------- | --------------------------------------------------- |
| **YAML**   | 与 Clash、Mihomo 及其他接受 YAML 代理列表的工具兼容 |
| **Base64** | 与任何期望 base64 编码数据的工具兼容                |
| **默认**   | 与所有现有客户端和工具兼容                          |
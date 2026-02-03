[EN](README_en.md) / [RU](README.md) / [ZH](README_zh.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

- [sub-filter](#sub-filter)
  - [✨ 功能特性](#-功能特性)
  - [🛠️ 编译说明](#️-编译说明)
  - [▶️ 使用方法](#️-使用方法)
    - [1. HTTP 服务器模式（动态过滤）](#1-http-服务器模式动态过滤)
      - [语法：](#语法)
      - [示例：](#示例)
      - [接口说明：](#接口说明)
    - [2. CLI 模式（一次性处理）](#2-cli-模式一次性处理)
      - [语法：](#语法-1)
      - [参数：](#参数)
      - [示例：](#示例-1)
  - [🌍 国家过滤](#-国家过滤)
    - [国家数据格式](#国家数据格式)
  - [🔤 参数说明](#-参数说明)
  - [🖥️ CLI 参数](#️-cli-参数)
  - [✅ 快速测试](#-快速测试)
    - [服务器模式](#服务器模式)
    - [CLI 模式](#cli-模式)
  - [📲 客户端集成](#-客户端集成)
  - [🐳 Docker](#-docker)
    - [启动服务器](#启动服务器)
    - [CLI 模式（Docker）](#cli-模式docker)

# sub-filter

一款智能代理订阅过滤器，支持 **VLESS、VMess、Trojan、Shadowsocks 和 Hysteria2**。

本工具会逐条验证订阅中的代理链接，确保：

- **安全性**（例如：阻止 VLESS 中的 `security=none`），
- **配置正确性**（例如：当 `security=reality` 时，必须包含 `pbk`），
- **基于规则的禁用（不良）关键词过滤**，
- **按国家、国旗或本地名称过滤**。

最终输出一份干净、安全、可直接用于 Clash、Sing-Box、路由器等客户端的订阅。

> ⚠️ **注意**：本工具 **不检测代理可用性（存活）**。如需此功能，请使用 [xray-checker](https://github.com/kutovoys/xray-checker)。

---

## ✨ 功能特性

✅ 通过 `rules.yaml` 中的[灵活规则](./FILTER_RULES_zh.md) 进行验证  以及来自 `badwords.yaml` 的 [设置](./BADWORDS.md)  
✅ 支持 **单国或多国过滤**（最多 20 个）及关键词屏蔽  
✅ 自动去重，并保留最完整的链接版本  
✅ 内置缓存（默认 30 分钟）  
✅ 支持命令行（CLI）模式，可直接输出到终端

---

## 🛠️ 编译说明

需要 **Go 1.21+**。

```bash
go build -o sub-filter .
```

---

## ▶️ 使用方法

本程序支持两种模式：**HTTP 服务器** 和 **命令行（CLI）**。

示例[配置文件](../config)

### 1. HTTP 服务器模式（动态过滤）

启动一个服务器，实时按需过滤订阅。

#### 语法：

```bash
./sub-filter <端口> [缓存时间] [订阅列表] [屏蔽词] [用户代理] [规则文件]
```

#### 示例：

```bash
# 最简启动（使用 ./config/ 下的默认文件）
./sub-filter 8000

# 完整配置
./sub-filter 8000 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt ./config/rules.yaml
```

#### 接口说明：

| 接口      | 说明               |
| --------- | ------------------ |
| `/filter` | 过滤单个订阅       |
| `/merge`  | 合并并过滤多个订阅 |

**参数：**

- `id` — `sources_file` 中的行号（用于 `/filter`）
- `ids` — 以逗号分隔的行号（最多 20 个，用于 `/merge`）
- `c` — [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes) 国家代码（最多 20 个）

**示例：**

- `/filter?id=1` → 过滤第一个订阅
- `/filter?id=1&c=DE` → 仅保留德国服务器
- `/merge?ids=1,2,3&c=US,CA` → 合并三个订阅，仅保留美加服务器

---

### 2. CLI 模式（一次性处理）

一次性处理所有订阅，并将结果保存到磁盘。

#### 语法：

```bash
./sub-filter --cli [--stdout] [--config 配置文件.yaml] [--country AD,DE]
```

#### 参数：

| 参数        | 说明                                 |
| ----------- | ------------------------------------ |
| `--cli`     | 启用 CLI 模式                        |
| `--stdout`  | 直接输出到终端                       |
| `--config`  | 使用外部配置文件                     |
| `--country` | 按国家过滤（例如 `--country=NL,RU`） |

#### 示例：

```bash
# 处理所有订阅并保存结果
./sub-filter --cli

# 直接输出到终端
./sub-filter --cli --stdout

# 按国家过滤
./sub-filter --cli --country=NL,RU

# 使用自定义配置
./sub-filter --cli --config ./my-config.yaml
```

---

## 🌍 国家过滤

### 国家数据格式

国家信息以 **扁平结构** 存储在 `./config/countries.yaml` 中：

```yaml
CN:
  cca3: CHN
  flag: '🇨🇳'
  name: China
  native: '中国|中华人民共和国'
```

**生成国家文件：**

```bash
./sub-filter --cli --countries
```

工具会在每条链接的 **片段部分**（`#...`）中搜索：

- **两位国家代码**（ISO 3166-1 alpha-2）：`CN`
- **三位国家代码**（ISO 3166-1 alpha-3）：`CHN`
- **国旗 emoji**：`🇨🇳`
- **英文名称**：`China`
- **本地名称**：`中国`、`中华人民共和国`

匹配 **不区分大小写**，并支持 **URL 解码**。

---

## 🔤 参数说明

| 参数             | 说明                                                                   |
| ---------------- | ---------------------------------------------------------------------- |
| `<端口>`         | HTTP 服务器端口（服务器模式必需）                                      |
| `cache_ttl`      | 缓存时间（秒，默认 1800）                                              |
| `sources_file`   | 订阅 URL 列表（每行一个）   [sub.txt](../config/sub.txt)               |
| `bad_words_file` | 服务器名称中的屏蔽词列表 [badwords.yaml](../config/badwords.yaml)      |
| `uagent_file`    | 允许的 User-Agent 列表（如 `Clash`）[uagent.txt](../config/uagent.txt) |
| `rules_file`     | 验证规则文件 [rules.yaml](../config/rules.yaml)                        |

---

## 🖥️ CLI 参数

| 参数          | 说明                                             |
| ------------- | ------------------------------------------------ |
| `--cli`       | 启用 CLI 模式                                    |
| `--stdout`    | 输出到标准输出                                   |
| `--config`    | 配置文件路径                                     |
| `--country`   | 按国家过滤（仅 CLI）                             |
| `--countries` | 生成  [countries.yaml](../config/countries.yaml) |

---

## ✅ 快速测试

### 服务器模式

```bash
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1&c=AD"
```

### CLI 模式

```bash
./sub-filter --cli --country=US --stdout
```

结果默认保存在 `/tmp/sub-filter-cache`（或您指定的目录）。

---

## 📲 客户端集成

在客户端中添加动态订阅链接，例如：

```
http://your-server:8000/filter?id=1&c=CN,JP
```

> 🔒 **建议**：始终通过 HTTPS 反向代理（如 Nginx、Caddy 或 Cloudflare）提供服务。

---

## 🐳 Docker

### 启动服务器

```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  8000 1800
```

### CLI 模式（Docker）

```bash
# 处理订阅
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --country=DE

# 输出到终端
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --stdout

# 生成国家文件
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --countries
```

> 💡 运行前请确保 `./config` 和 `./cache` 目录已存在。

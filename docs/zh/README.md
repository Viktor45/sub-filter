> [!WARNING]
> **已弃用：**本项目将于 2026 年 8 月弃用。
> 本项目将不再提供支持。您可以继续完整使用本项目，但不再提供错误修复和技术支持。您可以 fork 本项目并自行改进，不会有任何问题。
> > 请使用 [fumox](https://github.com/Viktor45/fumox/blob/main/USERGUIDE.md) 来获取更高级和类似的功能。

---

[EN](../README.md) / [RU](../ru/README.md) / [ZH](README.md)

此翻译由神经网络完成，如有任何错误，敬请谅解。

<!-- TOC -->
- [sub-filter](#sub-filter)
  - [功能特性](#功能特性)
  - [构建](#构建)
  - [配置](#配置)
    - [嵌套格式](#嵌套格式)
    - [旧式扁平键](#旧式扁平键)
    - [环境变量](#环境变量)
  - [模式 1：HTTP 服务器](#模式-1http-服务器)
    - [端点](#端点)
    - [请求参数](#请求参数)
    - [请求保护](#请求保护)
  - [模式 2：CLI](#模式-2cli)
  - [按国家过滤](#按国家过滤)
  - [缓存文件](#缓存文件)
  - [客户端接入](#客户端接入)
  - [Docker](#docker)
    - [运行服务器](#运行服务器)
    - [Docker 中的 CLI](#docker-中的-cli)
  - [架构](#架构)
<!-- TOC -->

# sub-filter

智能代理订阅过滤器：**VLESS、VMess、Trojan、Shadowsocks、Hysteria2**
（`vless://`、`vmess://`、`trojan://`、`ss://`、`hysteria2://`、`hy2://`）。

程序会检查订阅中每条链接的：

- **安全性**（例如阻止 VLESS 中的 `security=none`），
- **正确性**（例如 `security=reality` 时要求 `pbk`），
- 服务器名称中是否含有**「违禁词」**——按灵活规则处理
  （切除、替换或删除），
- 链接片段（fragment）中的**国家标记**（国旗、名称、ISO 代码）。

最终产出干净、安全的订阅，可直接用于 Clash、Sing-Box、路由器及其他客户端。

> ⚠️ 程序**不检测代理的可用性**——只检查配置的正确性。如需检测连通性，
> 请使用 [xray-checker](https://github.com/kutovoys/xray-checker)。

---

## 功能特性

- ✅ 基于 `rules.yaml` 的灵活[规则校验](FILTER_RULES.md)
- ✅ 基于 `badwords.yaml` 的[「违禁词」过滤](BADWORDS.md)（strip / replace / delete）
- ✅ 按**一个或多个国家**过滤（默认最多 20 个）
- ✅ 去重，并保留相同服务器中信息最完整的版本
- ✅ 将多个订阅合并为一个（`/merge`）
- ✅ 输出格式：纯文本、YAML（Clash/Mihomo）、base64——见 [FORMAT_PARAMETER](FORMAT_PARAMETER.md)
- ✅ 磁盘缓存（默认 30 分钟）
- ✅ HTTP 服务器模式与一次性 CLI 处理模式

---

## 构建

需要 **Go 1.26+**（见 `go.mod`）。

```bash
go build -o sub-filter .
```

---

## 配置

程序读取单个 YAML 配置文件。路径按以下顺序确定：

1. `--config <路径>` 标志；
2. 环境变量 `SUBFILTER_CONFIG`；
3. `./config/config.yaml`（默认）。

### 嵌套格式

推荐的结构是嵌套节：

```yaml
server:
  port: 8000                 # HTTP 端口
  host: 0.0.0.0              # 绑定地址
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 60s

cache:
  directory: /tmp/sub-filter-cache
  ttl: 30m                   # 缓存有效期
  max_age: 24h               # 缓存条目的硬性保留期限
  cleanup_interval: 2m
  merge_buckets: 256         # 磁盘流式 merge 的分片数

sources:
  file: ./config/sub.txt     # 订阅 URL，每行一个
  fetch_timeout: 10s
  max_size: 10485760         # 单个源的最大大小，字节（10 MB）
  max_sources: 1000

validation:
  rules_file: ./config/rules.yaml
  bad_words_file: ./config/badwords.yaml
  countries_file: ./config/countries.yaml
  ua_file: ./config/uagent.txt   # 额外的 User-Agent 模式
  max_countries: 20          # 单次请求的最大国家代码数
  max_merge_ids: 20          # /merge 的最大源数量

logging:
  level: info                # debug、info、warn、error
  format: json               # json 或 text
```

### 旧式扁平键

为保持向后兼容，加载器也接受扁平键：
`sources_file`、`rules_file`、`bad_words_file`、`countries_file`、`uagent_file`、
`cache_dir`、`cache_ttl`、`max_country_codes`、`max_merge_ids`、`merge_buckets`。
仓库自带的 [`config/config.yaml`](../../config/config.yaml) 正是使用这种扁平
格式。嵌套值优先于扁平值。

### 环境变量

| 变量               | 用途                                         |
| ------------------ | -------------------------------------------- |
| `SUBFILTER_CONFIG` | 配置文件路径                                 |
| `SUBFILTER_PORT`   | 覆盖 `server.port`                           |
| `LOG_LEVEL`        | 日志级别（`debug`、`info`、`warn`、`error`） |

---

## 模式 1：HTTP 服务器

每次请求时实时过滤订阅。

```bash
./sub-filter [端口]
```

唯一的位置参数是端口（默认 `8000`）。其余所有设置均来自配置文件。

```bash
# 最小化启动（./config/config.yaml，端口 8000）
./sub-filter

# 在其他端口启动
./sub-filter 8080

# 自定义配置文件并开启详细日志
./sub-filter --config ./my-config.yaml --debug
```

### 端点

| 端点      | 说明                                  |
| --------- | ------------------------------------- |
| `/filter` | 过滤单个订阅                          |
| `/merge`  | 合并并过滤多个订阅                    |
| `/health` | 健康检查，返回 `{"status":"ok", ...}` |

### 请求参数

| 参数     | 适用端点  | 说明                                                                                                                   |
| -------- | --------- | ---------------------------------------------------------------------------------------------------------------------- |
| `id`     | `/filter` | 源 ID——`sources.file` 中的行号（从 1 开始，仅计有效行）                                                                |
| `ids`    | `/merge`  | 逗号分隔或重复传递的源 ID（`ids=1&ids=2`）；也接受旧式 `id`。最多 `validation.max_merge_ids` 个                        |
| `c`      | 两者      | 逗号分隔的 [ISO 3166-1 alpha-2](https://zh.wikipedia.org/wiki/ISO_3166-1) 国家代码。最多 `validation.max_countries` 个 |
| `lim`    | 两者      | 响应中代理行的最大数量                                                                                                 |
| `format` | 两者      | 输出格式：`yaml`、`base64` 或组合——见 [FORMAT_PARAMETER](FORMAT_PARAMETER.md)                                          |
| `ip`     | 两者      | 获取源时使用的 IP 协议栈：`4`（仅 IPv4）或 `6`（仅 IPv6）。不传则行为不变                                              |

**示例：**

```text
/filter?id=1                       → 过滤第一个订阅
/filter?id=1&c=DE                  → 仅德国服务器
/filter?id=1&format=yaml           → 输出 Clash/Mihomo 的 YAML
/filter?id=1&ip=6                  → 仅通过 IPv6 获取源
/merge?ids=1,2,3&c=US,CA           → 合并三个源，仅美国/加拿大服务器
/merge?ids=1,2&format=yaml&lim=100 → 合并后的 YAML，最多 100 行
```

### 请求保护

`/filter` 和 `/merge` 受保护（未经安全评审请勿削弱）：

- **User-Agent 白名单。** 仅当请求的 `User-Agent` 以内置前缀
  （`clash`、`happ`、`incy`）开头，或匹配 `validation.ua_file`
  （`config/uagent.txt`）中的 regex 模式时才被接受。内置前缀区分大小写，
  因此 `curl -H "User-Agent: clash" ...` 有效，而 `Clash` 无效。
  其他请求返回 `400 Invalid User-Agent`。
- **按 IP 限流。** 持续速率 10 请求/秒，突发上限 5。超出的请求返回
  `429 Too Many Requests`。
- **严格的源 ID 校验。** ID 必须匹配 `^[a-zA-Z0-9_]+$` 且不超过 64 个字符。

---

## 模式 2：CLI

一次性处理订阅，并将结果写入缓存目录（或输出到终端）。

```bash
./sub-filter --cli [--stdout] [--config 文件.yaml] [--country AD,DE] [--debug] [id ...]
```

| 标志        | 说明                                                       |
| ----------- | ---------------------------------------------------------- |
| `--cli`     | 以 CLI 模式运行                                            |
| `--stdout`  | 将结果输出到终端而不是写入缓存                             |
| `--config`  | 使用外部配置文件                                           |
| `--country` | 按国家代码过滤（例如 `--country=NL,RU`），规则与 `c=` 相同 |
| `--debug`   | 启动时输出详细信息并记录处理日志                           |

源 ID 可以作为位置参数传入；未指定时处理所有已配置的源。

```bash
# 处理所有源并保存到缓存目录
./sub-filter --cli

# 将结果输出到终端
./sub-filter --cli --stdout

# 带国家过滤的处理
./sub-filter --cli --country=NL,RU

# 使用自定义配置仅处理源 1 和 3
./sub-filter --cli --config ./my-config.yaml 1 3
```

---

## 按国家过滤

国家数据保存在 `config/countries.yaml`（以 CCA2 代码为键的扁平映射）：

```yaml
RU:
  cca3: RUS
  flag: '🇷🇺'
  name: Russia
  native: 'Россия|Российская Федерация'
```

启用国家过滤时，程序会在每条链接的**片段**（`#...`）中查找所请求国家的
以下任意字符串：

- **CCA3 代码**：`RUS`
- **国旗表情**：`🇷🇺`
- **通用名称**：`Russia`
- **本地名称**：`Россия`、`Российская Федерация`

比较**不区分大小写**，并支持 **URL 解码**。没有片段的链接无法通过国家过滤。

> 📝 两字母 CCA2 代码（例如 `RU`）用作请求键，但不会在片段中直接搜索——
> 匹配依据是 CCA3、国旗和名称。

---

## 缓存文件

结果保存在 `cache.directory`（默认 `/tmp/sub-filter-cache`）。

服务器模式（`/filter`）为每个源与国家组合创建：

| 文件                           | 内容                         |
| ------------------------------ | ---------------------------- |
| `orig_<id>[_c_<代码>].txt`     | 原始下载的订阅               |
| `mod_<id>[_c_<代码>].txt`      | 过滤后的配置（提供给客户端） |
| `rejected_<id>[_c_<代码>].txt` | 被拒绝的行及原因             |

`/merge` 写入 `merge_<id1>_<id2>...[_c_<代码>].txt`。
CLI 模式写入 `<id>[_c_<代码>].txt`。

`<代码>` 是排序后用下划线连接的国家代码
（例如 `mod_1_c_DE_NL.txt`）。文件超过 `cache.ttl` 后会刷新。

---

## 客户端接入

在客户端中添加动态订阅：

```text
http://你的服务器:8000/filter?id=1&c=NL,RU
```

注意：客户端的 `User-Agent` 必须在白名单中（大多数流行客户端已被
`config/uagent.txt` 覆盖）。

> 🔒 **建议**：置于 HTTPS 反向代理（Nginx、Caddy、Cloudflare 等）之后使用。

---

## Docker

镜像从 `/config/config.yaml` 读取配置，并监听 `8000` 端口
（可通过 `SUBFILTER_PORT` 修改）。

### 运行服务器

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest
```

### Docker 中的 CLI

```bash
# 处理订阅并将结果写入 ./cache
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --country=DE

# 将结果输出到终端
docker run --rm \
  -v $(pwd)/config:/config:ro \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --stdout
```

仓库中提供了现成的 [`docker-compose.yml`](../../docker-compose.yml) 和
Podman-quadlet 示例 [`subfilter.container`](../../subfilter.container)。

> 💡 运行前请确保 `./config` 和 `./cache` 目录存在。

---

## 架构

项目采用依赖注入的模块化架构：

- **`pkg/config`** — 配置加载与校验（YAML，嵌套 + 扁平格式）
- **`pkg/service`** — 核心业务逻辑：HTTP 处理器、过滤、merge、缓存
- **`pkg/errors`** — 带代码与严重级别的类型化错误
- **`pkg/logger`** — 基于 `slog` 的结构化日志封装
- **`pkg/cache`** — 带命中率统计的已编译 regex 缓存
- **`internal/validator`** — 通用校验规则引擎
- **`internal/utils`** — URL 规范化、主机/端口校验、国家查询、去重
- **`vless`、`vmess`、`trojan`、`ss`、`hysteria2`** — 实现统一 `ProxyLink` 接口的协议解析器

如何扩展项目——见 [DEVELOPMENT](DEVELOPMENT.md)。

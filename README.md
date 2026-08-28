> [!WARNING]
> **DEPRECATED:** This project is about to be deprecated as of August 2026.
>
> This project is no longer supported. You can continue to use it in full, but bug fixes and technical support are not provided. You can fork the project and improve it yourself without any problems.
> >  Please use [fumox](https://github.com/Viktor45/fumox/blob/main/USERGUIDE.md) instead for advanced and similar functions.

---


<div align="center">

# 🧹 sub-filter

**Smart proxy subscription filter**  
_VLESS · VMess · Trojan · Shadowsocks · Hysteria2_

[![GitHub Release](https://img.shields.io/github/v/release/viktor45/sub-filter?style=flat&color=blue)](https://github.com/viktor45/sub-filter/releases/latest)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/viktor45/sub-filter/container.yaml?style=flat)](https://github.com/Viktor45/sub-filter/actions/workflows/container.yaml)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Docker Image](https://img.shields.io/badge/Docker-ghcr.io%2Fviktor45%2Fsub--filter-blue?logo=docker)](https://github.com/viktor45/sub-filter/pkgs/container/sub-filter)
[![en](https://img.shields.io/badge/lang-en-blue)](docs/README.md)
[![ru](https://img.shields.io/badge/lang-ru-red)](docs/ru/README.md)
[![zh](https://img.shields.io/badge/lang-zh-blue)](docs/zh/README.md)

**Removes junk. Keeps only secure servers.**

</div>

---

**sub-filter** is an intelligent proxy subscription filter for VLESS, VMess, Trojan,
Shadowsocks, and Hysteria2. It automatically:

- 🔒 **Blocks insecure configurations** (e.g., VLESS with `security=none`)
- 🧪 **Validates correctness** (required parameters, allowed values)
- 🚫 **Filters prohibited ("bad") keywords** by flexible rules (strip, replace, or delete)
- 🌍 **Selects servers by country** (flag, name, ISO code)
- 🔁 **Merges and deduplicates** multiple subscriptions into one clean list

The result is a ready-to-use subscription for **Clash, Sing-Box, routers, and other clients**.

> ⚠️ **Note**: This tool **does not test proxy liveness** (availability/latency).
> For that, use [xray-checker](https://github.com/kutovoys/xray-checker).

---

## 📚 Documentation

English is the primary language. Russian and Chinese translations are provided in
`docs/ru/` and `docs/zh/`.

| Topic                          | EN                                           | RU                                | ZH                                |
| ------------------------------ | -------------------------------------------- | --------------------------------- | --------------------------------- |
| **Main guide**                 | [docs](docs/README.md)                       | [docs/ru](docs/ru/README.md)      | [docs/zh](docs/zh/README.md)      |
| **Validation rules**           | [FILTER_RULES](docs/FILTER_RULES.md)         | [RU](docs/ru/FILTER_RULES.md)     | [ZH](docs/zh/FILTER_RULES.md)     |
| **Bad-word filters**           | [BADWORDS](docs/BADWORDS.md)                 | [RU](docs/ru/BADWORDS.md)         | [ZH](docs/zh/BADWORDS.md)         |
| **Output formats (`format=`)** | [FORMAT_PARAMETER](docs/FORMAT_PARAMETER.md) | [RU](docs/ru/FORMAT_PARAMETER.md) | [ZH](docs/zh/FORMAT_PARAMETER.md) |
| **FAQ**                        | [FAQ](docs/FAQ.md)                           | [RU](docs/ru/FAQ.md)              | [ZH](docs/zh/FAQ.md)              |
| **Development**                | [DEVELOPMENT](docs/DEVELOPMENT.md)           | [RU](docs/ru/DEVELOPMENT.md)      | [ZH](docs/zh/DEVELOPMENT.md)      |

Configuration and rule examples live in [`config/`](config/):

| File                                             | Purpose                     |
| ------------------------------------------------ | --------------------------- |
| [`config/config.yaml`](config/config.yaml)       | Main configuration          |
| [`config/rules.yaml`](config/rules.yaml)         | Validation rules            |
| [`config/badwords.yaml`](config/badwords.yaml)   | Bad-word rules              |
| [`config/sub.txt`](config/sub.txt)               | Subscription sources        |
| [`config/countries.yaml`](config/countries.yaml) | Country data                |
| [`config/uagent.txt`](config/uagent.txt)         | Allowed User-Agent patterns |

---

## 🚀 Quick Start

Requires **Go 1.26+** to build.

```bash
# Build
go build -o sub-filter .

# Start the HTTP server on port 8000 (default)
./sub-filter

# Test the output (note: the User-Agent must be on the allow-list)
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=RU"

# Process all configured subscriptions once in CLI mode and print to the terminal
./sub-filter --cli --stdout --country=NL,RU
```

> 💡 **Review the configuration files in `config/` before running.**

Full usage details are in the [main guide](docs/README.md).

---

## 🐳 Docker

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest
```

The image reads its configuration from `/config/config.yaml`
(`SUBFILTER_CONFIG=/config/config.yaml`) and listens on port `8000` by default.
See the [main guide](docs/README.md#docker) for more options.

---

<div align="center">

💡 **Tip**: Use `sub-filter` as middleware between public subscriptions and your
client — and forget about broken or misconfigured proxies!

</div>

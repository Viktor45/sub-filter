<div align="center">

# 🧹 sub-filter

**Smart proxy subscription filter**  
_VLESS · VMess · Trojan · Shadowsocks · Hysteria2_

[![GitHub Release](https://img.shields.io/github/v/release/viktor45/sub-filter?style=flat&color=blue)](https://github.com/viktor45/sub-filter/releases/latest)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/viktor45/sub-filter/ko-container.yaml?style=flat)](https://github.com/Viktor45/sub-filter/actions/workflows/ko-container.yaml)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Docker Image](https://img.shields.io/badge/Docker-ghcr.io%2Fviktor45%2Fsub--filter-blue?logo=docker)](https://github.com/viktor45/sub-filter/pkgs/container/sub-filter)
[![en](https://img.shields.io/badge/lang-en-blue)](https://github.com/viktor45/sub-filter/blob/main/docs/README_en.md)
[![ru](https://img.shields.io/badge/lang-ru-red)](https://github.com/viktor45/sub-filter/blob/main/docs/README.md)
[![zh](https://img.shields.io/badge/lang-zh-blue)](https://github.com/viktor45/sub-filter/blob/main/docs/README_zh.md)

**Removes junk. Keeps only secure servers.**

</div>

---

**sub-filter** is an intelligent proxy subscription filter for VLESS, VMess, Trojan, Shadowsocks, and Hysteria2.  
It automatically:

- 🔒 **Blocks insecure configurations** (e.g., VLESS without encryption)
- 🧪 **Validates correctness** (required parameters, allowed values)
- 🚫 **Rule-based filtering of prohibited (bad) keywords**
- 🌍 **Selects servers by country** (flag, name, ISO code)
- 🔁 **Merges and deduplicates** multiple subscriptions into one clean list

The result is a ready-to-use subscription for **Clash, Sing-Box, routers, and other clients**.

> ⚠️ **Note**: This tool **does not test proxy liveness** (availability/latency).  
> For that, use [xray-checker](https://github.com/kutovoys/xray-checker).

---

## 📚 Documentation

| Topic                 | Links                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------ |
| **Main Guide**        | [EN](docs/README_en.md) · [RU](docs/README.md) · [ZH](docs/README_zh.md)                   |
| **FAQ**               | [EN](docs/FAQ_en.md) · [RU](docs/FAQ.md) · [ZH](docs/FAQ_zh.md)                            |
| **Validation Rules**  | [EN](docs/FILTER_RULES_en.md) · [RU](docs/FILTER_RULES.md) · [ZH](docs/FILTER_RULES_zh.md) |
| **Bad words filters** | [EN](docs/BADWORDS_en.md) · [RU](docs/BADWORDS.md) · [ZH](docs/BADWORDS_zh.md)             |
| **Configuration**     | [config/config.yaml](config/config.yaml)                                                   |
| **Rules Example**     | [config/rules.yaml](config/rules.yaml)                                                     |
| **Bad words Example** | [config/badwords.yaml](config/badwords.yaml)                                               |
| Example configuration | [./config](./config)                                                                       |
| for developers:       |
| Extending             | [EN](docs/EXTENDING_en.md) · [RU](docs/EXTENDING.md) · [ZH](docs/EXTENDING_zh.md)          |
| Error Types           | [EN](docs/ERROR_TYPES_en.md) · [RU](docs/ERROR_TYPES.md) · [ZH](docs/ERROR_TYPES_zh.md)    |


---

## 🚀 Quick Start

```bash
# Start server on port 8000
./sub-filter 8000

# Test output
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1&c=RU"

# Process subscriptions in CLI mode and print to terminal
./sub-filter --cli --stdout --country=NL,RU
```

> 💡 **Don’t forget to review the configuration files!**

---

## 🐳 Docker

```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  8080
```

---

<div align="center">

💡 **Tip**: Use `sub-filter` as a middleware between public subscriptions and your client — and forget about broken or misconfigured proxies!

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=viktor45/sub-filter&type=date&logscale&legend=top-left)](https://www.star-history.com/#viktor45/sub-filter&type=date&logscale&legend=top-left)

</div>

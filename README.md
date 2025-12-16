[EN](docs/README_en.md) / [RU](docs/README.md)  / [ZH](docs/README_zh.md) 

# sub-filter

A simple **sub**scription **filter**

This tool is an intelligent filter for proxy server links (VLESS, VMess, Trojan, Shadowsocks, Hysteria2). It fetches public subscriptions, validates each server for correctness and security (e.g., blocks unencrypted connections or names containing forbidden keywords), filters out anything suspicious, and outputs a clean, working list—ready to use in Clash, Sing-Box, routers, and other clients.

⚠️ **Note**: This program **does not check proxy availability or latency**. For that, use [xray-checker](https://github.com/kutovoys/xray-checker).

## FAQ

[EN](docs/FAQ_en.md) / [RU](docs/FAQ.md) / [ZH](docs/FAQ_zh.md)

## Configuration

Example of a basic configuration file:  
[config/config.yaml](config/config.yaml)

## Validation Rules

Example of default filtering rules:  
[config/rules.yaml](config/rules.yaml)

Detailed documentation on how proxy links inside subscriptions are validated:  
[EN](docs/FILTER_RULES_en.md) / [RU](docs/FILTER_RULES.md) / [ZH](docs/FILTER_RULES_zh.md)

---
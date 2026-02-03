[EN](README_en.md) / [RU](README.md) / [ZH](README_zh.md)

This translation was made using AI.

- [sub-filter](#sub-filter)
  - [✨ Features](#-features)
  - [🛠️ Build Instructions](#️-build-instructions)
  - [▶️ Usage](#️-usage)
    - [1. HTTP Server Mode (Dynamic Filtering)](#1-http-server-mode-dynamic-filtering)
      - [Syntax:](#syntax)
      - [Examples:](#examples)
      - [Endpoints:](#endpoints)
    - [2. CLI Mode (One-time Processing)](#2-cli-mode-one-time-processing)
      - [Syntax:](#syntax-1)
      - [Flags:](#flags)
      - [Examples:](#examples-1)
  - [🌍 Country Filtering](#-country-filtering)
    - [Country Data Format](#country-data-format)
  - [🔤 Parameter Reference](#-parameter-reference)
  - [🖥️ CLI Flags](#️-cli-flags)
  - [✅ Quick Test](#-quick-test)
    - [Server](#server)
    - [CLI](#cli)
  - [📲 Client Integration](#-client-integration)
  - [🐳 Docker](#-docker)
    - [Run Server](#run-server)
    - [CLI in Docker](#cli-in-docker)

# sub-filter

A smart proxy subscription filter for **VLESS, VMess, Trojan, Shadowsocks, and Hysteria2**.

This tool validates every proxy link in your subscription by checking:

- **Security** (e.g., blocks `security=none` in VLESS),
- **Correctness** (e.g., requires `pbk` when `security=reality`),
- **Rule-based filtering of prohibited (bad) keywords**,
- **Geographic filtering** by country name, flag, or native language.

The result is a clean, secure, and ready-to-use subscription for Clash, Sing-Box, routers, and other clients.

> ⚠️ **Note**: This tool **does not test proxy liveness**. For that, please use [xray-checker](https://github.com/kutovoys/xray-checker).

---

## ✨ Features

✅ Validation via flexible [rules](./FILTER_RULES_en.md) from `rules.yaml` and [settings](./BADWORDS_en.md) from `badwords.yaml`  
✅ Filtering by **one or multiple countries** (up to 20) and bad words  
✅ Deduplication with selection of the most complete link version  
✅ Built-in caching (30 minutes by default)  
✅ CLI mode with terminal output support

---

## 🛠️ Build Instructions

Requires **Go 1.21+**.

```bash
go build -o sub-filter .
```

---

## ▶️ Usage

The program supports two modes: **HTTP server** and **CLI**.

Example [configuration files](../config)

### 1. HTTP Server Mode (Dynamic Filtering)

Starts a server that filters subscriptions on-the-fly.

#### Syntax:

```bash
./sub-filter <port> [cache_ttl] [sources_file] [bad_words_file] [uagent_file] [rules_file]
```

#### Examples:

```bash
# Minimal start (uses files from ./config/)
./sub-filter 8000

# Full configuration
./sub-filter 8000 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt ./config/rules.yaml
```

#### Endpoints:

| Endpoint  | Description                             |
| --------- | --------------------------------------- |
| `/filter` | Filter a single subscription            |
| `/merge`  | Merge and filter multiple subscriptions |

**Parameters:**

- `id` — line number from `sources_file` (for `/filter`)
- `ids` — comma-separated line numbers (max 20, for `/merge`)
- `c` — [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes) country codes (max 20)

**Examples:**

- `/filter?id=1` → filter the first subscription
- `/filter?id=1&c=DE` → filter by Germany
- `/merge?ids=1,2,3&c=US,CA` → merge three subscriptions, keep only US/CA servers

---

### 2. CLI Mode (One-time Processing)

Processes all subscriptions once and saves results to disk.

#### Syntax:

```bash
./sub-filter --cli [--stdout] [--config config.yaml] [--country AD,DE]
```

#### Flags:

| Flag        | Description                                       |
| ----------- | ------------------------------------------------- |
| `--cli`     | Enable CLI mode                                   |
| `--stdout`  | Print result to terminal                          |
| `--config`  | Use external config file                          |
| `--country` | Filter by country codes (e.g., `--country=NL,RU`) |

#### Examples:

```bash
# Process all and save to cache
./sub-filter --cli

# Output directly to terminal
./sub-filter --cli --stdout

# Filter by country
./sub-filter --cli --country=NL,RU

# Use custom config
./sub-filter --cli --config ./my-config.yaml
```

---

## 🌍 Country Filtering

### Country Data Format

Country information is stored in `./config/countries.yaml` in a **flat structure**:

```yaml
RU:
  cca3: RUS
  flag: '🇷🇺'
  name: Russia
  native: 'Россия|Российская Федерация'
```

**Generate the file:**

```bash
./sub-filter --cli --countries
```

The tool searches the **fragment** (`#...`) of each proxy link for:

- **ISO 3166-1 alpha-2 code**: `RU`
- **ISO 3166-1 alpha-3 code**: `RUS`
- **Flag emoji**: `🇷🇺`
- **Common name**: `Russia`
- **Native names**: `Россия`, `Российская Федерация`

Matching is **case-insensitive** and supports **URL decoding**.

---

## 🔤 Parameter Reference

| Parameter        | Description                                                                         |
| ---------------- | ----------------------------------------------------------------------------------- |
| `<port>`         | HTTP server port (required in server mode)                                          |
| `cache_ttl`      | Cache TTL in seconds (default: 1800)                                                |
| `sources_file`   | List of subscription URLs (one per line) [sub.txt](../config/sub.txt)               |
| `bad_words_file` | List of forbidden words strip/delete rules [badwords.yaml](../config/badwords.yaml) |
| `uagent_file`    | Allowed User-Agent list (e.g., `Clash`) [uagent.txt](../config/uagent.txt)          |
| `rules_file`     | Validation rules file [rules.yaml](../config/rules.yaml)                            |

---

## 🖥️ CLI Flags

| Flag          | Description                                         |
| ------------- | --------------------------------------------------- |
| `--cli`       | Run in CLI mode                                     |
| `--stdout`    | Output to stdout                                    |
| `--config`    | Path to config file                                 |
| `--country`   | Filter by country (CLI only)                        |
| `--countries` | Generate [countries.yaml](../config/countries.yaml) |

---

## ✅ Quick Test

### Server

```bash
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1&c=AD"
```

### CLI

```bash
./sub-filter --cli --country=US --stdout
```

Results are saved to `/tmp/sub-filter-cache` (or your configured directory).

---

## 📲 Client Integration

Add a dynamic subscription like:

```
http://your-server:8000/filter?id=1&c=NL,RU
```

> 🔒 **Recommendation**: Always run behind an HTTPS reverse proxy (e.g., Nginx, Caddy, or Cloudflare).

---

## 🐳 Docker

### Run Server

```bash
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  8080 1800
```

### CLI in Docker

```bash
# Process subscriptions
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --country=DE

# Output to terminal
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --stdout

# Generate countries.yaml
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --countries
```

> 💡 Ensure `./config` and `./cache` directories exist before running.

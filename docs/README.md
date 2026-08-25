[EN](README.md) / [RU](ru/README.md) / [ZH](zh/README.md)

<!-- TOC -->
* [sub-filter](#sub-filter)
  * [Features](#features)
  * [Build](#build)
  * [Configuration](#configuration)
    * [Nested format](#nested-format)
    * [Legacy flat keys](#legacy-flat-keys)
    * [Environment variables](#environment-variables)
  * [Mode 1: HTTP server](#mode-1-http-server)
    * [Endpoints](#endpoints)
    * [Query parameters](#query-parameters)
    * [Request protection](#request-protection)
  * [Mode 2: CLI](#mode-2-cli)
  * [Country filtering](#country-filtering)
  * [Cache files](#cache-files)
  * [Client integration](#client-integration)
  * [Docker](#docker)
    * [Run the server](#run-the-server)
    * [CLI in Docker](#cli-in-docker)
  * [Architecture](#architecture)
<!-- TOC -->

# sub-filter

A smart proxy subscription filter for **VLESS, VMess, Trojan, Shadowsocks, and Hysteria2**
(`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`).

The tool validates every proxy link in a subscription by checking:

- **Security** (e.g., blocks `security=none` in VLESS),
- **Correctness** (e.g., requires `pbk` when `security=reality`),
- **Prohibited ("bad") keywords** in server names, handled by flexible rules
  (strip, replace, or delete),
- **Country markers** in the link fragment (flag, name, ISO code).

The result is a clean, secure subscription ready for Clash, Sing-Box, routers,
and other clients.

> ⚠️ The tool **does not test proxy liveness** — only configuration correctness.
> For liveness checks use [xray-checker](https://github.com/kutovoys/xray-checker).

---

## Features

- ✅ Validation via flexible [rules](FILTER_RULES.md) from `rules.yaml`
- ✅ [Bad-word filtering](BADWORDS.md) from `badwords.yaml` (strip / replace / delete)
- ✅ Filtering by **one or more countries** (up to 20 by default)
- ✅ Deduplication that keeps the most complete version of duplicate servers
- ✅ Merging multiple subscriptions into one (`/merge`)
- ✅ Output formats: plain text, YAML (Clash/Mihomo), base64 — see [FORMAT_PARAMETER](FORMAT_PARAMETER.md)
- ✅ Disk caching (30 minutes by default)
- ✅ HTTP server and one-shot CLI modes

---

## Build

Requires **Go 1.26+** (see `go.mod`).

```bash
go build -o sub-filter .
```

---

## Configuration

The program reads a single YAML config file, resolved in this order:

1. `--config <path>` flag
2. `SUBFILTER_CONFIG` environment variable
3. `./config/config.yaml` (default)

### Nested format

The preferred structure uses nested sections:

```yaml
server:
  port: 8000                 # HTTP port
  host: 0.0.0.0              # bind address
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 60s

cache:
  directory: /tmp/sub-filter-cache
  ttl: 30m                   # how long cached results stay fresh
  max_age: 24h               # hard expiry for cache entries
  cleanup_interval: 2m
  merge_buckets: 256         # shards for disk-based streaming merge

sources:
  file: ./config/sub.txt     # subscription URLs, one per line
  fetch_timeout: 10s
  max_size: 10485760         # max source size in bytes (10 MB)
  max_sources: 1000

validation:
  rules_file: ./config/rules.yaml
  bad_words_file: ./config/badwords.yaml
  countries_file: ./config/countries.yaml
  ua_file: ./config/uagent.txt   # extra allowed User-Agent patterns
  max_countries: 20          # max codes per request
  max_merge_ids: 20          # max sources per /merge request

logging:
  level: info                # debug, info, warn, error
  format: json               # json or text
```

### Legacy flat keys

For backward compatibility the loader also accepts flat keys:
`sources_file`, `rules_file`, `bad_words_file`, `countries_file`, `uagent_file`,
`cache_dir`, `cache_ttl`, `max_country_codes`, `max_merge_ids`, `merge_buckets`.
The bundled [`config/config.yaml`](../config/config.yaml) uses this flat form.
Nested values take precedence over flat ones.

### Environment variables

| Variable           | Purpose                                      |
|--------------------|----------------------------------------------|
| `SUBFILTER_CONFIG` | Path to the config file                      |
| `SUBFILTER_PORT`   | Overrides `server.port`                      |
| `LOG_LEVEL`        | Log level (`debug`, `info`, `warn`, `error`) |

---

## Mode 1: HTTP server

Filters subscriptions on the fly for every request.

```bash
./sub-filter [port]
```

The only positional argument is the port (default `8000`). All other settings
come from the config file.

```bash
# Minimal start (uses ./config/config.yaml, port 8000)
./sub-filter

# Start on a custom port
./sub-filter 8080

# Custom config file and verbose logging
./sub-filter --config ./my-config.yaml --debug
```

### Endpoints

| Endpoint  | Description                                  |
| --------- | -------------------------------------------- |
| `/filter` | Filter a single subscription                 |
| `/merge`  | Merge and filter multiple subscriptions      |
| `/health` | Health check, returns `{"status":"ok", ...}` |

### Query parameters

| Parameter | Applies to | Description                                                                                                                                       |
|-----------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`      | `/filter`  | Source ID — the line number in `sources.file` (1-based, valid lines only)                                                                         |
| `ids`     | `/merge`   | Source IDs, comma-separated or repeated (`ids=1&ids=2`); legacy `id` also accepted. Max `validation.max_merge_ids`                                |
| `c`       | both       | [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes) country codes, comma-separated. Max `validation.max_countries` |
| `lim`     | both       | Maximum number of proxy lines in the response                                                                                                     |
| `format`  | both       | Output format: `yaml`, `base64`, or a combination — see [FORMAT_PARAMETER](FORMAT_PARAMETER.md)                                                   |
| `ip`      | both       | IP stack used to fetch sources: `4` (IPv4 only) or `6` (IPv6 only). Omitted: no preference, behavior is unchanged                                 |

**Examples:**

```text
/filter?id=1                       → filter the first subscription
/filter?id=1&c=DE                  → keep only German servers
/filter?id=1&format=yaml           → Clash/Mihomo YAML output
/filter?id=1&ip=6                  → fetch the source over IPv6 only
/merge?ids=1,2,3&c=US,CA           → merge three sources, keep US/CA servers
/merge?ids=1,2&format=yaml&lim=100 → merged YAML, at most 100 lines
```

### Request protection

Both `/filter` and `/merge` are protected (do not disable without a security review):

- **User-Agent allow-list.** A request is accepted only if its `User-Agent`
  starts with a built-in prefix (`clash`, `happ`, `incy`) or matches a regex
  pattern from `validation.ua_file` (`config/uagent.txt`). Built-in prefixes are
  matched case-sensitively, so `curl -H "User-Agent: clash" ...` works while
  `Clash` does not. Other requests get `400 Invalid User-Agent`.
- **Per-IP rate limiting.** Sustained 10 requests/second with a burst of 5.
  Excess requests get `429 Too Many Requests`.
- **Strict source ID validation.** IDs must match `^[a-zA-Z0-9_]+$` and be at
  most 64 characters.

---

## Mode 2: CLI

Processes subscriptions once and writes the results to the cache directory
(or prints them to the terminal).

```bash
./sub-filter --cli [--stdout] [--config file.yaml] [--country AD,DE] [--debug] [id ...]
```

| Flag        | Description                                                          |
|-------------|----------------------------------------------------------------------|
| `--cli`     | Run in CLI mode                                                      |
| `--stdout`  | Print results to the terminal instead of writing cache files         |
| `--config`  | Use an external config file                                          |
| `--country` | Filter by country codes (e.g. `--country=NL,RU`), same rules as `c=` |
| `--debug`   | Verbose startup info and processing logs                             |

Source IDs can be passed as positional arguments; if none are given, all
configured sources are processed.

```bash
# Process all configured sources and save to the cache directory
./sub-filter --cli

# Print results to the terminal
./sub-filter --cli --stdout

# Process with country filtering
./sub-filter --cli --country=NL,RU

# Process only sources 1 and 3 with a custom config
./sub-filter --cli --config ./my-config.yaml 1 3
```

---

## Country filtering

Country data lives in `config/countries.yaml` (flat map keyed by the CCA2 code):

```yaml
RU:
  cca3: RUS
  flag: '🇷🇺'
  name: Russia
  native: 'Россия|Российская Федерация'
```

When a country filter is active, the program scans the **fragment** (`#...`) of
each proxy link for any of these strings for the requested countries:

- **CCA3 code**: `RUS`
- **Flag emoji**: `🇷🇺`
- **Common name**: `Russia`
- **Native names**: `Россия`, `Российская Федерация`

Matching is **case-insensitive** and supports **URL decoding**. Links without a
fragment do not pass a country filter.

> 📝 The two-letter CCA2 code (e.g. `RU`) is used as the request key but is not
> itself searched inside fragments; matching relies on CCA3, flag, and names.

---

## Cache files

Results are stored in `cache.directory` (`/tmp/sub-filter-cache` by default).

Server mode (`/filter`) creates, per source and country combination:

| File                              | Content                                  |
| --------------------------------- | ---------------------------------------- |
| `orig_<id>[_c_<CODES>].txt`       | Original fetched subscription            |
| `mod_<id>[_c_<CODES>].txt`        | Filtered profile (served to clients)     |
| `rejected_<id>[_c_<CODES>].txt`   | Rejected lines with reasons              |

`/merge` writes `merge_<id1>_<id2>...[_c_<CODES>].txt`.
CLI mode writes `<id>[_c_<CODES>].txt`.

`<CODES>` is the sorted, underscore-joined list of country codes
(e.g. `mod_1_c_DE_NL.txt`). Files are refreshed when older than `cache.ttl`.

---

## Client integration

Add a dynamic subscription URL to your client:

```text
http://your-server:8000/filter?id=1&c=NL,RU
```

Remember that the client's `User-Agent` must be on the allow-list (most popular
clients are covered by `config/uagent.txt`).

> 🔒 **Recommendation**: run behind an HTTPS reverse proxy (Nginx, Caddy,
> Cloudflare, etc.).

---

## Docker

The image reads config from `/config/config.yaml` and listens on port `8000`
(configurable via `SUBFILTER_PORT`).

### Run the server

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest
```

### CLI in Docker

```bash
# Process subscriptions and write results into ./cache
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --country=DE

# Print results to the terminal
docker run --rm \
  -v $(pwd)/config:/config:ro \
  ghcr.io/viktor45/sub-filter:latest \
  --cli --stdout
```

A ready-made [`docker-compose.yml`](../docker-compose.yml) and a Podman quadlet
example [`subfilter.container`](../subfilter.container) are included in the
repository.

> 💡 Make sure the `./config` and `./cache` directories exist before running.

---

## Architecture

The project uses a modular architecture with dependency injection:

- **`pkg/config`** — config loading and validation (YAML, nested + legacy flat keys)
- **`pkg/service`** — core business logic: HTTP handlers, filtering, merge, caching
- **`pkg/errors`** — typed errors with codes and severity
- **`pkg/logger`** — structured logging built on `slog`
- **`pkg/cache`** — compiled-regex cache with hit/miss statistics
- **`internal/validator`** — generic rule engine and validation policies
- **`internal/utils`** — URL normalization, host/port validation, country lookup, dedupe helpers
- **`vless`, `vmess`, `trojan`, `ss`, `hysteria2`** — protocol parsers implementing the common `ProxyLink` interface

See [DEVELOPMENT](DEVELOPMENT.md) for how to extend the project.

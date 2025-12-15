[EN](README_en.md) / [RU](README.md)  / [ZH](README_zh.md) 

This translation was made using AI.

- [sub-filter](#sub-filter)
  - [What can it do?](#what-can-it-do)
  - [How to build?](#how-to-build)
  - [How to run?](#how-to-run)
    - [Mode 1: HTTP Server (Dynamic filtering)](#mode-1-http-server-dynamic-filtering)
      - [Full configuration example:](#full-configuration-example)
      - [Minimal example:](#minimal-example)
    - [Mode 2: CLI (One-time processing)](#mode-2-cli-one-time-processing)
      - [New CLI features:](#new-cli-features)
      - [Example: output to terminal](#example-output-to-terminal)
      - [Example: using a config file](#example-using-a-config-file)
  - [What do the parameters mean?](#what-do-the-parameters-mean)
  - [New flags: `--config` and `--stdout`](#new-flags---config-and---stdout)
    - [`--stdout` (CLI mode only)](#--stdout-cli-mode-only)
    - [`--config`](#--config)
      - [Example `config.yaml`:](#example-configyaml)
  - [How to verify it works?](#how-to-verify-it-works)
    - [For server mode:](#for-server-mode)
    - [For CLI mode:](#for-cli-mode)
  - [How to use in a client?](#how-to-use-in-a-client)
  - [Ready-to-use Docker image](#ready-to-use-docker-image)
  - [How to build the Docker image?](#how-to-build-the-docker-image)
  - [How to run in Docker?](#how-to-run-in-docker)
    - [With Docker:](#with-docker)
    - [With Podman (Docker alternative):](#with-podman-docker-alternative)
  - [CLI mode in Docker](#cli-mode-in-docker)

# sub-filter

A simple subscription filter

This program is an intelligent filter for proxy server URLs (VLESS, VMess, Trojan, Shadowsocks, Hysteria2). It fetches public subscriptions, validates each server for correctness and security (e.g., blocks unencrypted connections or names containing prohibited keywords), filters out anything suspicious, and outputs a clean, working list—ready for immediate use in Clash, Sing-Box, routers, and other clients.

If you're unsure why you'd need this, please read the [FAQ](FAQ.md).

⚠️ **Note**: This program does **not** test proxy **availability or latency**. For that, use [xray-checker](https://github.com/kutovoys/xray-checker).

---

## What can it do?

✅ Validates proxy links and removes unsafe or broken configurations  
✅ Filters servers based on a list of forbidden keywords (e.g., suspicious domains)  
✅ Blocks known honeypots that sometimes appear in public subscriptions  
✅ Caches results (default: 30 minutes) to avoid overloading networks or upstream servers  
✅ Generates subscriptions with clear descriptions and correct formatting  
✅ Supports configuration via file  
✅ Can output results directly to the terminal in CLI mode without saving files

---

## How to build?

If you have Go (version 1.25 or newer) installed, run in your terminal:

```bash
go build .
```

This produces a `sub-filter` executable—your ready-to-use program.

---

## How to run?

The program supports two modes: **HTTP server** and **CLI (command-line)**.

### Mode 1: HTTP Server (Dynamic filtering)

Starts an HTTP server on a specified port. Subscriptions are filtered on-demand for each request.

#### Full configuration example:

```bash
./sub-filter 8000 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt
```

#### Minimal example:

```bash
./sub-filter 8000
```

In this case:
- Cache TTL is 1800 seconds (30 minutes)  
- The program looks for config files in `./config/`  
- If any file is missing, it proceeds with empty lists (resulting in an empty subscription if no rules apply)

### Mode 2: CLI (One-time processing)

Processes all subscriptions once and saves results to the OS temp directory `sub-filter-cache`. The exact path is printed on startup. Ideal for automation, cron jobs, or offline use.

#### New CLI features:

- **`--stdout`**: Outputs everything directly to the terminal instead of saving files  
- **`--config`**: Lets you define all parameters in a single config file

#### Example: output to terminal

```bash
./sub-filter --cli --stdout
```

You’ll immediately see the final subscription without file creation.

#### Example: using a config file

```bash
./sub-filter --cli --config ./my-config.yaml
```

---

## What do the parameters mean?

| Parameter    | Description                                                       |
| ------------ | ----------------------------------------------------------------- |
| `8000`       | HTTP server port (server mode only)                               |
| `1800`       | Cache time-to-live (TTL) in seconds (1800 = 30 minutes)           |
| `sub.txt`    | List of subscription URLs (one per line)                          |
| `bad.txt`    | Forbidden words (e.g., suspicious domains) to exclude from output |
| `uagent.txt` | Allowed User-Agent strings (e.g., `Clash`, `Shadowrocket`)        |

> 💡 If file paths aren’t provided, the program looks in `./config/`.  
> If a file is missing, the program continues but skips those rules (e.g., no word filtering if `bad.txt` is absent).

---

## New flags: `--config` and `--stdout`

### `--stdout` (CLI mode only)

Instead of saving to `mod_1.txt`, `mod_2.txt`, etc., outputs everything directly to stdout. Useful for piping or copying the subscription instantly.

Example:

```bash
./sub-filter --cli --stdout > my-sub.txt
```

### `--config`

Define **all settings in a single file** (supports **YAML, JSON, or TOML**).

#### Example `config.yaml`:

```yaml
cache_ttl: 3600
sources_file: "./my-subs.txt"
bad_words_file: "./my-blocklist.txt"
allowed_ua:
  - "Clash"
  - "happ"
bad_words:
  - "tracking"
  - "fake"
```

If a field is omitted, the default value is used:

| Field            | Default Value                   |
| ---------------- | ------------------------------- |
| `cache_ttl`      | `1800` (30 minutes)             |
| `sources_file`   | `"./config/sub.txt"`            |
| `bad_words_file` | `"./config/bad.txt"`            |
| `uagent_file`    | `"./config/uagent.txt"`         |
| `cache_dir`      | `/tmp/sub-filter-cache` (Linux) |

> 💡 Config files are especially useful in Docker or systemd deployments.

---

## How to verify it works?

### For server mode:

Request the filtered subscription from the first URL in `sub.txt`:

```bash
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1"
```

If configured correctly, you’ll see a clean, filtered subscription.

> 💡 Tip: Ensure your client’s name (e.g., `Clash`) is listed in `uagent.txt`—otherwise, access may be denied.

### For CLI mode:

After running with `--cli`, check the `sub-filter-cache` directory:

```bash
./sub-filter --cli
```

You’ll find ready-to-use subscription files—no server needed.

Or output directly:

```bash
./sub-filter --cli --stdout
```

---

## How to use in a client?

Add a subscription URL like this in your client:

```
http://server:port/filter?id=number
```

Replace:
- `server` → IP of your router, Raspberry Pi, or server  
- `port` → port specified at startup (e.g., `8000`)  
- `number` → line number in `sub.txt` (first line = `id=1`)

> 🔒 **Security tip**: Run behind a reverse proxy with HTTPS (e.g., Nginx, Caddy, or Cloudflare), especially if exposed to the internet.

---

## Ready-to-use Docker image

Available for Linux `amd64` and `arm64`, built using [ko](.ko.yaml):

```
ghcr.io/viktor45/sub-filter:latest
```

## How to build the Docker image?

Standard build via `Dockerfile`:

```bash
docker build -t sub-filter .
```

## How to run in Docker?

Note: `/tmp/sub-filter-cache` is used for caching in the `distroless` image.

### With Docker:

```bash
docker run -d \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw \
  sub-filter \
  8000 1800
```

### With Podman (Docker alternative):

```bash
podman run -d --replace \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro,z \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw,z \
  sub-filter \
  8000 1800
```

> 📁 Ensure directories exist before starting:
> ```bash
> mkdir -p ./config ./cache
> ```

---

## CLI mode in Docker

Run one-time processing inside Docker:

```bash
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw \
  sub-filter \
  --cli 1800
```

Results appear in your local `./cache` folder.

Or output directly to terminal:

```bash
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw \
  sub-filter \
  --cli --stdout
```



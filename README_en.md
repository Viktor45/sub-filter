[EN](README_en.md) / [RU](README.md)  / [ZH](README_zh.md) 

This translation was made using AI.

- [sub-filter](#sub-filter)
  - [What can it do?](#what-can-it-do)
  - [How to build it?](#how-to-build-it)
  - [How to run it?](#how-to-run-it)
    - [Mode 1: HTTP server (live filtering)](#mode-1-http-server-live-filtering)
      - [Full example](#full-example)
      - [Minimal example](#minimal-example)
    - [Mode 2: CLI mode (one-time processing)](#mode-2-cli-mode-one-time-processing)
      - [Full example](#full-example-1)
      - [Minimal example](#minimal-example-1)
  - [What do the parameters mean?](#what-do-the-parameters-mean)
  - [How to test it?](#how-to-test-it)
    - [In server mode](#in-server-mode)
    - [In CLI mode](#in-cli-mode)
  - [How to use it in your proxy app?](#how-to-use-it-in-your-proxy-app)
  - [Ready-to-use Docker image](#ready-to-use-docker-image)
  - [How to build the Docker image?](#how-to-build-the-docker-image)
  - [How to run it in Docker?](#how-to-run-it-in-docker)
    - [With Docker](#with-docker)
    - [With Podman (a Docker alternative)](#with-podman-a-docker-alternative)
  - [CLI mode in Docker](#cli-mode-in-docker)

# sub-filter

A simple subscription filter

This tool is a smart filter for proxy links (VLESS, VMess, Trojan, Shadowsocks, Hysteria2). It takes public subscription links, checks every server for correctness and safety (for example, blocks unencrypted connections or names with forbidden words), removes anything suspicious, and gives you a clean, working list ready to use in Clash, Sing-Box, routers, or any other proxy client.

If you're wondering why you'd need this, check out our [FAQ](FAQ_en.md).

 ⚠️ This tool does NOT check if proxies are actually working or fast. For that, use https://github.com/kutovoys/xray-checker

---

## What can it do?

✅ Checks proxy links for correctness and removes unsafe or broken ones  
✅ Filters servers by a list of forbidden words (like suspicious domains)  
✅ Blocks known "honeypots"—fake servers sometimes found in public subscriptions  
✅ Caches results (30 minutes by default) so it doesn’t overload networks or servers  
✅ Generates clean, well-formatted subscriptions with clear labels

---

## How to build it?

If you have Go version 1.25 or newer installed, open a terminal and run:

```
go build .
```

After that, you’ll see a file called `sub-filter`—that’s your program!

---

## How to run it?

The program works in two modes: HTTP server or CLI (command line).

### Mode 1: HTTP server (live filtering)

Starts a web server on a port you choose. Subscriptions get filtered “on the fly” every time someone asks for them.

#### Full example

```
./filter 8000 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt
```

#### Minimal example

```
./filter 8000 1800
```

(In this case, it looks for config files in `./config/` automatically.)

### Mode 2: CLI mode (one-time processing)

Processes all subscriptions once and saves the results to your system’s temporary folder (`sub-filter-cache`). Great for cron jobs, automation, or offline use.

#### Full example

```
./filter --cli 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt
```

#### Minimal example

```
./filter --cli
```

(Uses default files from `./config/` and a 1800-second cache time.)

> 💡 Results are saved as `sub-filter-cache/mod_1.txt`, `mod_2.txt`, etc.  
> Rejected lines go into `sub-filter-cache/rejected_1.txt`, etc.

---

## What do the parameters mean?

| Parameter    | Meaning                                                                    |
| ------------ | -------------------------------------------------------------------------- |
| `8000`       | Port for the HTTP server (server mode only)                                |
| `1800`       | How long to keep cached results (1800 seconds = 30 minutes)                |
| `sub.txt`    | List of subscription URLs (one per line)                                   |
| `bad.txt`    | Forbidden words—any server name or domain containing these will be blocked |
| `uagent.txt` | Allowed client names (User-Agent), like `Clash` or `Shadowrocket`          |

> 💡 If you don’t specify file paths, the program looks for them in `./config/`.

---

## How to test it?

### In server mode

Try getting a filtered subscription for the first URL in `sub.txt`:

```
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1"
```

If everything’s set up right, you’ll see a clean subscription.

> 💡 Tip: Make sure your client name (like `Clash`) is listed in `uagent.txt`—that’s how the tool knows it’s allowed.

### In CLI mode

After running with `--cli`, check the `sub-filter-cache` folder:

```
./filter --cli
```

You’ll find ready-to-use subscription files—no server needed!

---

## How to use it in your proxy app?

Add a subscription link like this in your client:

```
http://your-server:port/filter?id=number
```

Replace:
- `your-server` → your Raspberry Pi, router, or server’s IP address  
- `port` → the port you chose when starting (e.g., `8000`)  
- `number` → the line number in `sub.txt` (first line = `id=1`)

> 🔒 If your server is reachable from the internet, it’s safer to put it behind a reverse proxy with HTTPS (like Nginx, Caddy, or Cloudflare).

---

## Ready-to-use Docker image

Available for Linux `amd64` and `arm64`, built using `ko`:

```
ghcr.io/viktor45/sub-filter:latest
```

## How to build the Docker image?

Just build it normally using the included `Dockerfile`:

```
docker build -t sub-filter .
```

## How to run it in Docker?

Note: the cache folder is `/tmp/sub-filter-cache`—this matches the `distroless` setup in the `Dockerfile`.

### With Docker

```
docker run -d \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw \
  sub-filter \
  8000 1800
```

### With Podman (a Docker alternative)

```
podman run -d --replace \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro,z \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw,z \
  sub-filter \
  8000 1800
```

> 📁 Make sure the `./config` and `./cache` folders exist before running:
> ```
> mkdir -p ./config ./cache
> ```

---

## CLI mode in Docker

You can run a one-time filter job inside Docker:

```
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/tmp/sub-filter-cache:rw \
  sub-filter \
  --cli 1800
```

The results will appear in your local `./cache` folder.
[EN](README_en.md) / [RU](README.md)  / [ZH](README_zh.md) 

This translation was made using AI.

- [sub-filter](#sub-filter)
  - [What can the program do?](#what-can-the-program-do)
  - [How to build the program?](#how-to-build-the-program)
  - [How to run?](#how-to-run)
    - [Mode 1: HTTP server (dynamic filtering)](#mode-1-http-server-dynamic-filtering)
      - [Full configuration example](#full-configuration-example)
      - [Minimal configuration example](#minimal-configuration-example)
    - [Mode 2: CLI (one-time processing)](#mode-2-cli-one-time-processing)
      - [Full configuration example](#full-configuration-example-1)
      - [Minimal configuration example](#minimal-configuration-example-1)
  - [What do the parameters mean?](#what-do-the-parameters-mean)
  - [How to check that everything works?](#how-to-check-that-everything-works)
    - [For server mode](#for-server-mode)
    - [For CLI mode](#for-cli-mode)
  - [How to use in a client?](#how-to-use-in-a-client)
  - [How to build a Docker image?](#how-to-build-a-docker-image)
  - [How to run in Docker?](#how-to-run-in-docker)
    - [With Docker](#with-docker)
    - [With Podman (Docker alternative)](#with-podman-docker-alternative)
  - [CLI mode in Docker](#cli-mode-in-docker)

# sub-filter

Simple subscription filter

This program is a smart filter for proxy server links (VLESS, VMess, Trojan, Shadowsocks, Hysteria2). It takes public subscriptions, checks each server for correctness and security (e.g., blocks unencrypted connections or names with forbidden words), removes anything suspicious, and outputs a clean, working list — ready to use in Clash, Sing-Box, routers, and other clients.

If you have questions about the purpose of this program, please read the [FAQ](FAQ_en.md).

⚠️ The program does not check the survivability of proxies. For this, use https://github.com/kutovoys/xray-checker

---

## What can the program do?

✅ Validates links and removes unsafe or broken configurations  
✅ Filters servers by a list of forbidden words (e.g., suspicious domains)  
✅ Blocks known "honeypots" sometimes found in public subscriptions  
✅ Caches results (default: 30 minutes) to avoid overloading networks and servers  
✅ Generates clean, well-formatted subscriptions with clear descriptions

---

## How to build the program?

If you have Go installed (version 1.21 or newer), run in your terminal:

```
go build -o filter .
```

After that, the `filter` file will appear — this is your program.

> 💡 If you're new to the terminal — just copy the command as-is. It will work!

---

## How to run?

The program supports two modes: **HTTP server** and **CLI (command-line)**.

### Mode 1: HTTP server (dynamic filtering)

Starts with a port number. Subscriptions are filtered on-the-fly with each request.

#### Full configuration example

```
./filter 8000 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt
```

#### Minimal configuration example

```
./filter 8000 1800
```

(In this case, the program will look for files in the `./config/` directory)

### Mode 2: CLI (one-time processing)

Processes all subscriptions once and saves results to the `./cache` folder. Ideal for automation, cron jobs, or offline use.

#### Full configuration example

```
./filter --cli 1800 ./config/sub.txt ./config/bad.txt ./config/uagent.txt
```

#### Minimal configuration example

```
./filter --cli
```

(Uses default files from `./config/` and TTL=1800 seconds)

> 💡 Results are saved as `./cache/mod_1.txt`, `./cache/mod_2.txt`, etc.  
> Rejected lines go to `./cache/rejected_1.txt`, etc.

---

## What do the parameters mean?

| Parameter    | Description                                                            |
| ------------ | ---------------------------------------------------------------------- |
| `8000`       | Port on which the server will run (server mode only)                   |
| `1800`       | Cache TTL in seconds (1800 = 30 minutes)                               |
| `sub.txt`    | List of subscription URLs (one per line)                               |
| `bad.txt`    | Words that must not appear in subscriptions (e.g., suspicious domains) |
| `uagent.txt` | Allowed clients (User-Agent), e.g., `Clash`, `Shadowrocket`            |

> 💡 If you don't specify file paths, the program will look for them in `./config/`.

---

## How to check that everything works?

### For server mode

Try requesting the filtered subscription from the first line of `sub.txt`:

```
curl -H "User-Agent: Clash" "http://localhost:8000/filter?id=1"
```

If configured correctly, you'll see a clean subscription.

> 💡 Tip: Make sure your client name (e.g., `Clash`) is in `uagent.txt` — this ensures the subscription loads.

### For CLI mode

After running with `--cli`, check the `./cache` folder:

```
ls -l ./cache/
cat ./cache/mod_1.txt
```

You'll see ready-to-use subscriptions without running a server.

---

## How to use in a client?

Add a subscription of the following form to your client:

```
http://server:port/filter?id=number
```

Replace:
- `server` → IP address of your router, Raspberry Pi, or server  
- `port` → port you specified at startup (e.g., `8000`)  
- `number` → line number from `sub.txt` with the desired subscription (first line = `id=1`)

> 🔒 It's recommended to run the program behind a reverse proxy with HTTPS (e.g., Nginx, Caddy, or Cloudflare), especially if accessible from the internet.

---

## How to build a Docker image?

```
docker build -t sub-filter .
```

---

## How to run in Docker?

### With Docker

```
docker run -d \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/cache:rw \
  sub-filter \
  8000 1800
```

### With Podman (Docker alternative)

```
podman run -d --replace \
  --name sub-filter \
  -p 8000:8000 \
  -v $(pwd)/config:/config:ro,z \
  -v $(pwd)/cache:/cache:rw,z \
  sub-filter \
  8000 1800
```

> 📁 Make sure the `./config` and `./cache` directories exist before running:
> ```
> mkdir -p ./config ./cache
> ```

---

## CLI mode in Docker

You can run one-time processing in Docker:

```
docker run --rm \
  -v $(pwd)/config:/config:ro \
  -v $(pwd)/cache:/cache:rw \
  sub-filter \
  --cli 1800
```

Results will appear in your local `./cache` folder.


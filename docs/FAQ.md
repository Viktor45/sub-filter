[EN](FAQ.md) / [RU](ru/FAQ.md) / [ZH](zh/FAQ.md)

<!-- TOC -->
* [Frequently Asked Questions](#frequently-asked-questions)
  * [Why does this program exist?](#why-does-this-program-exist)
  * [What exactly does the program reject?](#what-exactly-does-the-program-reject)
  * [Why filter by country?](#why-filter-by-country)
  * [How does country filtering work?](#how-does-country-filtering-work)
  * [Where can I see what was rejected?](#where-can-i-see-what-was-rejected)
  * [Why do I get "400 Invalid User-Agent"?](#why-do-i-get-400-invalid-user-agent)
  * [Will my data be sent anywhere?](#will-my-data-be-sent-anywhere)
<!-- TOC -->

# Frequently Asked Questions

## Why does this program exist?

Proxy subscriptions sometimes break because of a single invalid line, causing a
client (on a router or in an app) to reject the entire subscription. Instead of
cleaning subscriptions by hand, this tool automatically removes broken,
insecure, or unwanted servers. It is especially useful for routers and
resource-constrained devices.

> ⚠️ The program **does not test proxy liveness** — only configuration
> correctness.

## What exactly does the program reject?

With the bundled `config/rules.yaml`:

- VLESS with `security=none` (or a missing `security`, which is treated as
  `none`), or missing `sni`
- VLESS missing `pbk` when `security=reality`, `serviceName` when `type=grpc`,
  or `path` for `ws`/`httpupgrade`/`xhttp`/`splithttp`
- VMess with `security` set to `none`, `zero`, or `null` (unencrypted)
- Trojan with any `flow` parameter (removed in Xray-core 2024+)
- Shadowsocks with deprecated CFB/CTR ciphers
- Hysteria2 without `obfs`/`obfs-password`, or with `insecure=1`/`true`
- Servers whose names match a `delete` bad-word rule
- Servers not matching the requested country list (when a country filter is set)
- Links with unsupported schemes or malformed URLs

The full rule set and how to tune it are in
[FILTER_RULES](FILTER_RULES.md).

## Why filter by country?

To use only servers in the jurisdictions you want — for example, to improve
speed and connection stability.

## How does country filtering work?

The program scans the **fragment** of each proxy link (`#...`) for any of these
strings for the requested countries:

- ISO 3166-1 alpha-3 code: `AND`
- Flag emoji: `🇦🇩`
- Common name: `Andorra`
- Native names: `Principat d'Andorra`

Matching is **case-insensitive** and supports **URL decoding**. The two-letter
code you pass (`c=AD`) selects the country but is not itself searched in the
fragment. Links without a fragment do not pass a country filter.

## Where can I see what was rejected?

In server mode, the cache directory (`/tmp/sub-filter-cache` by default) holds,
for each source and country combination:

- `orig_<id>[_c_<CODES>].txt` — the original fetched subscription
- `mod_<id>[_c_<CODES>].txt` — the filtered result
- `rejected_<id>[_c_<CODES>].txt` — rejected lines, each preceded by a
  `# REASON: ...` line

`<CODES>` is the sorted, underscore-joined country codes, e.g.
`rejected_1_c_AD.txt` for `?id=1&c=AD`.

## Why do I get "400 Invalid User-Agent"?

`/filter` and `/merge` only accept requests whose `User-Agent` starts with a
built-in prefix (`clash`, `happ`, `incy`) or matches a pattern in
`config/uagent.txt`. Built-in prefixes are case-sensitive, so use
`User-Agent: clash` (lowercase) with `curl`. Most popular clients are already
covered by `uagent.txt`.

## Will my data be sent anywhere?

No. All processing happens **locally**. The program only:

1. Downloads the public subscriptions you configured,
2. Processes them on your device,
3. Delivers the result to your client (Clash, router, etc.).

**No data is sent to third parties.** The tool can run as a background server
or in one-time CLI mode, needs no cloud services, and can run in a Docker
container on your own device.

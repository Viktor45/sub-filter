[EN](FAQ_en.md) / [RU](FAQ.md)  / [ZH](FAQ_zh.md) 

This translation was made using AI.

- [Frequently Asked Questions](#frequently-asked-questions)
  - [Why does this program exist?](#why-does-this-program-exist)
  - [What exactly does the program remove?](#what-exactly-does-the-program-remove)
  - [Why filter by country?](#why-filter-by-country)
  - [How does country filtering work?](#how-does-country-filtering-work)
  - [Where can I see what the program removed?](#where-can-i-see-what-the-program-removed)
  - [Will my data be sent anywhere?](#will-my-data-be-sent-anywhere)

# Frequently Asked Questions

## Why does this program exist?

Sometimes proxy subscriptions break due to a single invalid line, causing the client (on a router or in an app) to reject the entire subscription. Instead of manually cleaning the subscription or adding servers one by one, this program was created:

**To automatically clean public proxy subscriptions** from broken, insecure, or unwanted servers. Especially useful for routers and resource-constrained devices.

> ⚠️ The program **does not test proxy liveness** — only configuration correctness.

## What exactly does the program remove?

- VLESS with `security=none` (unencrypted traffic — **forbidden in all cases**)
- VLESS missing required parameters: `encryption`, `sni`, and also:
  - `pbk` (when `security=reality`)
  - `serviceName` (when `type=grpc`)
  - `path` (when `type=ws`/`xhttp`)
- VMess without `tls=tls`
- Trojan with misconfigurations (e.g., `type=grpc` without `serviceName`)
- Hysteria2 without `obfs` or `obfs-password`
- Servers with "forbidden words" in their name
- Servers not matching the specified country list

## Why filter by country?

To use only servers located in your desired jurisdictions — for example, to improve speed and connection stability.

## How does country filtering work?

The program scans the **fragment** of the proxy link (`#...`) for any of the following strings:
- ISO 3166-1 alpha-2 country code: `AD`
- ISO 3166-1 alpha-3 country code: `AND`
- Flag emoji: `🇦🇩`
- Common name: `Andorra`
- Native name: `Principat d'Andorra`

Matching is **case-insensitive** and supports **URL decoding**.

## Where can I see what the program removed?

In the cache directory (`/tmp/sub-filter-cache`), two files are created for each subscription:
- `mod_??.txt` — filtered subscription
- `rejected_??.txt` — list of rejected lines with reasons

The filename depends on:
- Subscription number (`?id=1` → `rejected_1.txt`)
- Country code (if filtering by country, e.g., `rejected_1_ad.txt`)

## Will my data be sent anywhere?

No. All operations happen **locally**. The program only:
1. Downloads a public subscription
2. Processes it on your device
3. Delivers the result to your client (Clash, router, etc.)

**No data is sent to third parties.**  
The program can run as a background server or in one-time CLI mode. It requires no cloud services and can even be run in a Docker container on your own device.

---


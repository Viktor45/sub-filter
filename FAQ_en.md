[EN](FAQ_en.md) / [RU](FAQ.md)  / [ZH](FAQ_zh.md) 

This translation was made using AI.

- [Frequently Asked Questions](#frequently-asked-questions)
  - [Why do I need this program?](#why-do-i-need-this-program)
  - [What does the program remove?](#what-does-the-program-remove)
  - [Why remove unencrypted servers?](#why-remove-unencrypted-servers)
  - [Why filter by description if the client can do it?](#why-filter-by-description-if-the-client-can-do-it)
  - [Why does the program use caching?](#why-does-the-program-use-caching)
  - [Where can I see what the program removed?](#where-can-i-see-what-the-program-removed)
  - [Why does the program decode server names?](#why-does-the-program-decode-server-names)
  - [Why filter by User-Agent?](#why-filter-by-user-agent)
  - [What is CLI mode and why use it?](#what-is-cli-mode-and-why-use-it)
  - [Will my data be sent anywhere if I run this program?](#will-my-data-be-sent-anywhere-if-i-run-this-program)

# Frequently Asked Questions

## Why do I need this program?

Sometimes proxy subscriptions break because of a single bad line, causing your router or app to reject the entire list. Instead of manually cleaning the subscription or adding servers one by one, this program was created.

It acts as a "smart filter" between public subscriptions and your device. It cleans the subscription in real time and delivers only what your client can actually use.

⚠️ The program does not check the survivability of proxies. For this, use https://github.com/kutovoys/xray-checker

## What does the program remove?

The program removes servers that:
- use insecure settings (e.g., VLESS without encryption — like sending a postcard),
- contain configuration errors (e.g., gRPC without a service name),
- won’t work in your client due to incompatible parameters.

Additionally, you can provide a list of "forbidden words," and the program will remove any servers whose descriptions contain them.

## Why remove unencrypted servers?

Unencrypted servers are like sending a postcard — anyone who intercepts your traffic can see exactly what you’re doing online. This completely defeats the purpose of using proxy subscriptions, which are meant for privacy and security.

Note: For the Trojan and Hysteria2 protocol, the `insecure` option (skipping certificate validation) is allowed because the traffic itself is still encrypted. But in VLESS, `security=none` means no encryption at all — so such servers are removed.

## Why filter by description if the client can do it?

Some clients can filter on their own. But if you’re using a router, it might be busy with other tasks, and constantly reloading it to tweak subscription filters is inconvenient — proxy settings can be complex, and it’s easy to make a mistake.

It’s much simpler to place this program in front of your router — it handles all the "dirty work" anytime, without interfering with your router’s operation.

## Why does the program use caching?

Without caching, the program would fetch the subscription from the source every time, overloading both your device and the subscription server.

Caching allows you to:
- update subscriptions as often as you need (not just when the author updates),
- avoid overloading the subscription server,
- work faster, since data is already on your device.

All results (both server and CLI modes) are saved in the `./cache` directory.

## Where can I see what the program removed?

In the cache directory (usually `./cache`), files like `rejected_1.txt`, `rejected_2.txt`, etc., are created.  
The number in the filename corresponds to the subscription ID (e.g., `?id=1`, `?id=2`).

These files list the rejected lines and briefly explain why they were removed.  
If no such file exists, nothing was removed from that subscription.

## Why does the program decode server names?

Some subscriptions contain server names in encoded form (e.g., `%59%6F%75%54%75%62%65` instead of `YouTube`).  
To properly check these names for forbidden words, the program temporarily decodes them.

However, the final subscription keeps the original name — the program only checks it, never changes it.

## Why filter by User-Agent?

User-Agent is your app’s "name" (e.g., Clash, Shadowrocket).  
This filter ensures the program only serves subscriptions to intended clients.

This reduces unnecessary network and system load — there’s no point sending data to a browser or bot that can’t use it and doesn’t declare its capabilities.

## What is CLI mode and why use it?

CLI mode (run with `--cli`) processes all subscriptions **once** and saves the results to files. It’s useful if you:

- want to use subscriptions **without running a server** (e.g., from a local file on your phone),
- set up **automatic updates via cron**,
- work **offline** and want a clean subscription ready in advance.

Results are saved in the same `mod_*.txt` files as server mode — so you can easily switch between modes.

## Will my data be sent anywhere if I run this program?

No. All operations happen only on your device — like reading a book at home. No one from the outside can see what you’re doing.

The program only:
- downloads public subscriptions from URLs you specify,
- filters them on your device,
- delivers the result to your client (Clash, router, etc.).

It does not send your data anywhere and has no access to your traffic.


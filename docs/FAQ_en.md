[EN](FAQ_en.md) / [RU](FAQ.md)  / [ZH](FAQ_zh.md) 

This translation was made using AI.

- [Frequently Asked Questions](#frequently-asked-questions)
  - [Why do I need this program at all?](#why-do-i-need-this-program-at-all)
  - [What exactly does the program remove?](#what-exactly-does-the-program-remove)
  - [Why remove servers without encryption?](#why-remove-servers-without-encryption)
  - [Why filter by description if the client can do it itself?](#why-filter-by-description-if-the-client-can-do-it-itself)
  - [Why does the program use caching?](#why-does-the-program-use-caching)
  - [Where can I see what the program removed?](#where-can-i-see-what-the-program-removed)
  - [Why does the program decode server names?](#why-does-the-program-decode-server-names)
  - [Why is there a User-Agent filter?](#why-is-there-a-user-agent-filter)
  - [What is CLI mode and why is it needed?](#what-is-cli-mode-and-why-is-it-needed)
  - [Will my data be sent anywhere if I run this program?](#will-my-data-be-sent-anywhere-if-i-run-this-program)

# Frequently Asked Questions

## Why do I need this program at all?

Sometimes proxy subscriptions break because of just one bad line — and then your client on a router or in an app refuses to load the whole subscription. Instead of manually cleaning such a subscription or adding each server individually, this program was created.

It works as a "smart filter" between a public subscription and your device. In real time, it cleans the subscription of anything unnecessary and delivers only what your client can actually use.

 ⚠️  This program does NOT check if proxies are alive. For that, use https://github.com/kutovoys/xray-checker  

## What exactly does the program remove?

The program removes servers that:
- use insecure settings (for example, VLESS without encryption — like sending a postcard);
- contain configuration errors (for example, gRPC without a service name);
- cannot work in your client due to incompatible parameters.

Additionally, you can specify a list of "forbidden words" — and the program will remove any servers whose descriptions contain those words.

## Why remove servers without encryption?

Servers without encryption are like sending a postcard: anyone who intercepts the traffic will immediately see what you are doing online. This completely defeats the purpose of using proxy subscriptions, as you use them specifically for privacy and security.

Note: for Trojan or Hysteria2, the `insecure` parameter (skipping certificate verification) is allowed because the traffic itself is still encrypted. However, in VLESS, `security=none` means the traffic is sent with no encryption at all — so such servers are removed.

## Why filter by description if the client can do it itself?

Yes, some clients can filter on their own. But if you're using a router, it might be busy with other tasks, and restarting it every time to adjust subscription filters is inconvenient — proxy settings can be complex, and it's easy to miss something.

It's much simpler to put this program in front of it — it will do all the "dirty work" at any time without interfering with the router's operation.

## Why does the program use caching?

Without caching, the program would fetch the subscription from the source website every time. This puts load on both your device and the subscription server.

Caching allows you to:
- get the subscription as often as you need (not as often as the author updates it);
- avoid overloading the subscription server with requests;
- work faster, because the data is already on your device.

All results (for both server and CLI modes) are stored in the system's temporary directory (e.g., `/tmp/sub-filter-cache` on Linux).

## Where can I see what the program removed?

In the cache directory (usually the system's temporary folder, e.g., `/tmp/sub-filter-cache` on Linux), files like `rejected_1.txt`, `rejected_2.txt`, etc. are created.  
The number in the filename corresponds to the subscription number (the one you request via `?id=1`, `?id=2`, etc.).

These files contain a list of removed lines and a brief explanation of why they were discarded.  
If no such file exists, it means nothing was removed from that subscription.

## Why does the program decode server names?

Some subscriptions contain server names in encoded form (e.g., `%59%6F%75%54%75%62%65` instead of `YouTube`).  
To correctly check these names for "forbidden words," the program temporarily decodes them.

However, the final subscription contains the name in its original form — the program only checks it, without modifying it.

## Why is there a User-Agent filter?

User-Agent is the "name" of your application (e.g., Clash, Shadowrocket, etc.).  
This filter ensures the program only delivers subscriptions to clients it is intended for.

This reduces unnecessary load on your network and hardware — there's no point in sending data to, say, a browser or a bot that can't use it anyway and doesn't declare its capabilities.

## What is CLI mode and why is it needed?

CLI mode (launch with the `--cli` flag) allows you to **process all subscriptions once** and save the results to files. This is useful if you:

- want to use subscriptions **without running a server** (e.g., on a phone or in a client that reads files from disk);
- are setting up **automatic updates** via cron;
- are working **offline** and want a clean subscription ready in advance.

**New CLI features:**
- The `--stdout` flag — outputs the result directly to the terminal, without saving files.
- The `--config` flag — lets you specify all settings (example in `config/config.yaml`).

Results are saved to the same files (`mod_*.txt`) as in server mode — so you can easily switch between modes.

## Will my data be sent anywhere if I run this program?

No. All operations happen only on your device — like reading a book at home. No one outside can see what you're doing.

The program only:
- downloads a public subscription from the URL you provide,
- cleans it on your device,
- delivers the result to your client (Clash, router, etc.).

It does not send your data anywhere and has no access to your traffic.
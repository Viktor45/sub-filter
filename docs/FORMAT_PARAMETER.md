[EN](FORMAT_PARAMETER.md) / [RU](ru/FORMAT_PARAMETER.md) / [ZH](zh/FORMAT_PARAMETER.md)

<!-- TOC -->
* [The `format` parameter](#the-format-parameter)
  * [Supported formats](#supported-formats)
    * [Plain text (default)](#plain-text-default)
    * [YAML (Clash/Mihomo)](#yaml-clashmihomo)
    * [Base64](#base64)
    * [Combined: YAML + Base64](#combined-yaml--base64)
  * [YAML conversion details](#yaml-conversion-details)
    * [Proxy names](#proxy-names)
    * [Per-protocol fields](#per-protocol-fields)
  * [Response headers and filenames](#response-headers-and-filenames)
  * [Usage examples](#usage-examples)
  * [Troubleshooting](#troubleshooting)
<!-- TOC -->

# The `format` parameter

The `format=` query parameter of `/filter` and `/merge` transforms the proxy
list into a form suitable for different clients.

| Value              | Result                                        |
| ------------------ | --------------------------------------------- |
| *(empty/absent)*   | Plain text, one proxy URL per line            |
| `yaml`             | Clash/Mihomo-compatible YAML proxy list       |
| `base64`           | Base64-encoded plain text                     |
| `yaml+base64`      | YAML proxy list, then base64-encoded          |

The value is case-insensitive. Only the tokens `yaml` and `base64` are
accepted; anything else returns `400 Bad Request`.

> 📝 In a URL query string a literal `+` is decoded as a space, so
> `format=yaml+base64` and `format=yaml%20base64` are equivalent — both are
> accepted.

## Supported formats

### Plain text (default)

Without `format`, the response contains one proxy URL per line:

```text
/filter?id=1
```

```text
ss://BASE64@example.com:8388#proxy1
vless://uuid@example.com:443?security=tls&sni=example.com#proxy2
```

### YAML (Clash/Mihomo)

`format=yaml` converts every supported proxy link into a structured
Clash/Mihomo proxy entry:

```text
/filter?id=1&format=yaml
/merge?ids=1,2&format=yaml
```

```yaml
proxies:
  - name: "proxy1"
    type: ss
    server: "example.com"
    port: 8388
    cipher: "2022-blake3-aes-256-gcm"
    password: "mypassword"
  - name: "proxy2"
    type: vless
    server: "example.com"
    port: 443
    uuid: "myuuid"
    network: "tcp"
    tls: true
    servername: "example.com"
```

If no proxies remain after filtering, a minimal `proxies: []` document is
returned.

### Base64

`format=base64` base64-encodes the plain-text list:

```text
/filter?id=1&format=base64
```

```text
c3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MQp2bGVzczo...
```

### Combined: YAML + Base64

Both tokens can be given in any order (`yaml+base64` or `base64+yaml`); the
YAML conversion is always applied first, then the result is base64-encoded:

```text
/filter?id=1&format=yaml+base64
```

```text
cHJveGllczoKICAtIG5hbWU6ICJwcm94eTEiCiAgICB0eXBlOiBzcwogICAg...
```

## YAML conversion details

The converter parses the **normalized** links produced by the protocol packages
(SS userinfo is base64 `cipher:password`, VMess is `vmess://BASE64(JSON)`).

- Comments, empty lines, and unsupported schemes (anything other than `ss`,
  `vless`, `vmess`, `trojan`, `hy2`/`hysteria2`) are skipped — they are never
  turned into fake entries.
- All string values are quoted and escaped, so special characters cannot break
  the YAML structure.

### Proxy names

Names are resolved in this order:

1. **VMess**: the `ps` field of the decoded JSON payload, then the URL fragment.
2. **Other protocols**: the URL fragment — a `name=...` part if present,
   otherwise the whole fragment.
3. Query parameters `remark=` or `desc=`.
4. `<hostname>-<index>`, then `proxy-<index>` as a last resort.

### Per-protocol fields

| Protocol    | Emitted fields                                                                                                                                                                                          |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ss`        | `server`, `port`, `cipher`, `password`, optional `plugin: obfs` + `plugin-opts.mode`, `udp`                                                                                                             |
| `vless`     | `server`, `port`, `uuid`, `network`, `tls`, `servername`, `reality-opts` (`public-key`, `short-id`), `client-fingerprint`, `alpn`, `flow`, transport opts (`ws-opts`, `grpc-opts`, `xhttp-opts`), `udp` |
| `vmess`     | `server`, `port`, `uuid`, `alterId`, `cipher`, `network`, `tls`, `servername`, transport opts (`ws-opts`, `h2-opts`, `grpc-opts`)                                                                       |
| `trojan`    | `server`, `port`, `password`, `sni`, `reality-opts`, `skip-cert-verify`, `alpn`, `network`, transport opts, `udp`                                                                                       |
| `hysteria2` | `server`, `port`, `password`, `obfs` (salamander), `sni`, `skip-cert-verify`, `up`, `down`, `udp`                                                                                                       |

Transport notes: the canonical Xray parameter is `type` (`network` is a
fallback); REALITY fields map to `pbk`/`sid`/`fp`; Hysteria2 password comes
from the userinfo or `obfs-password`; legacy `allowInsecure` maps to
`skip-cert-verify`; speed limits read `upmbps`/`downmbps` (with `up`/`down`
fallbacks).

## Response headers and filenames

Responses are served as attachments with safe headers
(`X-Content-Type-Options: nosniff`, RFC 5987 encoded filename).

| Format          | Content-Type                        | File extension |
| --------------- | ----------------------------------- | -------------- |
| Plain (default) | `text/plain; charset=utf-8`         | `.txt`         |
| YAML            | `application/x-yaml; charset=utf-8` | `.yaml`        |
| Base64          | `application/octet-stream`          | `.b64`         |
| YAML + Base64   | `application/octet-stream`          | `.yaml`        |

## Usage examples

```bash
# Plain text (default)
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP"

# YAML for Clash/Mihomo
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml" > profile.yaml

# Merged sources as YAML
curl -H "User-Agent: clash" "http://localhost:8000/merge?ids=1,2&format=yaml"

# Base64-encoded YAML (for embedding)
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml+base64"

# YAML with country filter and line limit
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP&format=yaml&lim=100"
```

> 🔐 All endpoints still require an allowed `User-Agent` and are rate-limited —
> see the [main guide](README.md#request-protection).

## Troubleshooting

| Symptom                            | Cause / solution                                                                |
|------------------------------------|---------------------------------------------------------------------------------|
| `400 Bad Request` on `format=`     | Unknown token (e.g. `json`). Only `yaml` and `base64` are allowed.              |
| Fewer proxies in YAML than in text | Unsupported schemes and unparseable links are skipped during conversion.        |
| Base64 won't decode                | Use a standard decoder (`base64 -d`); ensure no newlines were added in transit. |
| Empty YAML                         | All proxies were filtered out; the response is `proxies: []`.                   |

**Performance notes:** YAML conversion is a single pass over the lines; base64
adds ~33% to the response size; combined formats apply transformations
sequentially. All responses remain subject to rate limiting and `lim`.

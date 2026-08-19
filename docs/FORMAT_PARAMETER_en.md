[EN](FORMAT_PARAMETER_en.md) / [RU](FORMAT_PARAMETER.md) / [ZH](FORMAT_PARAMETER_zh.md)

This translation was made using AI.

- [Format Parameter Documentation](#format-parameter-documentation)
  - [Overview](#overview)
  - [Supported Formats](#supported-formats)
    - [1. Default (Plain Text)](#1-default-plain-text)
    - [2. YAML Format](#2-yaml-format)
    - [3. Base64 Encoding](#3-base64-encoding)
    - [4. Combined Formats](#4-combined-formats)
      - [YAML + Base64](#yaml--base64)
  - [Usage Examples](#usage-examples)
    - [Basic Filter with Default Format](#basic-filter-with-default-format)
    - [Filter as YAML for Clash](#filter-as-yaml-for-clash)
    - [Merge Multiple Sources as YAML](#merge-multiple-sources-as-yaml)
    - [Base64 Encoded YAML (for embedding in configs)](#base64-encoded-yaml-for-embedding-in-configs)
    - [Filter with Country Codes and Format](#filter-with-country-codes-and-format)
  - [Integration with Clients](#integration-with-clients)
    - [Clash / Mihomo](#clash--mihomo)
    - [Base64 for Embedding](#base64-for-embedding)
  - [Query Parameters Reference](#query-parameters-reference)
  - [Troubleshooting](#troubleshooting)
    - [YAML Format Issues](#yaml-format-issues)
    - [Base64 Decoding Issues](#base64-decoding-issues)
  - [Performance Considerations](#performance-considerations)
  - [Compatibility](#compatibility)

# Format Parameter Documentation

## Overview

The `format=` parameter allows you to transform the proxy list response from `/filter` and `/merge` endpoints into different formats suitable for various clients.

## Supported Formats

### 1. Default (Plain Text)
When the `format` parameter is not specified or is empty, the response contains one proxy URL per line.

**Example:**
```
/filter?id=1
```

**Output:**
```
ss://example.com:8388#proxy1
vless://example.com:443#proxy2
trojan://example.com:443#proxy3
```

**Content-Type:** `text/plain; charset=utf-8`  
**File Extension:** `.txt`

---

### 2. YAML Format

Specifying `format=yaml` transforms the proxy list into YAML format compatible with Clash and Mihomo clients.

**Example:**
```
/filter?id=1&format=yaml
/merge?ids=1,2&format=yaml
```

**Output:**
```yaml
proxies:
  - name: "example.com-0"
    url: "ss://example.com:8388#proxy1"
  - name: "example.com-1"
    url: "vless://example.com:443#proxy2"
  - name: "example.com-2"
    url: "trojan://example.com:443#proxy3"
```

**Content-Type:** `application/x-yaml; charset=utf-8`  
**File Extension:** `.yaml`

**Note:** The proxy names are automatically extracted from:
- The URL fragment (e.g., `#name=MyProxy`)
- Query parameters (`remark=`, `desc=`)
- The hostname from the URL
- Generated as `proxy-N` if none of the above are available

---

### 3. Base64 Encoding

Specifying `format=base64` encodes the response in base64. This can be combined with other formats.

**Example:**
```
/filter?id=1&format=base64
```

**Output:**
```
c3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MQp2bGVzczo...
```

**Content-Type:** `application/octet-stream`  
**File Extension:** `.b64`

---

### 4. Combined Formats

You can combine formats using `+` separator or separate them with commas. The formats are applied in order.

**Examples:**

#### YAML + Base64
```
/filter?id=1&format=yaml+base64
```

This first converts to YAML, then encodes the result in base64.

**Output:**
```
cHJveGllczoKICAtIG5hbWU6ICJleGFtcGxlLmNvbS0wIgogICAgdXJsOiAic3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MSI=
```

**Content-Type:** `application/octet-stream`  
**File Extension:** `.yaml.b64`

---

## Usage Examples

### Basic Filter with Default Format
```bash
curl "http://localhost:8080/filter?id=1&c=US,JP"
```

### Filter as YAML for Clash
```bash
curl "http://localhost:8080/filter?id=1&format=yaml" | cat > profile.yaml
```

### Merge Multiple Sources as YAML
```bash
curl "http://localhost:8080/merge?ids=1,2&format=yaml"
```

### Base64 Encoded YAML (for embedding in configs)
```bash
curl "http://localhost:8080/filter?id=1&format=yaml+base64"
```

### Filter with Country Codes and Format
```bash
curl "http://localhost:8080/filter?id=1&c=US,JP,CN&format=yaml"
```

---

## Integration with Clients

### Clash / Mihomo
Use `format=yaml` to get a YAML output compatible with Clash and Mihomo:

```bash
curl "http://localhost:8080/filter?id=1&format=yaml" > clash-proxy.yaml
```

Then import this YAML file in your Clash configuration.

### Base64 for Embedding
When you need to embed the proxy list in other configurations or tools that expect base64-encoded data:

```bash
# Get base64-encoded plaintext proxies
ENCODED=$(curl "http://localhost:8080/filter?id=1&format=base64")

# Get base64-encoded YAML
YAML_ENCODED=$(curl "http://localhost:8080/filter?id=1&format=yaml+base64")
```

---

## Query Parameters Reference

| Parameter | Values                                         | Example        |
| --------- | ---------------------------------------------- | -------------- |
| `format`  | `yaml`, `base64`, `yaml+base64`, `base64+yaml` | `?format=yaml` |
| `id`      | Source ID                                      | `?id=1`        |
| `ids`     | Comma-separated source IDs                     | `?ids=1,2`     |
| `c`       | Country codes                                  | `?c=US,JP`     |
| `lim`     | Line limit                                     | `?lim=100`     |

---

## Troubleshooting

### YAML Format Issues
- The `format` parameter is validated: invalid values (e.g. `json`) return `400 Bad Request`
- The YAML output contains structured proxy fields (`server`, `port`, `password`, `uuid`, etc.) for Clash/Mihomo
- Comments, empty lines, and unsupported schemes (anything other than `ss`, `vless`, `vmess`, `trojan`, `hy2`/`hysteria2`) are ignored
- If no proxies remain, a minimal `proxies: []` document is returned

### Base64 Decoding Issues
- Use standard base64 decoders: `base64 -d` on Linux/Mac or Python `base64` module
- Ensure no newlines are added during transfer
- The Content-Type for base64 responses is `application/octet-stream`

---

## Performance Considerations

- **YAML conversion** adds minimal overhead as it iterates through lines once
- **Base64 encoding** adds ~33% to response size
- **Combining formats** applies transformations sequentially
- All responses are still subject to rate limiting and size limits

---

## Compatibility

- **YAML Format**: Compatible with Clash, Mihomo, and other tools that accept YAML proxy lists
- **Base64 Format**: Compatible with any tool that expects base64-encoded data
- **Default Format**: Compatible with all existing clients and tools

[EN](BADWORDS.md) / [RU](ru/BADWORDS.md) / [ZH](zh/BADWORDS.md)

<!-- TOC -->
* [Bad-word rules (`badwords.yaml`)](#bad-word-rules-badwordsyaml)
  * [What is a "bad word"?](#what-is-a-bad-word)
  * [File structure](#file-structure)
  * [Actions](#actions)
    * [strip](#strip)
    * [delete](#delete)
    * [replace](#replace)
  * [Where rules are applied](#where-rules-are-applied)
  * [Safety limits](#safety-limits)
  * [Regular expressions](#regular-expressions)
    * [YAML escaping](#yaml-escaping)
    * [Case-insensitive matching](#case-insensitive-matching)
  * [Practical examples](#practical-examples)
  * [Pattern writing tips](#pattern-writing-tips)
  * [Debugging](#debugging)
<!-- TOC -->

# Bad-word rules (`badwords.yaml`)

The file [`config/badwords.yaml`](../config/badwords.yaml) contains rules for
cleaning proxy **names** (link fragments) and, for `replace`, the whole link.
Think of it as a dictionary of "bad words" — not for censorship, but for
removing useless, promotional, or dangerous information from server names.

## What is a "bad word"?

A pattern (word, phrase, or regular expression) that appears in a proxy name
and is undesirable in the final list. Examples:

- `[TEST]` — marks a test server
- `[SPAM]` — an explicit spam marker
- `192.168.x.x` — a private IP, a sign of a parsing error
- `v1.2.3` — a version number that clutters the name

## File structure

The file is a YAML array of rules:

```yaml
- pattern: "regex to cut out of the name"
  action: strip

- pattern: "regex that rejects the whole line"
  action: delete

- pattern: "fp=chrome"
  action: replace
  replacement: "fp=firefox"
```

| Field         | Type   | Required        | Description                              |
| ------------- | ------ | --------------- | ---------------------------------------- |
| `pattern`     | string | ✅ yes          | Regular expression (Go `regexp` syntax)  |
| `action`      | string | ✅ yes          | `strip`, `delete`, or `replace`          |
| `replacement` | string | for `replace`   | Replacement string                       |
| `comment`     | string | no              | Free-form note (ignored by the program)  |

An unknown or missing `action` is treated as `delete`.

## Actions

### strip

Removes the matched substring from the name; the server **stays** in the list.
After removal, extra spaces are collapsed and the name is trimmed.

Use for minor junk: versions (`v1.2.3`), test/demo markers, ad tails.

```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: strip
```

`"Server v1.2.3 Fast"` → `"Server Fast"` ✅ accepted

### delete

Rejects the **entire line**; the server is excluded from the list and recorded
in `rejected_*.txt` with the matching rule as the reason.

Use for critical problems: spam/malware markers, private IPs, invalid ports.

```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: delete
```

`"Server [SPAM] in US"` → ❌ rejected

### replace

Replaces the match with the `replacement` string; the server stays in the list.
Unlike `strip`/`delete` (which operate on the decoded name), `replace` is
applied to the **whole normalized link**, so it can fix parameters anywhere in
the URL.

```yaml
- pattern: "fp=chrome"
  action: replace
  replacement: "fp=firefox"
```

## Where rules are applied

- `strip` and `delete` run against the **URL-decoded fragment** (the `#name`
  part) of each link during protocol processing.
- `replace` runs against the **full normalized link** after protocol
  processing and before country filtering.

## Safety limits

Patterns are compiled once at startup with protective limits:

- at most **20 patterns** are used (excess is ignored with a warning);
- a pattern longer than **100 characters** is skipped;
- patterns with nested quantifiers prone to ReDoS (e.g. `(.*)+`) or more than
  3 capture groups are rejected;
- invalid regexes are skipped (logged).

## Regular expressions

`sub-filter` uses Go's `regexp` package (RE2 syntax).

### YAML escaping

YAML itself interprets backslashes in double-quoted strings, so either double
them or use single quotes:

```yaml
# WRONG — YAML consumes one backslash:
pattern: "\[TEST\]"

# CORRECT — doubled backslashes:
pattern: "\\[TEST\\]"

# CORRECT — single-quoted, no YAML escaping:
pattern: '\[TEST\]'
```

### Case-insensitive matching

Add the inline flag `(?i)` at the start of the pattern:

```yaml
- pattern: '(?i)\[demo\]'   # matches [DEMO], [demo], [Demo]
  action: strip
```

## Practical examples

Remove version numbers:

```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: strip
```

Remove demo markers in any bracket style:

```yaml
- pattern: '(?i)\[demo\]|\(demo\)|<demo>'
  action: strip
```

Reject lines with private IPs (parsing-error indicator):

```yaml
- pattern: '(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)'
  action: delete
```

Reject spam/fraud/malware markers:

```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: delete
```

Reject invalid ports (0 or > 65535):

```yaml
- pattern: ':(?:0|6553[6-9]|655[4-9]\d|65[6-9]\d{2}|6[6-9]\d{3}|[7-9]\d{4}|[1-9]\d{5,})'
  action: delete
```

## Pattern writing tips

- Use word boundaries for whole words: `\btest\b` matches `test` but not
  `testing`.
- Escape special characters: `\[TEST\]`, `example\.com`.
- Prefer `(?i)` over listing every case variant.
- Group alternatives: `(?i)(spam|fraud|malware)`.
- Be strict with `delete` rules and cautious with `strip` rules — a too-broad
  `delete` pattern silently removes good servers.
- Order rules logically: `strip` (cleanup) first, `delete` (blocking) second.

## Debugging

- Test patterns at [regex101.com](https://regex101.com) with the **Go** flavor.
- Run `./sub-filter --cli` — if the file parses, the config loads; invalid
  patterns are reported in the log and skipped.
- Check `rejected_<id>.txt` in the cache directory: every rejected line is
  stored there with its reason, including the bad-word rule that matched.

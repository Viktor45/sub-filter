[EN](BADWORDS_en.md) / [RU](BADWORDS.md) / [ZH](BADWORDS_zh.md)

This translation was made using AI.

- [Documentation for `badwords.yaml`](#documentation-for-badwordsyaml)
- [Purpose and Concept](#purpose-and-concept)
  - [What is a "bad word"?](#what-is-a-bad-word)
  - [Two Filtering Strategies](#two-filtering-strategies)
- [File Structure](#file-structure)
  - [Rule Fields](#rule-fields)
  - [Minimal Example](#minimal-example)
- [Action Types](#action-types)
  - [Action: `strip`](#action-strip)
  - [Action: `delete`](#action-delete)
- [Regular Expression Syntax](#regular-expression-syntax)
  - [Basic Constructs](#basic-constructs)
  - [Special Sequences](#special-sequences)
  - [Modifiers](#modifiers)
  - [Escaping Special Characters](#escaping-special-characters)
- [Practical Examples](#practical-examples)
  - [Example 1: Removing Version Numbers](#example-1-removing-version-numbers)
  - [Example 2: Removing Quality/Status Markers](#example-2-removing-qualitystatus-markers)
  - [Example 3: Blocking Private IPs (Parsing Error Indicator)](#example-3-blocking-private-ips-parsing-error-indicator)
  - [Example 4: Blocking Spam and Malware](#example-4-blocking-spam-and-malware)
  - [Example 5: Blocking Invalid Ports](#example-5-blocking-invalid-ports)
- [Pattern Writing Rules](#pattern-writing-rules)
  - [✅ Best Practices](#-best-practices)
  - [⚠️ Common Mistakes](#️-common-mistakes)
- [Debugging and Testing](#debugging-and-testing)
  - [YAML Syntax Validation](#yaml-syntax-validation)
  - [Pattern Testing](#pattern-testing)
  - [Troubleshooting](#troubleshooting)
- [Organization Recommendations](#organization-recommendations)
  - [Rule Order](#rule-order)
  - [YAML Comments](#yaml-comments)
- [Conclusion](#conclusion)

---

## Documentation for `badwords.yaml`

## Purpose and Concept

The `badwords.yaml` file is a **set of rules for filtering and modifying proxy link names** in the `sub-filter` program.

Think of it as a **dictionary of "bad words"**, but not in the sense of censorship—rather, **removing junk, spam, or dangerous information** from server names.

### What is a "bad word"?

A **"bad word"** is a pattern (word, phrase, or regular expression) that appears in a proxy name and is undesirable in the final list. Examples:

- **[TEST]** in the name → indicates a test server (not needed in production lists)
- **[SPAM]** in the name → explicit spam marker
- **192.168.x.x** in the name → private IP (sign of parsing error)
- **v1.2.3** in the name → version number (clutters the name)

### Two Filtering Strategies

`sub-filter` supports **two processing strategies** when a pattern is found:

1. **`strip`** — remove only the found pattern from the name, **keep the server** (server accepted, name cleaned)
2. **`delete`** — remove the **entire line** (server completely rejected)

**The choice of strategy** depends on **the importance of the filtered content**:

- `strip` — for **minor junk** (versions, markers, demo versions)
- `delete` — for **critical errors** (spam, malware, invalid parameters, local IPs)

---

## File Structure

The `badwords.yaml` file contains an **array of rules**. Each rule is an object with two fields:

```yaml
- pattern: "your regular expression"
  action: "strip"

- pattern: "another expression"
  action: "delete"
```

### Rule Fields

| Field     | Type   | Required | Description                             |
| --------- | ------ | -------- | --------------------------------------- |
| `pattern` | string | ✅ yes    | Regular expression (Go `regexp` syntax) |
| `action`  | string | ✅ yes    | `"strip"` or `"delete"`                 |

### Minimal Example

```yaml
# Remove the word "test" from the name
- pattern: "test"
  action: "strip"

# Reject the entire server if the name contains "spam"
- pattern: "\\[spam\\]"
  action: "delete"
```

---

## Action Types

### Action: `strip`

**Behavior:** the matched substring is **removed from the name**, the server **remains in the list**.

**Process:**
1. Find a match with the pattern in the server name
2. Remove the found match
3. Collapse multiple spaces into one
4. Trim spaces at the beginning and end
5. **Return the updated name**

**When to use:**
- Removing versions (`v1.2.3`)
- Removing test markers (`[TEST]`, `[DEMO]`)
- Removing junk that doesn't affect functionality (`#1`, `@admin`, etc.)

**Example result:**
```
Input name:     "My [TEST] Server v1.2.3"
Pattern 1:      "\[TEST\]" (strip)  →  "My  Server v1.2.3"
Pattern 2:      "v\d+\.\d+\.\d+" (strip)  →  "My Server"
Final name:     "My Server"
Status:         ✅ ACCEPTED
```

### Action: `delete`

**Behavior:** the matched substring **rejects the entire line**, the server is **completely excluded** from the list.

**Process:**
1. Find a match with the pattern in the server name
2. If a match is found: **reject the server**
3. If no matches: continue processing

**When to use:**
- Blocking dangerous content (`[SPAM]`, `[MALWARE]`)
- Blocking private IPs (sign of parsing error)
- Blocking non-working ports (`port: 99999`)
- Blocking deprecated protocols

**Example result:**
```
Input name:     "Server [SPAM] in US"
Pattern:        "\\[spam\\]" (delete, case-insensitive)
Result:         ❌ REJECTED (entire line removed)
```

---

## Regular Expression Syntax

`sub-filter` uses the **Go `regexp` package** (POSIX Extended Regular Expression syntax with Go extensions).

### Basic Constructs

| Construct | Meaning                     | Example                      |
| --------- | --------------------------- | ---------------------------- |
| `.`       | Any character (except `\n`) | `a.c` → `abc`, `aXc`         |
| `*`       | 0 or more                   | `ab*c` → `ac`, `abc`, `abbc` |
| `+`       | 1 or more                   | `ab+c` → `abc`, `abbc`       |
| `?`       | 0 or 1                      | `ab?c` → `ac`, `abc`         |
| `[abc]`   | One of the characters       | `[aeiou]` → any vowel        |
| `[^abc]`  | Not one of the characters   | `[^0-9]` → not a digit       |
| `[a-z]`   | Range                       | `[0-9]` → any digit          |
| `(...)`   | Grouping                    | `(ab)+` → `ab`, `abab`       |
| `\|`      | OR                          | `cat\|dog` → `cat` or `dog`  |

### Special Sequences

| Sequence | Meaning                          |
| -------- | -------------------------------- |
| `\d`     | Any digit (0-9)                  |
| `\D`     | Not a digit                      |
| `\w`     | Letter, digit, underscore        |
| `\W`     | Not letter, digit, underscore    |
| `\s`     | Whitespace (space, tab, newline) |
| `\S`     | Non-whitespace character         |
| `^`      | Start of line                    |
| `$`      | End of line                      |
| `\b`     | Word boundary                    |
| `\\`     | Escape special characters        |

### Modifiers

**Go `regexp` uses built-in syntax flags:**

| Flag   | Purpose                                          |
| ------ | ------------------------------------------------ |
| `(?i)` | Case-insensitive search (place at pattern start) |
| `(?m)` | Multiline mode                                   |

**Examples:**
```
(?i)test              # "test", "TEST", "Test" — all match
(?i)\[demo\]          # "[DEMO]", "[demo]", "[Demo]" — all match
```

### Escaping Special Characters

If you need to search for a **literal special character** (not its special meaning), escape it with a backslash:

| Character | Escaping | Example                                           |
| --------- | -------- | ------------------------------------------------- |
| `.`       | `\.`     | `example\.com` → matches "example.com" (with dot) |
| `[`       | `\[`     | `\[TEST\]` → matches "[TEST]" (brackets)          |
| `(`       | `\(`     | `\(v1\)` → matches "(v1)"                         |
| `*`       | `\*`     | `\*plus\*` → matches "*plus*"                     |
| `\`       | `\\`     | `C:\\path\\to\\file` → matches "C:\path\to\file"  |

**⚠️ Important in YAML**: YAML itself uses the backslash for escaping, so **double your backslashes**:

```yaml
# WRONG (YAML will consume one backslash):
pattern: "\[TEST\]"  # YAML reads this as "[TEST" — not what you want!

# CORRECT:
pattern: "\\[TEST\\]"  # YAML reads "\[TEST\]" → regex understands "[TEST]"
```

---

## Practical Examples

### Example 1: Removing Version Numbers

**Task:** remove the version from "Server v1.2.3 Fast", keeping the server.

```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: "strip"
  # Explanation:
  # \b — word boundary (to avoid matching "version")
  # v\d+\.\d+ — "v" + digits + "." + digits (v1.2)
  # (\.\d+)? — optionally ".3"
```

**Result:**
```
Input name:    "Server v1.2.3 Fast"
After strip:   "Server Fast"
Status:        ✅ ACCEPTED with modified name
```

### Example 2: Removing Quality/Status Markers

**Task:** remove markers like `[DEMO]`, `(demo)`, `<demo>` from names—case-insensitive.

```yaml
- pattern: '(?i)\[demo\]|\(demo\)|<demo>'
  action: "strip"
  # Explanation:
  # (?i) — case-insensitive search (at pattern start)
  # \[demo\] — "[demo]" (brackets escaped)
  # | — OR
  # \(demo\) — "(demo)"
  # <demo> — "<demo>"
```

**Result:**
```
"Server [DEMO] US"     →  "Server US"
"My Proxy (demo)"      →  "My Proxy"
"Test <demo> Japan"    →  "Test Japan"
```

### Example 3: Blocking Private IPs (Parsing Error Indicator)

**Task:** reject the entire line if the name contains a private IP (sign of incorrect parsing).

```yaml
- pattern: '(?i)(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+)'
  action: "delete"
  # Explanation:
  # localhost — special name
  # 127\.0\.0\.1 — localhost IP (dots escaped)
  # 192\.168\.\d+\.\d+ — network 192.168.0.0/16
  # 10\.\d+\.\d+\.\d+ — network 10.0.0.0/8
  # 172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+ — network 172.16.0.0/12
```

**Result:**
```
"Proxy 192.168.1.1"    →  ❌ REJECTED
"Server 10.0.0.5"      →  ❌ REJECTED
"Good Server US"       →  ✅ ACCEPTED
```

### Example 4: Blocking Spam and Malware

**Task:** reject a server if its name contains spam, fraud, or malware markers.

```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: "delete"
  # Explanation:
  # (?i) — case-insensitive
  # \[ — opening bracket (escaped)
  # (spam|fraud|malware|phishing|scam) — any of these words
  # \] — closing bracket
```

**Result:**
```
"Server [SPAM] EU"     →  ❌ REJECTED
"Good [fraud] Proxy"   →  ❌ REJECTED
"Normal Server"        →  ✅ ACCEPTED
```

### Example 5: Blocking Invalid Ports

**Task:** reject a server if its name contains a port outside the range 1-65535.

```yaml
- pattern: ':(0|6553[6-9]|655[4-9][0-9]|65[6-9][0-9]{2}|6[6-9][0-9]{3}|[7-9][0-9]{4})'
  action: "delete"
  # Explanation:
  # : — colon (separates address from port)
  # (0|...) — either 0 or numbers > 65535
```

**Result:**
```
"Server:99999"         →  ❌ REJECTED
"Server:0"             →  ❌ REJECTED
"Server:443"           →  ✅ ACCEPTED
```

---

## Pattern Writing Rules

### ✅ Best Practices

1. **Use word boundary `\b` for whole words:**
   ```yaml
   # GOOD — matches "test" but not "testing"
   pattern: '\btest\b'
   action: "strip"
   
   # BAD — matches "test", "testing", and "atesting"
   pattern: 'test'
   action: "strip"
   ```

2. **Escape special characters in YAML (double your backslashes):**
   ```yaml
   # CORRECT
   pattern: '\\[TEST\\]'
   
   # WRONG
   pattern: '\[TEST\]'  # YAML will consume the backslashes!
   ```

3. **Use `(?i)` for case-insensitive search:**
   ```yaml
   # GOOD — matches "TEST", "test", "Test"
   pattern: '(?i)\[demo\]'
   
   # BAD — matches only "[demo]"
   pattern: '\[demo\]'
   ```

4. **Group alternatives in parentheses:**
   ```yaml
   # GOOD
   pattern: '(?i)(spam|fraud|malware)'
   
   # BAD (may be ambiguous)
   pattern: 'spam|fraud|malware'
   ```

5. **For delete rules be strict, for strip rules be careful:**
   ```yaml
   # GOOD — matches only standard version strings
   - pattern: '\bv\d+\.\d+\.\d+\b'
     action: "strip"
   
   # BAD — may accidentally delete something important
   - pattern: '\d+'
     action: "delete"
   ```

### ⚠️ Common Mistakes

| Mistake                             | Example                           | Fix                                      |
| ----------------------------------- | --------------------------------- | ---------------------------------------- |
| Brackets not escaped                | `pattern: '[TEST]'`               | `pattern: '\\[TEST\\]'`                  |
| Missing `(?i)` for case-insensitive | `pattern: '\[demo\]'`             | `pattern: '(?i)\\[demo\\]'`              |
| Pattern too broad                   | `pattern: 'a'`                    | `pattern: '(?i)\\[a\\]'` (be specific)   |
| No escaping in YAML                 | `pattern: "\[TEST\]"`             | `pattern: "\\[TEST\\]"` (double slashes) |
| Word boundary in wrong place        | `pattern: 'test\b'` for "testing" | `pattern: '\btest\b'` (both sides)       |

---

## Debugging and Testing

### YAML Syntax Validation

Make sure your `badwords.yaml` file is syntactically correct:

```bash
# Try to load the config (the program will show parsing errors)
./sub-filter --cli

# If config loads without YAML errors, it will output:
# "Configuration loaded successfully"
```

### Pattern Testing

**Method 1: Online regex tester**

Visit [regex101.com](https://regex101.com):
1. Select **"Go"** from the "Flavor" menu
2. Paste your pattern in the "Regular Expression" field
3. Paste test names in the "Test String" field
4. Check the matches

**Example:**
```
Flavor:        Go
Pattern:       (?i)\[demo\]|\(demo\)|<demo>
Test strings:  
  My [DEMO] Server    ✅ matches
  Test (demo) US      ✅ matches
  Server <demo>       ✅ matches
  Normal Server       ❌ does not match
```

### Troubleshooting

| Problem                                | Cause                                | Solution                                                            |
| -------------------------------------- | ------------------------------------ | ------------------------------------------------------------------- |
| "Error: invalid pattern" on startup    | Syntax error in regex                | Check the pattern on regex101.com with Go flag                      |
| Pattern doesn't match expected strings | Missing `(?i)` or incorrect escaping | Use `(?i)` for case-insensitive; check double slashes in YAML       |
| Strip removes too much                 | Pattern too broad                    | Narrow it down (add `\b` or more specific characters)               |
| Delete rejects good servers            | Pattern matches accidentally         | Make the pattern more specific (e.g., `\[SPAM\]` instead of `SPAM`) |

---

## Organization Recommendations

### Rule Order

It's recommended to **organize rules** logically:

1. **Strip rules first** (cleanup)
   - Versions
   - Test markers
   - Demo markers

2. **Delete rules second** (rejection of critical issues)
   - Spam/malware
   - Private IPs
   - Invalid ports

```yaml
# GOOD ORGANIZATION
# === Strip rules (cleanup) ===
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: "strip"

- pattern: '(?i)\[test(ing|ed|er)?\]'
  action: "strip"

# === Delete rules (blocking) ===
- pattern: '(?i)\[(spam|fraud|malware)\]'
  action: "delete"

- pattern: '192\.168\.\d+\.\d+'
  action: "delete"
```

### YAML Comments

Use YAML comments for documentation:

```yaml
# Remove version strings (v1.2.3, v2.0)
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: "strip"

# Block servers marked as spam
- pattern: '(?i)\[spam\]'
  action: "delete"
```

---

## Conclusion

The `badwords.yaml` file is a powerful tool for **automatic cleanup and filtering** of subscriptions. Proper configuration allows you to:

- ✅ **Keep useful servers** (using `strip`)
- ✅ **Exclude spammed sources** (using `delete`)
- ✅ **Ensure clean final lists** (automatic removal of versions, markers, errors)

**Start with simple patterns** (exact words and phrases), then move to **more complex regular expressions** as needed.

If you have questions — use **regex101.com** for visual pattern testing.

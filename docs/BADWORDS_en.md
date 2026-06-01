[EN](BADWORDS_en.md) / [RU](BADWORDS.md) / [ZH](BADWORDS_zh.md)

This translation was made using AI.

<!-- TOC -->
* [Documentation for `badwords.yaml`](#documentation-for-badwordsyaml)
  * [Purpose and Concept](#purpose-and-concept)
  * [What is a "bad word"?](#what-is-a-bad-word)
  * [Two Filtering Strategies](#two-filtering-strategies)
  * [File Structure](#file-structure)
  * [Rule Fields](#rule-fields)
  * [Minimal Example](#minimal-example)
  * [Action Types](#action-types)
    * [Action: `strip`](#action-strip)
    * [Action: `delete`](#action-delete)
    * [Action: `replace`](#action-replace)
  * [Regular Expression Syntax](#regular-expression-syntax)
    * [Basic Constructs](#basic-constructs)
    * [Special Sequences](#special-sequences)
    * [Modifiers](#modifiers)
    * [Escaping Special Characters](#escaping-special-characters)
  * [Practical Examples](#practical-examples)
    * [Example 1: Removing Version Numbers](#example-1-removing-version-numbers)
    * [Example 2: Removing Quality/Status Markers](#example-2-removing-qualitystatus-markers)
    * [Example 3: Blocking Private IPs (Parsing Error Indicator)](#example-3-blocking-private-ips-parsing-error-indicator)
    * [Example 4: Blocking Spam and Malware](#example-4-blocking-spam-and-malware)
    * [Example 5: Blocking Invalid Ports](#example-5-blocking-invalid-ports)
  * [Pattern Writing Rules](#pattern-writing-rules)
    * [✅ Best Practices](#-best-practices)
    * [⚠️ Common Mistakes](#-common-mistakes)
  * [Debugging and Testing](#debugging-and-testing)
    * [Checking YAML Syntax](#checking-yaml-syntax)
    * [Testing Patterns](#testing-patterns)
    * [Troubleshooting](#troubleshooting)
  * [Organization Recommendations](#organization-recommendations)
    * [Rule Order](#rule-order)
    * [Comments in YAML](#comments-in-yaml)
  * [Conclusion](#conclusion)
<!-- TOC -->

---

# Documentation for `badwords.yaml`

## Purpose and Concept
The `badwords.yaml` file is a set of rules for filtering and modifying proxy link names in the `sub-filter` program.
Think of it as a dictionary of "bad words", not in the sense of censorship, but in the sense of removing useless, promotional, or dangerous information from server names.

## What is a "bad word"?
A "bad word" is a pattern (a word, phrase, or regular expression) that appears in a proxy name and is undesirable in the final list. Examples:
- `[TEST]` in the name → indicates a test server (not needed in the production list)
- `[SPAM]` in the name → explicit spam marker
- `192.168.x.x` in the name → private IP (sign of a parsing error)
- `v1.2.3` in the name → version number (clutters the name)

## Two Filtering Strategies
`sub-filter` supports two primary strategies for handling a matched pattern:
- `strip` — remove only the matched pattern from the name, keep the string (server accepted, name cleaned).
- `delete` — remove the entire line (server completely rejected).

The choice of strategy depends on the importance of the filtered content:
- `strip` — for minor junk (versions, markers, demo versions).
- `delete` — for critical errors (spam, malware, invalid parameters, local IPs).

## File Structure
The `badwords.yaml` file contains an array of rules. Each rule is an object with the following fields:

```yaml
- pattern: "your regular expression for stripping"
  action: "strip"

- pattern: "another expression to delete the entire line"
  action: "delete"

- pattern: "fp=chrome"
  action: "replace"
  replacement: "fp=firefox"
```

## Rule Fields
| Field         | Type   | Required            | Description                                 |
|---------------|--------|---------------------|---------------------------------------------|
| `pattern`     | string | ✅ Yes               | Regular expression (Go `regexp` syntax)     |
| `action`      | string | ✅ Yes               | `strip`, `delete`, or `replace`             |
| `replacement` | string | ✅ Yes for `replace` | Replacement string when `action: "replace"` |

## Minimal Example
```yaml
# Remove the word "test" from the name
- pattern: "test"
  action: "strip"

# Reject the entire server if the name contains "spam"
- pattern: "\\[spam\\]"
  action: "delete"
```

## Action Types

### Action: `strip`
**Behavior:** The matched substring is removed from the name; the server remains in the list.
**Process:**
1. Find a match for the pattern in the server name.
2. Remove the matched substring.
3. Collapse multiple spaces into a single space.
4. Trim leading and trailing whitespace.
5. Return the updated name.

**When to use:**
- Removing versions (`v1.2.3`)
- Removing test markers (`[TEST]`, `[DEMO]`)
- Removing junk and ads that do not affect functionality (`#1`, `@admin`, etc.)

**Example Result:**
- Input name: `"My [TEST] Server v1.2.3"`
- Pattern 1: `"\[TEST\]"` (strip) → `"My  Server v1.2.3"`
- Pattern 2: `"v\d+\.\d+\.\d+"` (strip) → `"My Server"`
- Final name: `"My Server"`
- Status: ✅ ACCEPTED

### Action: `delete`
**Behavior:** The matched substring rejects the entire line; the server is completely excluded from the list.
**Process:**
1. Find a match for the pattern in the server name.
2. If a match is found: reject the server.
3. If no match is found: continue processing.

**When to use:**
- Blocking dangerous content (`[SPAM]`, `[MALWARE]`)
- Blocking private IPs (sign of a parsing error)
- Blocking invalid ports (`port: 99999`)
- Blocking outdated protocols

**Example Result:**
- Input name: `"Server [SPAM] in US"`
- Pattern: `"\\[spam\\]"` (delete, case-insensitive)
- Result: ❌ REJECTED (entire line removed)

### Action: `replace`
**Behavior:** The matched substring is replaced with another string; the server remains in the list.
**Rule Fields:**
- `pattern` — regular expression to search for
- `action: "replace"`
- `replacement` — string to substitute instead of the matched value

**Process:**
1. Find a match for the pattern in the server name.
2. Replace the match with the `replacement` value.
3. Collapse multiple spaces into a single space.
4. Trim leading and trailing whitespace.
5. Return the updated name.

**When to use:**
- Fixing parameters that do not affect functionality but interfere with filtering.
- Adjusting values inside link fragments without deleting the entire line.
- Replacing outdated or unwanted tags with safe alternatives.

**Example:**
```yaml
- pattern: "fp=chrome"
  action: "replace"
  replacement: "fp=firefox"
```
If the rule matches, `fp=chrome` will be replaced with `fp=firefox`, and the string will be preserved.

## Regular Expression Syntax
`sub-filter` uses the Go `regexp` package (POSIX Extended Regular Expression syntax with Go extensions).

### Basic Constructs
| Construct | Meaning                     | Example                      |
|-----------|-----------------------------|------------------------------|
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
| Sequence | Meaning                         |
|----------|---------------------------------|
| `\d`     | Any digit (0-9)                 |
| `\D`     | Not a digit                     |
| `\w`     | Letter, digit, underscore       |
| `\W`     | Not a letter, digit, underscore |
| `\s`     | Space, tab, newline             |
| `\S`     | Not a whitespace character      |
| `^`      | Start of string                 |
| `$`      | End of string                   |
| `\b`     | Word boundary                   |
| `\\`     | Escape special characters       |

### Modifiers
Go `regexp` uses inline syntax flags:
| Flag | Purpose |
| --- | --- |
| `(?i)` | Case-insensitive search (include at the beginning of the pattern) |
| `(?m)` | Multiline mode |

**Examples:**
```regex
(?i)test              # "test", "TEST", "Test" — all match
(?i)\[demo\]          # "[DEMO]", "[demo]", "[Demo]" — all match
```

### Escaping Special Characters
If you need to search for a literal special character (rather than its special meaning), escape it with a backslash:

| Character | Escaping | Example                                                    |
|-----------|----------|------------------------------------------------------------|
| `.`       | `\.`     | `example\.com` → searches for `"example.com"` (with a dot) |
| `[`       | `\[`     | `\[TEST\]` → searches for `"[TEST]"` (square brackets)     |
| `(`       | `\(`     | `\(v1\)` → searches for `"(v1)"`                           |
| `*`       | `\*`     | `\*plus\*` → searches for `"*plus*"`                       |
| `\`       | `\\`     | `C:\\path\\to\\file` → searches for `"C:\path\to\file"`    |

⚠️ **Important in YAML:** YAML itself uses the backslash for escaping, so you must double the backslashes:
```yaml
# WRONG (YAML will consume one slash):
pattern: "\[TEST\]"  # YAML reads this as "[TEST" — not what you want!

# CORRECT:
pattern: "\\[TEST\\]"  # YAML reads "\[TEST\]" → regex understands "[TEST]"
```

## Practical Examples

### Example 1: Removing Version Numbers
**Task:** Remove the version from the name `"Server v1.2.3 Fast"`, keeping the server.
```yaml
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: "strip"
  # Explanation:
  # \b — word boundary (to avoid matching "version")
  # v\d+\.\d+ — "v" + digits + "." + digits (v1.2)
  # (\.\d+)? — optional ".3"
```
**Result:**
- Input name: `"Server v1.2.3 Fast"`
- After strip: `"Server Fast"`
- Status: ✅ ACCEPTED with modified name

### Example 2: Removing Quality/Status Markers
**Task:** Remove markers like `[DEMO]`, `(demo)`, `<demo>` from names — case-insensitively.
```yaml
- pattern: '(?i)\[demo\]|\(demo\)|<demo>'
  action: "strip"
```
**Result:**
- `"Server [DEMO] US"` → `"Server US"`
- `"My Proxy (demo)"` → `"My Proxy"`
- `"Test <demo> Japan"` → `"Test Japan"`

### Example 3: Blocking Private IPs (Parsing Error Indicator)
**Task:** Reject the entire line if the name contains a private IP (sign of incorrect parsing).
```yaml
- pattern: '(?i)(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+)'
  action: "delete"
```
**Result:**
- `"Proxy 192.168.1.1"` → ❌ REJECTED
- `"Server 10.0.0.5"` → ❌ REJECTED
- `"Good Server US"` → ✅ ACCEPTED

### Example 4: Blocking Spam and Malware
**Task:** Reject the server if its name contains spam, fraud, or malware markers.
```yaml
- pattern: '(?i)\[(spam|fraud|malware|phishing|scam)\]'
  action: "delete"
```

### Example 5: Blocking Invalid Ports
**Task:** Reject the server if its name contains a port outside the 1-65535 range.
```yaml
- pattern: ':(0|6553[6-9]|655[4-9][0-9]|65[6-9][0-9]{2}|6[6-9][0-9]{3}|[7-9][0-9]{4})'
  action: "delete"
```

## Pattern Writing Rules

### ✅ Best Practices
- **Use word boundaries `\b` for whole words:**
  ```yaml
  # GOOD — matches "test", but not "testing"
  pattern: '\btest\b'
  ```
- **Escape special characters in YAML (double the backslashes):**
  ```yaml
  pattern: '\\[TEST\\]'
  ```
- **Use `(?i)` for case-insensitive search:**
  ```yaml
  pattern: '(?i)\[demo\]'
  ```
- **Group alternatives with parentheses:**
  ```yaml
  pattern: '(?i)(spam|fraud|malware)'
  ```
- **Be strict for `delete` rules, cautious for `strip` rules.**

### ⚠️ Common Mistakes
| Mistake                                | Example                             | Correction                               |
|----------------------------------------|-------------------------------------|------------------------------------------|
| Square brackets not escaped            | `pattern: '[TEST]'`                 | `pattern: '\\[TEST\\]'`                  |
| Missing `(?i)` for case-insensitive    | `pattern: '\[demo\]'`               | `pattern: '(?i)\\[demo\\]'`              |
| Pattern too broad                      | `pattern: 'a'`                      | `pattern: '(?i)\\[a\\]'` (more specific) |
| Missing escaping in YAML               | `pattern: "\[TEST\]"`               | `pattern: "\\[TEST\\]"` (double slashes) |
| Using word boundary in the wrong place | `pattern: 'test\b'` for `"testing"` | `pattern: '\btest\b'` (on both sides)    |

## Debugging and Testing

### Checking YAML Syntax
Ensure the `badwords.yaml` file is syntactically correct:
```bash
./sub-filter --cli
# If the config loads without YAML errors, it will print:
# "Configuration loaded successfully"
```

### Testing Patterns
**Method 1: Online regex tester**
Visit [regex101.com](https://regex101.com):
1. Select "Go" in the "Flavor" menu.
2. Paste your pattern into the "Regular Expression" field.
3. Paste test names into the "Test String" field.
4. Check the matches.

### Troubleshooting
| Problem                                | Cause                                | Solution                                                            |
|----------------------------------------|--------------------------------------|---------------------------------------------------------------------|
| `"Error: invalid pattern"` on startup  | Syntax error in regex                | Check the pattern on regex101.com with the Go flag                  |
| Pattern doesn't match expected strings | Missing `(?i)` or incorrect escaping | Use `(?i)` for case-insensitive; check double slashes in YAML       |
| `strip` removes too much               | Pattern is too broad                 | Narrow the pattern (add `\b` or more specific characters)           |
| `delete` rejects good servers          | Pattern matches accidentally         | Make the pattern more specific (e.g., `\[SPAM\]` instead of `SPAM`) |

## Organization Recommendations

### Rule Order
It is recommended to order rules logically:
1. **`strip` rules first** (cleaning up junk: versions, test markers, demo markers)
2. **`delete` rules second** (rejecting critical issues: spam/malware, private IPs, invalid ports)

### Comments in YAML
Use YAML comments for documentation:
```yaml
# Remove version strings (v1.2.3, v2.0)
- pattern: '\bv\d+\.\d+(\.\d+)?\b'
  action: "strip"

# Block servers marked as spam
- pattern: '(?i)\[spam\]'
  action: "delete"
```

## Conclusion
The `badwords.yaml` file is a powerful tool for automatically cleaning and filtering subscriptions. 
Proper configuration allows you to:
- ✅ Keep useful servers (using `strip`)
- ✅ Exclude spammed sources (using `delete`)
- ✅ Ensure the cleanliness of the final list (automatic removal of versions, markers, errors)

Start with simple patterns (exact words and phrases), then move on to more complex regular expressions as needed.
If you have questions, use regex101.com for visual pattern testing.

---
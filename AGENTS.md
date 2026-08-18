# AGENTS.md

Repository guidance for coding agents working in `sub-filter`.

**Required:** Go 1.26.0 or higher
**Test Command:** `go test ./...`
**Build:** `go build -o sub-filter .`
**Run:** `./sub-filter` or with `--cli` flag for CLI mode

## Purpose

`sub-filter` is a Go CLI/service application that fetches proxy subscription sources, validates and normalizes proxy links, filters bad words, applies optional country filtering, deduplicates and merges subscriptions, and exposes results via HTTP endpoints or CLI output.

Supported protocols:

- `vless://`
- `vmess://`
- `trojan://`
- `ss://`
- `hysteria2://`
- `hy2://`

Primary behaviors:

- fetch remote or local subscription sources
- validate proxy links per protocol and policy rules
- strip/replace/delete bad-word matches
- filter entries by country markers in URL fragments
- merge multiple source IDs with deduplication
- support HTTP endpoints and CLI mode

## Entry Points

- `main.go`: parses flags, loads config, creates `service.Service`, starts HTTP server or processes CLI.
- `pkg/service/service.go`: main app logic, HTTP handlers, request protections, filtering, merge, caching, and country parsing.
- `pkg/config/config.go`: config schema, nested YAML plus legacy flat key support, runtime loading of sources/rules/bad words/countries/UA allowlist.

## Important Packages

- `pkg/service`: HTTP handlers, request validation, filtering, merge, CLI processing.
- `pkg/config`: config loading, validation, file path resolution.
- `internal/validator`: generic rule engine and validation policies.
- `internal/utils`: URL normalization, host/port validation, country lookup, dedupe helpers.
- `vless`, `vmess`, `trojan`, `ss`, `hysteria2`: protocol-specific parsing/normalization.
- `pkg/errors`: typed application errors.
- `pkg/logger`: structured logging wrapper.

## Runtime Flow

1. `main.go` loads config via `config.Load` and creates `Service`.
2. `pkg/config` loads configured source map, rules, bad-word rules, countries, and optionally allowed user agents.
3. `Service` builds protocol processors and registers HTTP handlers.
4. `/filter` and `/merge` validate requests, rate-limit by IP, check User-Agent, parse country codes, and process sources.
5. Protocol packages match and normalize proxy lines, then service filters and deduplicates the output.
6. Response content is served with safe headers and optional line limiting.

## HTTP Surface

- `/filter`
- `/merge`
- `/health`

Request protections (⚠️ **Security-Critical**):

- **User-Agent allowlist** — validates requests against built-in prefixes and optional file; do not weaken without security review
- **per-IP rate limiting** — prevents abuse; configurable but defaults are intentional
- **strict source ID validation** — enforces `^[a-zA-Z0-9_]+$`, max length 64

## CLI Surface

Flags live in `main.go`.

- `--cli`
- `--stdout`
- `--config`
- `--countries`
- `--country`

CLI accepts source IDs as positional args or processes all configured sources if none are passed.

## Config Reality

The code prefers nested YAML sections `server`, `cache`, `sources`, `validation`, `logging`, but also accepts legacy flat keys for compatibility.

Important nested fields:

- `sources.file`
- `cache.directory`
- `cache.ttl`
- `validation.rules_file`
- `validation.bad_words_file`
- `validation.countries_file`
- `validation.ua_file`
- `validation.max_countries`
- `validation.max_merge_ids`

`config.Load` also honors `SUBFILTER_CONFIG`, `SUBFILTER_PORT`, and `LOG_LEVEL`.

## Country Filtering

- `/filter` and `/merge` use `c=` and `parseCountryCodes`.
- Only two-letter uppercase codes are accepted and validated against loaded countries.
- CLI `--country` also applies country filtering.

## Dedupe and Merge

- dedupe key from `internal/utils.NormalizeLinkKey`
- winner selection via `CompareAndSelectBetter`
- `/merge` accepts repeated `ids`, comma-separated `ids`, and legacy `id`

## Change guidance

- New protocol: implement `ProxyLink`, add tests, register in `createProxyProcessors()`.
- Validation behavior: update `config/rules.yaml`, protocol tests, and relevant docs.
- Config schema changes: update `pkg/config/config.go`, docs, and examples together.
- Preserve rate limiter and User-Agent protections unless there is a security justification.

## Tests

- `go test ./...` — run all tests
- `go test ./pkg/service ./pkg/config ./internal/validator` — test core packages
- `go test ./ss ./vless ./vmess ./trojan ./hysteria2` — test protocol implementations
- `go test -race ./...` — test for race conditions

## Go Development Standards

Refer to [.github/instructions/go.instructions.md](.github/instructions/go.instructions.md) for idiomatic Go practices, naming conventions, and code review standards used in this project.

## Files worth reading first

- `main.go`
- `pkg/service/service.go`
- `pkg/config/config.go`
- `internal/validator/generic.go`
- `internal/utils/utils.go`
- `config/rules.yaml`
- `config/badwords.yaml`
- `docs/README_en.md`
- `docs/FILTER_RULES_en.md`
- `docs/BADWORDS_en.md`

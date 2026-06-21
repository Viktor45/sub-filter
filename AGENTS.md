# AGENTS.md

Repository guidance for coding agents working in `sub-filter`.

## Purpose

`sub-filter` is a Go service and CLI for filtering proxy subscriptions.
Supported protocols:

- `vless://`
- `vmess://`
- `trojan://`
- `ss://`
- `hysteria2://`
- `hy2://`

Primary behaviors:

- fetch remote subscription sources
- validate and normalize links per protocol
- strip or delete links by bad-word regex rules
- filter links by country markers found in URL fragments
- merge and deduplicate subscriptions
- expose filtering through HTTP and CLI modes

## Entry Points

- `main.go`: parses flags, loads config, creates `service.Service`, starts HTTP or CLI mode
- `pkg/service/service.go`: main application logic
- `pkg/config/config.go`: config loading, source validation, runtime data loading

## Important Packages

- `pkg/service`: HTTP handlers, fetch/caching, filtering, merge, CLI processing
- `pkg/config`: YAML config structs, source loading, rules and bad-word loading
- `internal/validator`: generic rule engine used by protocol processors
- `internal/utils`: shared parsing, host validation, dedupe helpers, country matching
- `vless`, `vmess`, `trojan`, `ss`, `hysteria2`: protocol-specific parsing/normalization
- `pkg/errors`: typed application errors
- `pkg/logger`: `slog` wrapper

## Runtime Flow

1. Load config from `config/config.yaml` via `config.Load`.
2. Load source URLs, validation rules, bad-word rules, countries, and allowed user agents.
3. Build protocol processors in `Service.createProxyProcessors()`.
4. Fetch source content over HTTP using a resolved public IP from `SafeSource`.
5. Parse each line by protocol, normalize it, and validate parameters using `rules.yaml`.
6. Optionally filter by country using the URL fragment.
7. Cache filtered, merged, and rejected outputs on disk.

## HTTP Surface

Handlers are registered in `pkg/service/service.go`.

- `/filter`
- `/merge`
- `/health`

Request protections:

- User-Agent allowlist check
- per-IP rate limiting

## CLI Surface

Flags live in `main.go`.

- `--cli`
- `--stdout`
- `--config`
- `--countries`
- `--country`

## Config Reality

The code expects a nested YAML structure matching `pkg/config.Config`, not the flat key layout currently shown in `config/config.yaml`.

Expected top-level sections:

- `server`
- `cache`
- `sources`
- `validation`
- `logging`

Examples:

- `sources.file`
- `cache.directory`
- `cache.ttl`
- `validation.rules_file`
- `validation.bad_words_file`
- `validation.countries_file`
- `validation.ua_file`

Do not assume the shipped `config/config.yaml` is authoritative without checking the struct tags in `pkg/config/config.go`.

## Rules and Validation

Validation is policy-driven.

- Rules are loaded from `config/rules.yaml`
- Bad-word rules are loaded from `config/badwords.yaml`
- `GenericValidator` enforces:
  - required params
  - allowed values
  - forbidden values
  - conditional requirements

Protocol packages mostly parse input and hand normalized params into the validator.

## Country Filtering

Country filtering uses `config/countries.yaml` data and matches against decoded URL fragments.
It checks for:

- alpha-3 code
- flag
- common name
- native names

Filtering logic is implemented in `internal/utils/countries.go` and used from `pkg/service/service.go`.

## Dedupe and Merge

Merge logic is bucketed on disk for reduced peak memory usage.

- per-link dedupe key comes from `internal/utils.NormalizeLinkKey`
- winner selection uses `internal/utils.CompareAndSelectBetter`

## Current Known Drift

These are real repo mismatches agents should account for before editing docs or behavior.

1. `config/config.yaml` is flat, but `pkg/config/config.go` expects nested sections.
2. `docs/README_en.md` documents `/merge?ids=1,2,3`, but the code currently reads repeated query params and does not split comma-separated `ids`.
3. CLI `--country` is documented, but `processSource()` in `pkg/service/service.go` does not currently apply country filtering to CLI output.
4. `ss/ss.go` extracts the Shadowsocks cipher, but currently validates with an empty param map, so `rules.yaml` method rules are not actually enforced there.
5. `docs/EXTENDING_en.md` is stale; processor registration happens by returning a slice from `createProxyProcessors()`, not by mutating a `processors[...]` map.

## Tests

As of the latest repo check, `go test ./...` passes from this workspace.

If Go commands fail in restricted execution with errors like:

- `package fmt is not in std`
- `failed to trim cache`

recheck outside the sandbox before assuming the repo or Go install is broken. This was previously caused by sandbox/cache restrictions, not by repository code.

## Editing Guidance

- Prefer changing code to match actual `Config` structs rather than copying the flat config example.
- When editing protocol behavior, update that protocol's tests.
- When changing validation semantics, inspect both `config/rules.yaml` and the relevant protocol package.
- Keep docs synchronized with code, especially for:
  - config schema
  - `/merge` query syntax
  - CLI country filtering
  - extension instructions

## Useful Commands

```bash
go test ./...
go test ./pkg/service ./pkg/config ./internal/validator
go build .
```

## Files Worth Reading First

- `main.go`
- `pkg/service/service.go`
- `pkg/config/config.go`
- `internal/validator/generic.go`
- `internal/utils/utils.go`
- `internal/utils/countries.go`
- `config/rules.yaml`
- `config/badwords.yaml`
- `docs/README_en.md`

# Copilot instructions for sub-filter

Короткие, практичные указания для агент-ассистентов, работающих в этом репозитории.

**Требуется:** Go 1.26.0 или выше  
**Команда тестов:** `go test ./...`  
**Сборка:** `go build -o sub-filter .`  
**Запуск:** `./sub-filter` или с флагом `--cli` для CLI-режима

## Коротко о проекте

- Язык: Go (module `sub-filter`). Сборка/зависимости через `go mod`.
- Назначение: CLI/HTTP утилита для фильтрации прокси-подписок (VLESS, VMess, Trojan, Shadowsocks, Hysteria2).
- Режимы: HTTP-сервер и CLI — реализованы в `main.go`.

## Архитектура — что важно знать

- `main.go` — CLI флаги, загрузка конфига, создание сервиса, запуск HTTP-сервера, graceful shutdown.
- `pkg/config/config.go` — структура `Config`, поддержка нового вложенного YAML и legacy flat-формата, runtime загрузка sources/rules/badwords/countries/UA allowlist.
- `pkg/service/service.go` — core логика фильтрации, слияния, HTTP handlers, rate limiting, User-Agent проверка, country-коды, кэш.
- `internal/validator` — проверка правил и generic validation engine.
- `internal/utils` — парсинг/нормализация URL, host/port validation, country lookup, dedupe key.
- Протоколы: `ss/`, `vless/`, `vmess/`, `trojan/`, `hysteria2/`.

## Ключевые runtime особенности

- HTTP API:
  - `/filter?id=<id>&c=<codes>&lim=<n>`
  - `/merge?ids=1,2,3&c=<codes>&lim=<n>` — поддерживает как повторяющиеся `ids`, так и comma-separated список; также работает alias `id`.
  - `/health` — GET only.
- CLI:
  - `--cli --stdout --country=AR,AE`
- `--country` применяется при CLI-обработке через `Service.ProcessCLI`.
- User-Agent allowlist проверяется по встроенным префиксам и по файлу `validation.ua_file`.
- Rate limiting на клиента (IP) жестко задано в `pkg/service/service.go`.

## Конфигурация

- Предпочитайте вложенный формат YAML с ключами `server`, `cache`, `sources`, `validation`, `logging`.
- Legacy flat-keys поддерживаются `pkg/config/config.go` для совместимости.
- `config.Load` также читает `SUBFILTER_CONFIG`, `SUBFILTER_PORT`, `LOG_LEVEL`.
- В секции `validation` ожидаются поля `rules_file`, `bad_words_file`, `countries_file`, `ua_file`, `max_countries`, `max_merge_ids`.

## Что менять с осторожностью

- ⚠️ **Не менять `isValidUserAgent` и связанные User-Agent правила без проверки** — это критическая защита от ботов.
- ⚠️ **Не менять параметры rate limiter** (`limiterBurst`, `limiterEvery`) без реального тестирования.
- Не нарушать синхронизацию схемы config и документации.
- Изменения в дедупликации должны учитывать `internal/utils.NormalizeLinkKey` и `CompareAndSelectBetter`.

## Go стандарты разработки

См. [.github/instructions/go.instructions.md](.github/instructions/go.instructions.md) для идиоматичного Go, соглашений об именах и стандартов code review используемых в проекте.

## PR формат

- Кратко: что исправлено (1–2 строки).
- Список файлов и причина изменения (1–2 bullets).
- Тесты: какие добавлены/обновлены и как запускать (`go test ./...`).

## Полезные точки входа для кода

- `main.go`
- `pkg/service/service.go`
- `pkg/config/config.go`
- `internal/validator/validator.go`
- `internal/utils/utils.go`
- `config/rules.yaml`, `config/badwords.yaml`, `config/countries.yaml`
- `docs/README_en.md`, `docs/FILTER_RULES_en.md`, `docs/BADWORDS_en.md`
# Copilot instructions for sub-filter

Короткие, практичные указания для агент-ассистентов, работающих в этом репозитории.

## Коротко о проекте
- Язык: Go (module `sub-filter`). Сборка/зависимости через `go mod`.
- Назначение: CLI/HTTP утилита для фильтрации прокси-подписок (VLESS, VMess, Trojan, Shadowsocks, Hysteria2).
- Режимы: HTTP-сервер (`/filter`), CLI (`--cli`) — реализованы в `main.go`.

## Архитектура — что важно знать
- Входные источники: `config/sub.txt` (списки подписок). Конфиги: `config/config.yaml`, `config/rules.yaml`, `config/countries.yaml`.
- Основные модули:
  - `main.go` — точка входа, режимы работы, HTTP handlers, кэширование в `cfg.CacheDir`.
  - `internal/utils` — общие утилиты для парсинга/нормализации/валидности ссылок (см. `NormalizeLinkKey`, `IsValidHost`).
  - `internal/validator` — интерфейс `Validator` и реализации правил в `validator/*.go`.
  - Пакеты протоколов: `ss/`, `vless/`, `vmess/`, `trojan/`, `hysteria2/` — реализуют `ProxyLink`-процессоры и парсинг конкретных форматов.
- Поток данных: загрузка URL → декодирование/парсинг ссылок → применяются процессоры протоколов → верификация/фильтрация по bad-words и правилам → дедупликация (`NormalizeLinkKey`) → запись в кэш/выдача.

## Проект-специфические конвенции и паттерны
- Валидация: используйте `internal/validator.Validator` через `rules.yaml`. Если правило не найдено — используется `GenericValidator` (см. `main.go:createProxyProcessors`).
- Дедупликация: ключи нормализуются через `internal/utils.NormalizeLinkKey` и сравниваются функцией `CompareAndSelectBetter`.
- Country lookup: файл `config/countries.yaml` загружается в `AppConfig.Countries` и используется в `parseCountryCodes` (ограничение `maxCountryCodes` в `main.go`).
- Ограничения: макс длина id `maxIDLength`, макс страны `maxCountryCodes`, лимит запросов per-IP через `rate.Limiter`.

## Команды для разработки и отладки
- Сборка и запуск:
  - `go build ./...` — собрать все пакеты.
  - `go run main.go` — запустить локально (поддерживает аргументы порта/режима).
  - Пример: `./sub-filter --cli --stdout --country=NL,RU`
- Тесты:
  - `go test ./...` — запустить все тесты.
  - Проверьте пакеты протоколов по отдельности: `go test ./ss` и т.д.
- Docker: пример в `README.md` (имя образа `ghcr.io/viktor45/sub-filter:latest`).

## Что искать при изменениях/пулл-реквестах
- Добавляя новый протокол, копируйте паттерн из `ss/` или `vmess/`: реализуйте `ProxyLink`-интерфейс, тесты `*_test.go` и регистрация в `createProxyProcessors`.
- Изменения в логике дедупликации/нормализации должны обновлять `internal/utils.NormalizeLinkKey` и тесты вокруг `CompareAndSelectBetter`.
- Конфигурация: обновляйте `config/*.yaml` и `docs/FILTER_RULES.md` синхронно.

## Примеры конкретных мест в коде
- HTTP handlers и режимы: [main.go](main.go)
- Форматы и проверка хостов/портов: [internal/utils/utils.go](internal/utils/utils.go)
- Валидатор: [internal/validator/validator.go](internal/validator/validator.go)
- Пример реализации протокола: [ss/ss.go](ss/ss.go), тесты — [ss/ss_test.go](ss/ss_test.go)

## Ограничения и что агент не должен менять без проверки
- Не менять поведение rate-limiter и default-параметры (`limiterBurst`, `limiterEvery`) без тестирования под нагрузкой.
- Не отключать проверки User-Agent (см. `isValidUserAgent`) — это важная защита от ботов.

## Формат PR-описания от агента
- Кратко: что исправлено (1–2 строки).
- Список изменённых файлов и причина изменения (1–2 bullets).
- Тесты: какие добавлены/обновлены и как запускать (`go test ./...`).

Если нужно, уточню или расширю секции (например, подробный маршрут данных при merge/CLI). Оставьте пожелания или укажите, что добавить.

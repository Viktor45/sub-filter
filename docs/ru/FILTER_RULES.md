[EN](../FILTER_RULES.md) / [RU](FILTER_RULES.md) / [ZH](../zh/FILTER_RULES.md)

<!-- TOC -->
* [Правила валидации (`rules.yaml`)](#правила-валидации-rulesyaml)
  * [Как работает валидация](#как-работает-валидация)
  * [Типы правил](#типы-правил)
    * [required_params](#required_params)
    * [allowed_values](#allowed_values)
    * [forbidden_values](#forbidden_values)
    * [conditional](#conditional)
  * [VLESS](#vless)
  * [VMess](#vmess)
  * [Trojan](#trojan)
  * [Shadowsocks](#shadowsocks)
  * [Hysteria2](#hysteria2)
  * [Настройка строгости](#настройка-строгости)
  * [Типичные отклонения](#типичные-отклонения)
  * [Ссылки](#ссылки)
<!-- TOC -->

# Правила валидации (`rules.yaml`)

Файл [`config/rules.yaml`](../../config/rules.yaml) определяет, какие
конфигурации прокси считаются корректными, а какие отклоняются. Он разбит на
секции по протоколам: `vless`, `vmess`, `trojan`, `ss`, `hysteria2`.

Вы можете добавлять собственные правила или изменять существующие. После
редактирования файла перезапустите фильтр.

## Как работает валидация

Парсер каждого протокола извлекает параметры ссылки и передаёт их универсальному
движку правил (`internal/validator`). Проверки выполняются в таком порядке:

1. **`required_params`** — каждый перечисленный параметр должен присутствовать.
2. **`forbidden_values`** — если перечисленный параметр имеет запрещённое
   значение, ссылка отклоняется. Без учёта регистра; подстановочный знак `"*"`
   запрещает любое значение.
3. **`allowed_values`** — если перечисленный параметр присутствует, его значение
   должно быть в списке разрешённых. Без учёта регистра.
4. **`conditional`** — когда все условия `when` совпадают, параметры из
   `require` становятся обязательными. Значения условий сравниваются
   **с учётом регистра** (это логические условия, а не пользовательский ввод).

Ссылка, не прошедшая любую проверку, отклоняется и записывается в файл кэша
`rejected_*.txt` с указанием причины.

> 📝 Некоторые записи `required_params` в штатном `rules.yaml` намеренно
> закомментированы — настройки по умолчанию сознательно мягкие («безопасность
> важнее количества»). См. [Настройка строгости](#настройка-строгости).

## Типы правил

### required_params

Список параметров, которые обязательно должны присутствовать в ссылке.

```yaml
vless:
  required_params:
    - sni
```

Если любой параметр отсутствует, ссылка отклоняется. Эта проверка выполняется
первой.

### allowed_values

Допустимые значения параметра. Проверяются только при наличии параметра.

```yaml
ss:
  allowed_values:
    method:
      - "aes-256-gcm"
      - "chacha20-poly1305"
```

Сравнение без учёта регистра (`aes-256-gcm` = `AES-256-GCM`). Значение вне
списка отклоняет ссылку.

### forbidden_values

Запрещённые значения параметра. Проверяются только при наличии параметра.
Имеют приоритет над `allowed_values`.

```yaml
vless:
  forbidden_values:
    security: ["none"]      # security=none запрещён
    authority: [""]         # пустой authority запрещён

trojan:
  forbidden_values:
    flow: ["*"]             # ЛЮБОЕ значение flow запрещено
```

Подстановочный знак `"*"` запрещает параметр с любым значением.

### conditional

Правила, применяемые только при выполнении определённых условий:

```yaml
conditional:
  - when: { security: "reality" }
    require: ["pbk"]
  - when: { type: "grpc" }
    require: ["serviceName"]
```

Все записи в `when` должны совпасть (логическое И); после этого каждый параметр
из `require` становится обязательным.

---

## VLESS

```yaml
vless:
  required_params:
    - sni
    # encryption необязателен в URI; раскомментируйте, чтобы требовать его
    # - encryption
  forbidden_values:
    security: ["none"]
    authority: [""]
  allowed_values:
    security: ["tls", "reality"]
    type: ["tcp", "ws", "httpupgrade", "grpc", "xhttp", "splithttp"]
    flow:
      - "xtls-rprx-vision"
      - "xtls-rprx-vision-udp443"
      - "xtls-rprx-vision-direct"
    mode: ["gun", "multi"]
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: "ws" }
      require: ["path"]
    - when: { type: "httpupgrade" }
      require: ["path"]
    - when: { type: "xhttp" }
      require: ["path"]
    - when: { type: "splithttp" }
      require: ["path"]
```

| Аспект       | Правило                                                                                                         |
|--------------|-----------------------------------------------------------------------------------------------------------------|
| Обязательные | `sni`                                                                                                           |
| `security`   | только `tls` или `reality`; `none` запрещён. Отсутствие `security` трактуется парсером как `none` и отклоняется |
| `type`       | `tcp`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `splithttp`                                                        |
| `flow`       | `xtls-rprx-vision`, `xtls-rprx-vision-udp443`, `xtls-rprx-vision-direct`                                        |
| `mode`       | `gun`, `multi` (режимы gRPC)                                                                                    |
| Условные     | `security=reality` → `pbk`; `type=grpc` → `serviceName`; `type=ws/httpupgrade/xhttp/splithttp` → `path`         |

**Корректные примеры:**

```text
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=tcp
vless://uuid@example.com:443?encryption=none&sni=example.com&security=reality&pbk=key&type=grpc&serviceName=service&mode=gun
vless://uuid@example.com:443?encryption=none&sni=example.com&security=tls&type=ws&path=/path
```

---

## VMess

```yaml
vmess:
  # uuid по умолчанию не требуется (некоторые реализации его опускают);
  # раскомментируйте, чтобы требовать его
  # required_params:
  #   - uuid
  forbidden_values:
    security: ["null", "zero", "none"]
    scy: ["null"]
  allowed_values:
    net: ["tcp", "ws", "grpc", "httpupgrade", "h2", "xhttp", "splithttp"]
    security: ["auto", "aes-128-gcm", "chacha20-poly1305"]
  conditional:
    - when: { net: "grpc" }
      require: ["serviceName"]
    - when: { net: "ws" }
      require: ["path"]
    - when: { net: "httpupgrade" }
      require: ["path"]
    - when: { net: "xhttp" }
      require: ["path"]
    - when: { net: "splithttp" }
      require: ["path"]
```

| Аспект       | Правило                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| Обязательные | по умолчанию нет (адрес сервера и UUID всё равно проверяет сам парсер)                            |
| `security`   | `auto`, `aes-128-gcm`, `chacha20-poly1305`; `none`, `zero`, `null` **запрещены** (без шифрования) |
| `scy`        | `null` запрещён                                                                                   |
| `net`        | `tcp`, `ws`, `grpc`, `httpupgrade`, `h2`, `xhttp`, `splithttp`                                    |
| Условные     | `net=grpc` → `serviceName`; `net=ws/httpupgrade/xhttp/splithttp` → `path`                         |

> ⚠️ В отличие от старых наборов правил, шифрование `zero` и `none`
> отклоняется, а не допускается.

---

## Trojan

```yaml
trojan:
  # password по умолчанию не требуется; раскомментируйте, чтобы требовать его
  # required_params:
  #   - password
  forbidden_values:
    flow: ["*"]   # flow удалён из Trojan в Xray-core 2024+
  allowed_values:
    type: ["tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp"]
    security: ["tls", "reality"]
    mode: ["gun", "multi"]
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: "ws" }
      require: ["path"]
    - when: { type: "httpupgrade" }
      require: ["path"]
    - when: { type: "xhttp" }
      require: ["path"]
    - when: { type: "splithttp" }
      require: ["path"]
```

| Аспект       | Правило                                                                                                 |
|--------------|---------------------------------------------------------------------------------------------------------|
| Обязательные | по умолчанию нет (парсер всё равно требует корректные хост/порт)                                        |
| `flow`       | **запрещён с любым значением** — удалён из Trojan в Xray-core 2024+                                     |
| `type`       | `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp`, `splithttp`                                                |
| `security`   | `tls`, `reality`                                                                                        |
| `mode`       | `gun`, `multi` (режимы gRPC)                                                                            |
| Условные     | `security=reality` → `pbk`; `type=grpc` → `serviceName`; `type=ws/httpupgrade/xhttp/splithttp` → `path` |

**Корректные примеры:**

```text
trojan://password@example.com:443?security=tls&type=tcp
trojan://password@example.com:443?security=tls&type=grpc&serviceName=service&mode=gun
```

❌ Отклоняется — содержит удалённый параметр `flow`:

```text
trojan://password@example.com:443?flow=xtls-rprx-vision
```

---

## Shadowsocks

```yaml
ss:
  required_params:
    # password и method по умолчанию не требуются;
    # раскомментируйте, чтобы усилить безопасность
    # - password
    # - method
  forbidden_values:
    # устаревшие потоковые шифры (удалены из Xray-core 2024+)
    method:
      - "aes-128-cfb"
      - "aes-256-cfb"
      - "aes-128-ctr"
      - "aes-256-ctr"
  allowed_values:
    method:
      # AEAD-шифры (современный стандарт)
      - "aes-128-gcm"
      - "aes-256-gcm"
      - "chacha20-poly1305"
      - "xchacha20-poly1305"
      # Shadowsocks 2022 (Blake3)
      - "2022-blake3-aes-128-gcm"
      - "2022-blake3-aes-256-gcm"
      - "2022-blake3-chacha20-poly1305"
      # без шифрования; отключено по умолчанию
      # - "none"
```

| Аспект       | Правило                                                                                                                                                                      |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Обязательные | по умолчанию нет (парсер всё равно проверяет синтаксис шифра)                                                                                                                |
| Разрешённые  | AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `xchacha20-poly1305`; SS2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| Запрещённые  | `aes-128-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-256-ctr` (удалены из Xray-core 2024+)                                                                                      |
| `none`       | **не разрешён** по умолчанию (закомментирован в штатных правилах)                                                                                                            |

**Рекомендуется:** `2022-blake3-aes-256-gcm` (самый безопасный и современный)
или `aes-256-gcm` (традиционный AEAD).

```text
ss://2022-blake3-aes-256-gcm:password@example.com:8388   ✅
ss://aes-256-gcm:password@example.com:8388               ✅
ss://aes-256-cfb:password@example.com:8388               ❌ отклонено (устаревший шифр)
```

---

## Hysteria2

```yaml
hysteria2:
  forbidden_values:
    insecure: ["1", "true"]
  required_params:
    - obfs
    - obfs-password
  allowed_values:
    obfs: ["salamander"]
```

| Аспект       | Правило                                                            |
|--------------|--------------------------------------------------------------------|
| Обязательные | `obfs`, `obfs-password` (обфускация обязательна)                   |
| `obfs`       | только `salamander`                                                |
| `insecure`   | `1` / `true` запрещены (проверка сертификата должна быть включена) |

**Корректный пример:**

```text
hy2://password@example.com:443?obfs=salamander&obfs-password=secret
```

---

## Настройка строгости

Штатные правила намеренно строгие. Вы можете их скорректировать:

- **Ослабить**: удалите записи из `forbidden_values` или `conditional`.
- **Усилить**: раскомментируйте записи `required_params` (`encryption` для
  VLESS, `uuid` для VMess, `password` для Trojan, `password`/`method` для SS)
  или снова разрешите нешифрованный метод `none` для Shadowsocks.

Любое изменение требует перезапуска программы.

## Типичные отклонения

Эти отклонения следуют за изменениями в Xray-core и являются самой частой
причиной потери записей в публичных подписках:

| Протокол    | Отклоняется, когда                          | Причина                                                   |
|-------------|---------------------------------------------|-----------------------------------------------------------|
| VLESS       | `security=none` или отсутствует `security`  | Трафик без шифрования                                     |
| VMess       | `security` равен `none`/`zero`/`null`       | Трафик без шифрования                                     |
| Trojan      | любой параметр `flow`                       | Удалён из Trojan в Xray-core 2024+                        |
| Shadowsocks | шифры CFB/CTR                               | Удалены из Xray-core 2024+                                |
| Hysteria2   | нет `obfs`/`obfs-password` или `insecure=1` | Обфускация обязательна; проверка TLS должна быть включена |

## Ссылки

- Xray-core: https://xtls.github.io/
- Trojan: https://trojan-gfw.github.io/
- Shadowsocks: https://shadowsocks.org/

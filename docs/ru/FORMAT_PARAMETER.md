[EN](../FORMAT_PARAMETER.md) / [RU](FORMAT_PARAMETER.md) / [ZH](../zh/FORMAT_PARAMETER.md)

<!-- TOC -->
* [Параметр `format`](#параметр-format)
  * [Поддерживаемые форматы](#поддерживаемые-форматы)
    * [Обычный текст (по умолчанию)](#обычный-текст-по-умолчанию)
    * [YAML (Clash/Mihomo)](#yaml-clashmihomo)
    * [Base64](#base64)
    * [Комбинация: YAML + Base64](#комбинация-yaml--base64)
  * [Детали преобразования в YAML](#детали-преобразования-в-yaml)
    * [Имена прокси](#имена-прокси)
    * [Поля по протоколам](#поля-по-протоколам)
  * [Заголовки ответа и имена файлов](#заголовки-ответа-и-имена-файлов)
  * [Примеры использования](#примеры-использования)
  * [Устранение неполадок](#устранение-неполадок)
<!-- TOC -->

# Параметр `format`

Параметр запроса `format=` для `/filter` и `/merge` преобразует список прокси
в форму, подходящую для разных клиентов.

| Значение              | Результат                                         |
|-----------------------|---------------------------------------------------|
| *(пусто/отсутствует)* | Обычный текст, по одному URL прокси на строку     |
| `yaml`                | YAML-список прокси, совместимый с Clash/Mihomo    |
| `base64`              | Обычный текст, закодированный в base64            |
| `yaml+base64`         | YAML-список прокси, затем закодированный в base64 |

Значение не зависит от регистра. Принимаются только токены `yaml` и `base64`;
любое другое значение возвращает `400 Bad Request`.

> 📝 В строке запроса URL литеральный `+` декодируется как пробел, поэтому
> `format=yaml+base64` и `format=yaml%20base64` эквивалентны — принимаются оба
> варианта.

## Поддерживаемые форматы

### Обычный текст (по умолчанию)

Без `format` ответ содержит по одному URL прокси на строку:

```text
/filter?id=1
```

```text
ss://BASE64@example.com:8388#proxy1
vless://uuid@example.com:443?security=tls&sni=example.com#proxy2
```

### YAML (Clash/Mihomo)

`format=yaml` преобразует каждую поддерживаемую ссылку прокси в
структурированную запись прокси Clash/Mihomo:

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

Если после фильтрации прокси не осталось, возвращается минимальный документ
`proxies: []`.

### Base64

`format=base64` кодирует текстовый список в base64:

```text
/filter?id=1&format=base64
```

```text
c3M6Ly9leGFtcGxlLmNvbTo4Mzg4I3Byb3h5MQp2bGVzczo...
```

### Комбинация: YAML + Base64

Оба токена можно указать в любом порядке (`yaml+base64` или `base64+yaml`);
сначала всегда выполняется преобразование в YAML, затем результат кодируется в
base64:

```text
/filter?id=1&format=yaml+base64
```

```text
cHJveGllczoKICAtIG5hbWU6ICJwcm94eTEiCiAgICB0eXBlOiBzcwogICAg...
```

## Детали преобразования в YAML

Конвертер разбирает **нормализованные** ссылки, которые выдают пакеты
протоколов (userinfo у SS — это base64 `cipher:password`, VMess — это
`vmess://BASE64(JSON)`).

- Комментарии, пустые строки и неподдерживаемые схемы (всё, кроме `ss`,
  `vless`, `vmess`, `trojan`, `hy2`/`hysteria2`) пропускаются — они никогда не
  превращаются в фиктивные записи.
- Все строковые значения заключаются в кавычки и экранируются, поэтому
  специальные символы не могут сломать структуру YAML.

### Имена прокси

Имена определяются в таком порядке:

1. **VMess**: поле `ps` декодированного JSON, затем фрагмент URL.
2. **Остальные протоколы**: фрагмент URL — часть `name=...`, если она есть,
   иначе весь фрагмент целиком.
3. Параметры запроса `remark=` или `desc=`.
4. В крайнем случае `<hostname>-<index>`, затем `proxy-<index>`.

### Поля по протоколам

| Протокол    | Выдаваемые поля                                                                                                                                                                                           |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ss`        | `server`, `port`, `cipher`, `password`, опционально `plugin: obfs` + `plugin-opts.mode`, `udp`                                                                                                            |
| `vless`     | `server`, `port`, `uuid`, `network`, `tls`, `servername`, `reality-opts` (`public-key`, `short-id`), `client-fingerprint`, `alpn`, `flow`, опции транспорта (`ws-opts`, `grpc-opts`, `xhttp-opts`), `udp` |
| `vmess`     | `server`, `port`, `uuid`, `alterId`, `cipher`, `network`, `tls`, `servername`, опции транспорта (`ws-opts`, `h2-opts`, `grpc-opts`)                                                                       |
| `trojan`    | `server`, `port`, `password`, `sni`, `reality-opts`, `skip-cert-verify`, `alpn`, `network`, опции транспорта, `udp`                                                                                       |
| `hysteria2` | `server`, `port`, `password`, `obfs` (salamander), `sni`, `skip-cert-verify`, `up`, `down`, `udp`                                                                                                         |

Замечания по транспорту: канонический параметр Xray — `type` (`network`
используется как запасной); поля REALITY отображаются в `pbk`/`sid`/`fp`;
пароль Hysteria2 берётся из userinfo или `obfs-password`; устаревший
`allowInsecure` отображается в `skip-cert-verify`; ограничения скорости читают
`upmbps`/`downmbps` (с запасными `up`/`down`).

## Заголовки ответа и имена файлов

Ответы отдаются как вложения с безопасными заголовками
(`X-Content-Type-Options: nosniff`, имя файла в кодировке RFC 5987).

| Формат               | Content-Type                        | Расширение файла |
|----------------------|-------------------------------------|------------------|
| Текст (по умолчанию) | `text/plain; charset=utf-8`         | `.txt`           |
| YAML                 | `application/x-yaml; charset=utf-8` | `.yaml`          |
| Base64               | `application/octet-stream`          | `.b64`           |
| YAML + Base64        | `application/octet-stream`          | `.yaml`          |

## Примеры использования

```bash
# Обычный текст (по умолчанию)
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP"

# YAML для Clash/Mihomo
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml" > profile.yaml

# Объединённые источники в YAML
curl -H "User-Agent: clash" "http://localhost:8000/merge?ids=1,2&format=yaml"

# YAML в base64 (для встраивания)
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&format=yaml+base64"

# YAML с фильтром по странам и лимитом строк
curl -H "User-Agent: clash" "http://localhost:8000/filter?id=1&c=US,JP&format=yaml&lim=100"
```

> 🔐 Все эндпоинты по-прежнему требуют разрешённый `User-Agent` и ограничены
> по частоте — см. [основное руководство](README.md#защита-запросов).

## Устранение неполадок

| Симптом                            | Причина / решение                                                                                        |
|------------------------------------|----------------------------------------------------------------------------------------------------------|
| `400 Bad Request` на `format=`     | Неизвестный токен (например, `json`). Разрешены только `yaml` и `base64`.                                |
| В YAML меньше прокси, чем в тексте | Неподдерживаемые схемы и неразбираемые ссылки пропускаются при преобразовании.                           |
| Base64 не декодируется             | Используйте стандартный декодер (`base64 -d`); убедитесь, что при передаче не добавились переводы строк. |
| Пустой YAML                        | Все прокси отфильтрованы; ответ — `proxies: []`.                                                         |

**Замечания о производительности:** преобразование в YAML — один проход по
строкам; base64 добавляет ~33% к размеру ответа; комбинированные форматы
применяют преобразования последовательно. Все ответы по-прежнему подчиняются
ограничению частоты и `lim`.

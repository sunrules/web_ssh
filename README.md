# WebSSH — Web-терминал для SSH через браузер

**WebSSH** — это веб-приложение на Go 1.26.3, которое предоставляет терминал SSH прямо в браузере через WebSocket. Разработано для безопасного удалённого управления серверами в условиях сетевых ограничений РКН.

## Возможности

- **Полноценный SSH-терминал** в браузере через WebSocket + xterm.js (mc, vim, nano, цвета).
- **uTLS-флис-фингерпринтов** в реальном времени: Chrome 133, Chrome 120/115 с Post-Quantum X25519Kyber768, Firefox, iOS, Edge, Safari, Randomized.
- **DoH с расширенным пулом провайдеров** (Cloudflare, Google, Quad9, Mullvad, NextDNS, AdGuard и др.) + автоматический health-check каждые 30 с.
- **DoH-запросы через SOCKS5/Tor** — ISP не видит DNS-запросов.
- **Encrypted Client Hello (ECH)** — реальный SNI шифруется внутри TLS-хендшейка.
- **ChaCha20-Poly1305 обфускация** с KDF через **HKDF-SHA256** (криптографически стойкий).
- **TLS record padding** после хендшейка (имитация поведения Chrome).
- **GREASE-расширения** в ClientHello для противодействия uTLS-детекту.
- **Post-Quantum X25519Kyber768Draft00** — устойчивость к квантовым атакам.
- **Рандомизированный WebSocket endpoint path** — `/<random_hex>` генерируется при старте.
- **Автоматическая ротация SNI-доноров** — 21 актуальный на 2026 домен (www.asus.com, www.samsung.com, www.microsoft.com, www.google.com и др.).
- **Anti-Siberia-flood защита** — лимит TLS-хендшейков (4) + backoff 25 с между батчами.
- **SOCKS5-прокси** (Tor через `enable_tor: true`).
- **IPv6-приоритет** — IPv6-адреса DoH резолва проверяются первыми (ТСПУ хуже фильтрует IPv6).
- **Структурированное логирование** через `slog` с уровнями Info / Warn / Debug.
- **IP-контроль доступа** — белый список IP/подсетей через `access.json`.
- **TLS 1.2/1.3** — автоматическое включение при наличии сертификатов.
- **Graceful shutdown** — корректное завершение сессий при перезапуске.
- **WebSocket: origin check (CSRF), max message size (1 MB), rate limit, ping/pong** (30 с ping, 60 с pong).

## Актуальные стратегии обхода РКН (июнь 2026)

Проект использует следующие стратегии, актуальные на июнь 2026:

### Механизмы обхода (в порядке приоритета)

| # | Механизм | Описание | Настройка |
|---|----------|----------|-----------|
| 1 | **uTLS-ротация fingerprint'ов** | Chrome 133, Chrome 120_PQ, Chrome 115_PQ, Firefox, iOS, Edge, Safari, Randomized. Браузерные fingerprint'ы применяются через встроенный `UTLSIdToSpec` (НЕ через самописный ClientHelloSpec — иначе JA3/JA4 ломается). | `webssh.conf` → `[utls] client_hello` |
| 2 | **DoH с мульти-провайдером** | 9 провайдеров + динамический health-check. При выходе провайдера из строя — исключается из ротации. | `proxy.json` → `doh_providers` |
| 3 | **DoH через SOCKS5/Tor** | DNS-запросы DoH направляются через Tor — ISP не видит DoH-трафика. | `proxy.json` → `socks5` + `doh` |
| 4 | **Маскированный User-Agent** | DoH-запросы используют реальный UA Chrome/Safari/Firefox/Edge вместо `Go-http-client/1.1`. | Встроено |
| 5 | **Post-Quantum криптография** | X25519Kyber768Draft00 в Chrome 120/115 PQ. Устойчиво к квантовым атакам (для защиты данных, не от DPI). | Встроено в `HelloChrome_120_PQ`, `HelloChrome_115_PQ` |
| 6 | **GREASE-расширения** | Добавление GREASE в ClientHello. DPI не может детектировать uTLS по отсутствию GREASE. | Встроено для custom fingerprint'ов |
| 7 | **Encrypted Client Hello (ECH)** | Шифрует реальный SNI внутри TLS-хендшейка. DPI видит только внешний SNI (например, `www.asus.com`). | `proxy.json` → `ech_config` (base64) |
| 8 | **TLS record padding** | После успешного TLS-хендшейка отправляется Chrome-like padding record. Скрывает реальные размеры первых пакетов. | Встроено в `paddedTLSConn` |
| 9 | **ChaCha20-Poly1305 обфускация** | XChaCha20-Poly1305 с KDF через HKDF-SHA256. Случайный nonce на пакет. | `proxy.json` → `obfs_secret` |
| 10 | **SOCKS5/Tor** | Маршрутизация через Tor (только через мосты obfs4/snowflake для РФ 2026). | `-proxy addr` / `proxy.json` → `socks5` |
| 11 | **Рандомизация WebSocket пути** | Уникальный путь `/<16-hex>` при каждом запуске. | Встроено |
| 12 | **Anti-Siberia-flood** | После 4 TLS-хендшейков — пауза 25 с. Предотвращает «Сибирскую блокировку» IP:port на 120 с. | `proxy.json` → `max_tls_attempts`, `tls_strategy_delay` |
| 13 | **Ротация SNI hostname** | 21 актуальный на 2026 домен (www.asus.com, www.samsung.com, www.microsoft.com, www.google.com, www.apple.com и др.) — не в списках ТСПУ. | `proxy.json` → `sni_hostnames` |
| 14 | **Прямые IP-адреса** | Fallback на заранее заданные IP. | `proxy.json` → `direct_ips` |
| 15 | **Альтернативные порты** | Подключение по нестандартным портам (8443, 2053, 2083 и др.). | `proxy.json` → `alt_ports` |
| 16 | **WebSocket origin pin** | Защита от CSRF — WS upgrade принимается только с указанных Origin'ов. | `proxy.json` → `ws_origin_pins` |
| 17 | **WebSocket rate limit** | 512 KB/s, burst 1 MB на сессию. Защита от slow-rate атак. | Встроено |

### Что НЕ реализовано (и почему)

- **QUIC-туннель через `quic-go`** — реальный QUIC требует двусторонней поддержки (на сервере должен быть QUIC-туннель, на клиенте — QUIC-клиент). Поскольку целевой сервис — это обычный `sshd` на TCP, нативный QUIC не применяется. Вместо этого — UDP-обёртка отключена.
- **HTTP/2 CONNECT туннель** — был в исходном коде, но фактически использовал `tls.Client` (Go-фолбэк) и не работал с обычным sshd. Удалён.
- **Серверные стратегии (VLESS-Reality, AmneziaWG)** — выходят за рамки WebSSH. Рекомендуется поднимать их **отдельным процессом** перед sshd.

## Рекомендуемая архитектура для прод (июнь 2026)

WebSSH — это **web-интерфейс** для SSH. Для реального обхода РКН в проде рекомендуется **двухслойная** схема:

```
[Браузер] → [WebSSH :443 (TLS)] → [sshd :22] ← юзер подключается через WebSSH
                                    ↑
                          (или через bypass-слой ↓)

Вариант A: [WebSSH :443] → [Xray-core VLESS+Reality+Vision] → [sshd :22]
Вариант B: [WebSSH :443] → [AmneziaWG 2.0] → [sshd :22]
Вариант C: [WebSSH :443] → [sshd :22 напрямую] (только в безопасных сетях)
```

Стратегии A и B поднимаются отдельным процессом; WebSSH подключается к localhost:22 (или другому локальному порту).

## Быстрый старт

```bash
# Сборка (Go 1.26+)
go build -o webssh -ldflags "-s -w" .

# Запуск на порту 3400
./webssh

# С DoH и SOCKS5
./webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# С debug-логом
./webssh -debug

# Справка
./webssh -h
```

После запуска откройте `http://localhost:3400` (или `https://localhost:3400` при TLS).

**WebSocket путь** генерируется автоматически при каждом запуске (выводится в лог). Старый путь `/ws` также поддерживается для обратной совместимости.

## Установка и сборка

### Требования

- Go 1.26+
- Доступ в интернет для скачивания зависимостей

### Сборка

```bash
git clone https://github.com/sunrules/web_ssh.git
cd web_ssh
go mod tidy
go build -o webssh -ldflags "-s -w" .

# Кросскомпиляция для Linux:
GOOS=linux GOARCH=amd64 go build -o webssh -ldflags "-s -w" .
```

### Запуск как systemd-сервис

Файл `/etc/systemd/system/webssh.service`:

```ini
[Unit]
Description=WebSSH Terminal Service
After=network.target

[Service]
Type=simple
User=vmorozov
Group=vmorozov
WorkingDirectory=/home/vmorozov/DEV/web_ssh
ExecStart=/home/vmorozov/DEV/web_ssh/webssh -p 3400 -key /etc/ssh/ssh_known_hosts
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now webssh
```

## Конфигурация

### `webssh.conf` — настройки по умолчанию и uTLS fingerprint

```ini
# WebSSH configuration
[main]
host = 127.0.0.1
port = 2222

# uTLS Client Hello fingerprint (браузерная эмуляция для обхода DPI).
# Доступные варианты:
#   HelloChrome_Auto    — автоматический выбор актуальной версии Chrome
#   HelloChrome_133     — Chrome 133 (стабильная, рекомендуется)
#   HelloChrome_120     — Chrome 120
#   HelloChrome_120_PQ  — Chrome 120 + Post-Quantum X25519Kyber768
#   HelloChrome_115_PQ  — Chrome 115 + Post-Quantum X25519Kyber768
#   HelloFirefox_Auto   — актуальный Firefox
#   HelloEdge_Auto      — Microsoft Edge
#   HelloSafari_Auto    — Safari
#   HelloIOS_Auto       — iOS Safari
#   HelloRandomized     — случайный fingerprint (экспериментально)
#   HelloGolang         — стандартный Go fingerprint (без обфускации)
[utls]
client_hello = HelloChrome_133
```

### `proxy.json` — настройки обхода блокировок

```json
{
  "socks5": "127.0.0.1:9050",
  "enable_tor": true,
  "doh": "https://dns.cloudflare.com/dns-query",
  "doh_providers": [
    "https://dns.cloudflare.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://mozilla.cloudflare-dns.com/dns-query",
    "https://doh.mullvad.net/dns-query",
    "https://dns.nextdns.io/dns-query",
    "https://dns.adguard-dns.com/dns-query",
    "https://dns.electrolab.ru/dns-query",
    "https://doh.opendns.com/dns-query"
  ],
  "direct_ips": ["198.51.100.1"],
  "alt_ports": [8443, 2053, 2083, 2096, 2222],
  "sni_hostnames": [
    "www.asus.com",
    "www.samsung.com",
    "www.dell.com",
    "www.microsoft.com",
    "www.google.com",
    "www.apple.com"
  ],
  "obfs_secret": "ваш-секрет-32-символа-base64-или-просто-строка",
  "ech_config": "",

  "max_tls_attempts": 4,
  "tls_strategy_delay": 25000000000,

  "ws_read_limit": 1048576,
  "ws_origin_pins": ["https://ваш-домен.ru"]
}
```

**Параметры обхода блокировок:**

- **`socks5`** — адрес SOCKS5-прокси (например `127.0.0.1:9050` для Tor)
- **`enable_tor`** — автоматическая настройка SOCKS5 на `127.0.0.1:9050` если прокси не задан явно
- **`doh`** — основной URL DoH-резолвера
- **`doh_providers`** — список дополнительных DoH-провайдеров (если пусто — используется встроенный пул)
- **`direct_ips`** — список IP-адресов для прямого подключения (fallback)
- **`alt_ports`** — альтернативные порты SSH
- **`sni_hostnames`** — массив доменов для ротации SNI (если пусто — используется встроенный пул 21 доменов)
- **`obfs_secret`** — секрет для ChaCha20-Poly1305 обфускации. Получить: `openssl rand -base64 32`
- **`ech_config`** — Encrypted Client Hello (base64 из DNS HTTPS RR). Если пусто — ECH выключен.
- **`max_tls_attempts`** — макс. TLS-хендшейков перед backoff (default 4)
- **`tls_strategy_delay`** — пауза между батчами TLS в наносекундах (default 25s)
- **`ws_read_limit`** — макс. размер WS-сообщения в байтах (default 1 MB)
- **`ws_origin_pins`** — список разрешённых Origin для CSRF-защиты WS

### `access.json` — контроль доступа по IP

```json
{
  "allowed_ips": [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "*"
  ]
}
```

`"*"` — разрешить все IP. Если файла нет — `["*"]` по умолчанию.

### `cert.pem` / `key.pem` — TLS-сертификаты

Если сертификаты найдены — включится HTTPS (WSS). Создать самоподписанные:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Без TLS весь трафик (включая пароли) передаётся в открытом виде!**
Рекомендуется использовать nginx / Caddy как reverse proxy с Let's Encrypt.

## Используемые библиотеки Go 1.26

- **`github.com/gorilla/websocket`** v1.5.3 — WebSocket-фреймворк
- **`github.com/refraction-networking/utls`** v1.8.2 — эмуляция браузерного TLS handshake (JA3/JA4 fingerprint Chrome/Firefox/Safari)
- **`golang.org/x/crypto/chacha20poly1305`** — XChaCha20-Poly1305 AEAD для обфускации
- **`golang.org/x/crypto/hkdf`** — HKDF-SHA256 для KDF обфускации (замена слабого XOR)
- **`golang.org/x/crypto/ssh`** — SSH-клиент с терминалом и PTY
- **`golang.org/x/crypto/ssh/knownhosts`** — проверка known_hosts
- **`golang.org/x/net/proxy`** — SOCKS5-прокси для SSH-соединений и DoH-запросов
- **`golang.org/x/time/rate`** — token-bucket rate-limiter для WebSocket-команд
- **`log/slog`** — структурированное логирование с уровнями Info / Warn / Debug
- **`sync/atomic`** — атомарные флаги для безопасной остановки горутин
- **`net/http`** — стандартный HTTP-сервер с TLS 1.3
- **`crypto/rand`** — криптографически стойкая генерация рандомизированных путей WebSocket

## Замечания по безопасности

1. **Пароль передаётся в JSON WebSocket** — без TLS это открытый текст. С TLS — безопасно, но логируется на reverse-proxy. Рекомендуется SSH-ключ.
2. **Известные_хосты** — `-key /path/to/known_hosts` обязателен для прода. Без него используется `InsecureIgnoreHostKey`.
3. **SOCKS5 Tor** — обычный Tor (без мостов obfs4/snowflake/webtunnel) уже блокируется в РФ. Нужны мосты.
4. **Origin-pinning** — для прода обязательно настройте `ws_origin_pins` в `proxy.json`.

## Отладка

```bash
# Запуск с подробным логом
./webssh -debug

# Логи пишутся в debug.log рядом с бинарником
tail -f debug.log

# Проверка JA4 fingerprint собственного TLS-соединения
# Сниффите трафик: tcpdump -i any -w /tmp/cap.pcap 'host ваш-сервер'
# Загрузите в https://tls.browserleaks.com/json для просмотра JA3/JA4
```

## Лицензия

MIT.

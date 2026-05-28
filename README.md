# WebSSH — Web-терминал для SSH через браузер

**WebSSH** — это веб-приложение на Go, которое предоставляет терминал SSH прямо в браузере через WebSocket.  
Разработано для безопасного удалённого управления серверами в условиях сетевых ограничений.

## Возможности

- **Полноценный SSH-терминал** в браузере через WebSocket + xterm.js (поддержка mc, vim, nano, цветов).
- **Структурированное логирование** через `slog` с уровнями Info / Warn / Debug.
- **IP-контроль доступа** — белый список IP/подсетей через `access.json`.
- **TLS 1.2/1.3** — автоматическое включение при наличии сертификатов.
- **Graceful shutdown** — корректное завершение сессий при перезапуске.
- **Настройки по умолчанию** — host/port и uTLS fingerprint из `webssh.conf` подставляются в форму браузера.
- **Буфер обмена** — Ctrl+C / Ctrl+V / правая кнопка мыши (копирование/вставка).
- **Поддержка ресайза** — терминал автоматически подстраивается под размер окна.

## Обход блокировок (РКН / DPI 2025–2026)

### Механизмы обхода (в порядке приоритета)

| Механизм | Описание | Настройка |
|---|---|---|
| **Ротация TLS-фингерпринтов** | Автоматический перебор fingerprint'ов: Chrome → Firefox → iOS → Randomized. Если DPI заблокировал конкретный fingerprint, следующая попытка использует другой. Успешный fingerprint кешируется для повторного использования. | Встроено (пул из 4 fingerprint'ов) |
| **Encrypted Client Hello (ECH)** | Шифрует реальный SNI внутри TLS-хендшейка. DPI видит только внешний SNI (напр. `cloudflare.com`), а реальный домен зашифрован. | `proxy.json` → `ech_config` (base64 из DNS) |
| **uTLS Camouflage** | Маскировка SSH под HTTPS-трафик с эмуляцией Chrome/Firefox/Safari. DPI видит браузерный TLS handshake (JA3 fingerprint), а не Go-клиент. Включает ClientHello padding (BoringPaddingStyle) для маскировки размера. | `proxy.json` → `sni_hostname`, `webssh.conf` → `[utls]` |
| **DoH мульти-провайдер** | Цепочка DNS-over-HTTPS провайдеров: Cloudflare → Google → Quad9 → Mozilla. Если один заблокирован — автоматический переход на следующий. | `proxy.json` → `doh_providers` |
| **DoH через SOCKS5/Tor** | DNS-резолвинг DoH направляется через Tor/SOCKS5 — ISP не видит DoH-запросов. | Автоматически при `socks5` + `doh` |
| **Маскировка User-Agent** | DoH-запросы используют случайный реальный User-Agent (Chrome/Safari/Firefox) вместо `Go-http-client/1.1`. | Встроено |
| **Приоритет IPv6** | IPv6-адреса подключаются первыми — DPI РКН хуже фильтрует IPv6 трафик. | Встроено |
| **SOCKS5-прокси** | Маршрутизация SSH через Tor (автонастройка через `enable_tor`). | `-proxy addr` / `proxy.json` → `enable_tor` |
| **Рандомизация WebSocket пути** | При каждом запуске генерируется уникальный путь WebSocket (напр. `/a3f8b2c1e90d4f67`). DPI не может заблокировать фиксированный путь. Старый путь `/ws` также поддерживается для обратной совместимости. | Встроено |
| **XOR Obfuscation (legacy)** | Маскировка SSH-трафика: XOR + fake HTTP-баннер (fallback, если uTLS недоступен). | `proxy.json` → `obfs_secret` |
| **Прямые IP-адреса** | Подключение напрямую по IP с наивысшим приоритетом, минуя DNS-блокировки. | `proxy.json` → `direct_ips` |
| **Альтернативные порты** | Подключение по нестандартным портам (2222, 2053, 8443 и др.). | `proxy.json` → `alt_ports` |
| **TLS ServerHello маскировка** | Веб-сервер маскирует ServerHello: session tickets включены, расширенный список cipher suites (как у реальных серверов). | Встроено |
| **Автоматический перебор стратегий** | Каждая комбинация (адрес + метод обфускации + fingerprint) — отдельная стратегия. Рабочий fingerprint кешируется и используется первым при следующих подключениях. | Встроено |

### Примеры обхода блокировок

```bash
# DoH через Cloudflare с поддержкой IPv6
webssh -doh https://dns.cloudflare.com/dns-query

# DoH + Tor (SOCKS5)
webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# Максимальная защита: uTLS + ECH + DoH через Tor + ротация fingerprint'ов
./webssh -p 3400 -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050 -debug
# sni_hostname, obfs_secret и ech_config задаются в proxy.json
```

## Быстрый старт

```bash
# Сборка
go build -o webssh -ldflags "-s -w" .

# Запуск на порту 3400
./webssh

# С портом, debug, DoH и прокси
./webssh -p 8080 -debug -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# Справка
./webssh -h
```

После запуска откройте браузер на `http://localhost:3400` (или `https://localhost:3400` при TLS).

**WebSocket путь** генерируется автоматически при каждом запуске (выводится в лог). Старый путь `/ws` также поддерживается.

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

# Кросскомпиляция для другой платформы:
GOOS=linux GOARCH=amd64 go build -o webssh -ldflags "-s -w" .
```

### Запуск как systemd-сервис на Linux

Файл `/etc/systemd/system/webssh.service`:

```ini
[Unit]
Description=WebSSH Terminal Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/webssh
ExecStart=/opt/webssh/webssh -p 3400 -key /etc/ssh/ssh_known_hosts
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now webssh
```

## Конфигурация

### `webssh.conf` — настройки по умолчанию и uTLS fingerprint (опционально)

INI-файл в директории с бинарником. Поддерживает секции `[main]` (host/port для формы) и `[utls]` (выбор браузерного fingerprint для DPI-обхода).

```ini
# WebSSH configuration
[main]
host = 127.0.0.1
port = 2222

# uTLS Client Hello fingerprint (браузерная эмуляция для обхода DPI)
[utls]
client_hello = HelloChrome_Auto
```

**Секция `[utls]`** — настройка эмуляции браузерного TLS handshake (JA3 fingerprint):
- `HelloChrome_Auto` — Chrome (автовыбор актуальной версии, рекомендуется)
- `HelloFirefox_Auto` — Firefox
- `HelloEdge_Auto` — Microsoft Edge
- `HelloSafari_Auto` — Safari
- `HelloIOS_Auto` — iOS Safari
- `HelloRandomized` — случайный fingerprint (экспериментально)
- `HelloGolang` — стандартный Go fingerprint (без обфускации)

Если секция `[utls]` отсутствует — по умолчанию используется `HelloChrome_133`.
**Важно:** настроенный fingerprint используется как приоритетный кандидат, но система автоматически перебирает другие fingerprint'и из пула (Chrome, Firefox, iOS, Randomized) если основной заблокирован.

### `proxy.json` — настройки обхода блокировок (опционально)

```json
{
  "socks5": "127.0.0.1:9050",
  "enable_tor": true,
  "doh": "https://dns.cloudflare.com/dns-query",
  "doh_providers": [
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://mozilla.cloudflare-dns.com/dns-query"
  ],
  "direct_ips": ["198.51.100.1"],
  "alt_ports": [8443, 2053, 2083, 2096, 2222],
  "sni_hostname": "cloudflare.com",
  "obfs_secret": "vash-sekretnyy-kluch-32-simvola",
  "ech_config": ""
}
```

CLI-флаги `-doh` и `-proxy` имеют приоритет над `proxy.json`.

**Параметры обхода блокировок:**

- **`socks5`** — адрес SOCKS5-прокси (например `127.0.0.1:9050` для Tor)
- **`enable_tor`** — автоматическая настройка SOCKS5 на `127.0.0.1:9050` если прокси не задан явно
- **`doh`** — основной URL DoH-резолвера (например `https://dns.cloudflare.com/dns-query`)
- **`doh_providers`** — список дополнительных DoH-провайдеров для fallback (если основной заблокирован)
- **`direct_ips`** — список IP-адресов для прямого подключения (в обход DNS, наивысший приоритет)
- **`alt_ports`** — альтернативные порты SSH (перебираются если стандартный порт недоступен)
- **`sni_hostname`** — **TLS Camouflage**: домен для маскировки SSH под HTTPS (например `cloudflare.com`). DPI видит обычный TLS-трафик к легитимному сайту. Это самый сильный метод обфускации.
- **`obfs_secret`** — XOR-обфускация (legacy fallback): секретный ключ для маскировки SSH-протокола.
  - При пустой строке (`""`) XOR-обфускация выключена
  - Если сервер не поддерживает обфускацию, происходит автоматический fallback на plain
  - Рекомендуется: `openssl rand -base64 32`
- **`ech_config`** — **Encrypted Client Hello** (base64): шифрует реальный SNI. Получить: `dig https YOUR_DOMAIN +short`. Если пусто — ECH выключен.

**Приоритет обфускации (в коде):**
1. Если указан `sni_hostname` → TLS Camouflage (самый сильный) с ротацией fingerprint'ов + ECH (если настроен)
2. Если нет `sni_hostname`, но есть `obfs_secret` → XOR obfuscation (legacy)
3. Иначе → plain-соединение без обфускации

**DoH через SOCKS5:** если заданы одновременно `doh` и `socks5`/`enable_tor`, DNS-запросы DoH автоматически направляются через прокси. ISP не видит DoH-трафик.

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

`"*"` — разрешить все IP. Если файла нет — используются `["*"]`.

### `cert.pem` / `key.pem` — TLS-сертификаты

Если сертификаты найдены — включится HTTPS (WSS).  
Создать самоподписанные:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Без TLS весь трафик (включая пароли) передаётся в открытом виде!**
Рекомендуется использовать nginx / Caddy как reverse proxy с Let's Encrypt.

## Использованные технологии Go 1.26

- **`github.com/refraction-networking/utls`** — эмуляция браузерного TLS handshake (JA3 fingerprint Chrome/Firefox/Safari) для обхода DPI. Ротация fingerprint'ов, ECH, ClientHello padding.
- **`log/slog`** — структурированное логирование с уровнями Info, Warn, Debug.
- **`errors.Is` / `fmt.Errorf(%w)`** — корректная обработка и wrapping ошибок.
- **`map[string]any`** — типизированные слайсы вместо `interface{}`.
- **`net/http.ServeMux`** — роутинг без сторонних библиотек.
- **`golang.org/x/net/proxy`** — SOCKS5-прокси для SSH-соединений и DoH-запросов.
- **`golang.org/x/crypto/ssh`** — SSH-клиент с терминалом и PTY.
- **`crypto/rand`** — криптографически стойкая генерация рандомизированных путей WebSocket.

## .gitignore — что попадает в репозиторий

Конфигурационные файлы с IP / логинами / паролями и TLS-сертификаты **не** включаются в git:

| Файл | В git | Причина |
|---|---|---|
| `main.go` | ✅ | Исходный код |
| `go.mod` / `go.sum` | ✅ | Зависимости |
| `static/` | ✅ | Веб-интерфейс (xterm.js) |
| `README.md` | ✅ | Документация |
| `.gitignore` | ✅ | Правила игнорирования |
| `webssh.service` | ✅ | Пример systemd unit |
| `access.json` | ❌ | IP-адреса и сети |
| `proxy.json` | ❌ | Адреса прокси и обхода |
| `webssh.conf` | ❌ | Настройки подключения |
| `cert.pem` / `key.pem` | ❌ | TLS-сертификаты |
| `webssh` / `webssh.exe` | ❌ | Бинарник |
| `debug.log` | ❌ | Логи |

## Структура проекта

```
web_ssh/
├── main.go            # Сервер + SSH-мост + Obfuscation (Go 1.26)
├── go.mod             # Модуль и зависимости (в git)
├── go.sum             # Контрольные суммы (в git)
├── .gitignore         # Правила игнорирования (в git)
├── README.md          # Этот файл (в git)
├── webssh.service     # systemd unit (пример) (в git)
├── static/
│   ├── index.html     # Веб-интерфейс (xterm.js) (в git)
│   ├── script.js      # WebSocket-клиент (в git)
│   └── style.css      # Стили (в git)
├── access.json        # IP-контроль доступа (НЕ в git)
├── proxy.json         # Настройки обхода блокировок (НЕ в git)
├── webssh.conf        # Настройки формы по умолчанию (НЕ в git)
├── cert.pem           # TLS-сертификат (НЕ в git)
└── key.pem            # Ключ TLS (НЕ в git)
```

## Пуш в репозиторий

```bash
# Проверить, какие файлы попадут в коммит
git status

# Добавить все отслеживаемые файлы
git add .

# Создать коммит
git commit -m "feat: DPI bypass — TLS fingerprint rotation, ECH, multi-DoH, randomized WS path"

# Отправить на GitHub
git push origin main
```

## Лицензия

Проект распространяется под лицензией MIT.
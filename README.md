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
- **Индикатор статуса соединения** — цветная точка в заголовке терминала (жёлтый = подключение, зелёный = готово, красный = разорвано).
- **Автоматическое переподключение** — exponential backoff при разрыве соединения (до 5 попыток).

## Обход блокировок (РКН / DPI 2025–2026)

### Механизмы обхода (в порядке приоритета)

| Механизм | Описание | Настройка |
|---|---|---|
| **UDP-капсуляция** | SSH-трафик упаковывается напрямую в UDP (замена полноценного QUIC/HTTP3). Не требует специального ПО на сервере — работает с любым sshd. DPI анализировать UDP-потоки значительно сложнее, чем TCP. | `-quic` / `proxy.json` → `enable_quic: true` |
| **DoH мульти-провайдер с health check** | Цепочка DNS-over-HTTPS провайдеров: Cloudflare → Google → Quad9 → Mozilla. Фоновый мониторинг доступности — если провайдер перестал отвечать, он исключается из ротации. При восстановлении — снова включается. | `proxy.json` → `doh_providers` |
| **DoH через SOCKS5/Tor** | DNS-резолвинг DoH направляется через Tor/SOCKS5 — ISP не видит DoH-запросов. | Автоматически при `socks5` + `doh` |
| **Маскировка User-Agent** | DoH-запросы используют случайный реальный User-Agent (Chrome/Safari/Firefox) вместо `Go-http-client/1.1`. | Встроено |
| **Ротация TLS-фингерпринтов** | Автоматический перебор fingerprint'ов: Chrome 133 → Chrome 120 PQ → Chrome 115 PQ → Firefox → iOS → Randomized. Если DPI заблокировал конкретный fingerprint, следующая попытка использует другой. Успешный fingerprint кешируется для повторного использования. | Встроено (пул из 6 fingerprint'ов) |
| **Post-Quantum криптография** | X25519Kyber768Draft00 — пост-квантовое согласование ключей, устойчивое к атакам квантового компьютера. DPI не может расшифровать TLS handshake даже в будущем. | Встроено в `HelloChrome_120_PQ` и `HelloChrome_115_PQ` |
| **GREASE расширения** | Добавление GREASE (Generate Random Extensions And Sustain Extensibility) в ClientHello — DPI не может детектировать uTLS по отсутствию GREASE. | Встроено для всех fingerprint'ов |
| **Encrypted Client Hello (ECH)** | Шифрует реальный SNI внутри TLS-хендшейка. DPI видит только внешний SNI (напр. `cloudflare.com`), а реальный домен зашифрован. | `proxy.json` → `ech_config` (base64 из DNS) |
| **uTLS Camouflage** | Маскировка SSH под HTTPS-трафик с эмуляцией Chrome/Firefox/Safari. DPI видит браузерный TLS handshake (JA3 fingerprint), а не Go-клиент. Включает ClientHello padding (BoringPaddingStyle) для маскировки размера. | `proxy.json` → `sni_hostname`, `webssh.conf` → `[utls]` |
| **Приоритет IPv6** | IPv6-адреса подключаются первыми — DPI РКН хуже фильтрует IPv6 трафик. | Встроено |
| **SOCKS5-прокси** | Маршрутизация SSH через Tor (автонастройка через `enable_tor`). | `-proxy addr` / `proxy.json` → `enable_tor` |
| **Рандомизация WebSocket пути** | При каждом запуске генерируется уникальный путь WebSocket (напр. `/a3f8b2c1e90d4f67`). DPI не может заблокировать фиксированный путь. Старый путь `/ws` также поддерживается для обратной совместимости. | Встроено |
| **ChaCha20-Poly1305 обфускация** | Криптографически стойкое шифрование трафика (замена XOR). Использует AEAD с XChaCha20-Poly1305. Случайный nonce для каждого пакета. | `proxy.json` → `obfs_secret` |
| **HTTP/2 CONNECT туннель** | Маскировка SSH-трафика под HTTP/2 с TLS. Отправляет CONNECT-запрос с браузерным User-Agent. DPI видит обычный HTTPS в браузере. | `proxy.json` → `sni_hostname` |
| **Ротация SNI hostname** | Автоматический перебор популярных CDN (cloudflare.com, google.com, github.com и др.) в качестве маскирующего SNI. Если DPI заблокировал один домен — используется следующий. | `proxy.json` → `sni_hostnames` (массив) |
| **Прямые IP-адреса** | Подключение напрямую по IP (последний приоритет, только если все остальные стратегии не сработали). | `proxy.json` → `direct_ips` |
| **Альтернативные порты** | Подключение по нестандартным портам (2222, 2053, 8443 и др.). | `proxy.json` → `alt_ports` |
| **TLS ServerHello маскировка** | Веб-сервер маскирует ServerHello: session tickets включены, расширенный список cipher suites (как у реальных серверов). | Встроено |
| **Автоматический перебор стратегий** | Каждая комбинация (адрес + метод обфускации + fingerprint + SNI) — отдельная стратегия. Рабочий fingerprint кешируется и используется первым при следующих подключениях. | Встроено |

### Порядок перебора стратегий подключения

```
1. UDP-капсуляция (QUIC) — пробуется первой, UDP трафик сложно детектится DPI
   ↓ если не сработал (UDP заблокирован)
2. DoH IP + uTLS/PQ/ECH (ротация fingerprint'ов, Post-Quantum)
   ↓ если не сработал
3. DoH IP + ChaCha20 (шифрование поверх TCP)
   ↓ если не сработал
4. Original host + plain/chacha (прямое SSH через Tor/SOCKS5)
   ↓ если не сработал
5. Original host + uTLS/PQ/ECH (TLS camouflage)
   ↓ если не сработал
6. Alt ports + plain/chacha/TLS (другие TCP-порты)
   ↓ если не сработал
7. Direct IPs — только в крайнем случае
```

Каждая стратегия обёрнута в 12-секундный таймаут. После неудачной попытки автоматически переходит к следующей. Первая успешная — устанавливает соединение.

### Примеры обхода блокировок

```bash
# DoH через Cloudflare с поддержкой IPv6
webssh -doh https://dns.cloudflare.com/dns-query

# DoH + Tor (SOCKS5)
webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# Максимальная защита: uTLS + ECH + DoH через Tor + ротация fingerprint'ов + Post-Quantum
./webssh -p 3400 -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050 -debug
# sni_hostnames, obfs_secret и ech_config задаются в proxy.json
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
client_hello = HelloChrome_133
```

**Секция `[utls]`** — настройка эмуляции браузерного TLS handshake (JA3 fingerprint):
- `HelloChrome_133` — Chrome 133 (стабильная версия, рекомендуется)
- `HelloFirefox_Auto` — Firefox
- `HelloEdge_Auto` — Microsoft Edge
- `HelloSafari_Auto` — Safari
- `HelloIOS_Auto` — iOS Safari
- `HelloRandomized` — случайный fingerprint (экспериментально)
- `HelloGolang` — стандартный Go fingerprint (без обфускации)

Если секция `[utls]` отсутствует — по умолчанию используется `HelloChrome_133`.
**Важно:** настроенный fingerprint используется как приоритетный кандидат, но система автоматически перебирает другие fingerprint'и из пула (Chrome 133, Chrome 120 PQ, Chrome 115 PQ, Firefox, iOS, Randomized) если основной заблокирован.

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
  "sni_hostnames": [
    "cloudflare.com",
    "google.com",
    "github.com",
    "microsoft.com"
  ],
  "obfs_secret": "vash-sekretnyy-kluch-32-simvola",
  "ech_config": ""
}
```

CLI-флаги `-doh` и `-proxy` имеют приоритет над `proxy.json`.

**Параметры обхода блокировок:**

- **`socks5`** — адрес SOCKS5-прокси (например `127.0.0.1:9050` для Tor)
- **`enable_tor`** — автоматическая настройка SOCKS5 на `127.0.0.1:9050` если прокси не задан явно
- **`doh`** — основной URL DoH-резолвера (например `https://dns.cloudflare.com/dns-query`)
- **`doh_providers`** — список дополнительных DoH-провайдеров для fallback (с фоновым health check каждые 30с)
- **`direct_ips`** — список IP-адресов для прямого подключения (в обход DNS, наивысший приоритет)
- **`alt_ports`** — альтернативные порты SSH (перебираются если стандартный порт недоступен)
- **`sni_hostname`** — **TLS Camouflage**: домен для маскировки SSH под HTTPS (например `cloudflare.com`)
- **`sni_hostnames`** — массив доменов для ротации SNI (перебираются, если DPI заблокировал конкретный)
- **`obfs_secret`** — **ChaCha20-Poly1305 обфускация**: секретный ключ для шифрования трафика
  - При пустой строке (`""`) ChaCha20-обфускация выключена
  - Рекомендуется: `openssl rand -base64 32`
- **`ech_config`** — **Encrypted Client Hello** (base64): шифрует реальный SNI. Получить: `dig https YOUR_DOMAIN +short`. Если пусто — ECH выключен.

**Приоритет обфускации (в коде):**
1. Если указан `sni_hostname` или `sni_hostnames` → TLS Camouflage с ротацией fingerprint'ов + Post-Quantum + ECH
2. Если указан `sni_hostname` или `sni_hostnames` → HTTP/2 CONNECT туннель
3. Если нет SNI, но есть `obfs_secret` → ChaCha20-Poly1305 обфускация
4. Иначе → plain-соединение без обфускации

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

- **`github.com/refraction-networking/utls`** — эмуляция браузерного TLS handshake (JA3 fingerprint Chrome/Firefox/Safari) для обхода DPI. Ротация fingerprint'ов, ECH, GREASE, Post-Quantum X25519Kyber768Draft00.
- **`golang.org/x/crypto/chacha20poly1305`** — ChaCha20-Poly1305 AEAD шифрование для обфускации трафика (замена XOR).
- **`log/slog`** — структурированное логирование с уровнями Info, Warn, Debug.
- **`errors.Is` / `fmt.Errorf(%w)`** — корректная обработка и wrapping ошибок.
- **`map[string]any`** — типизированные слайсы вместо `interface{}`.
- **`net/http.ServeMux`** — роутинг без сторонних библиотек.
- **`sync/atomic`** — атомарный флаг для безопасной остановки горутин.
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
git commit -m "feat: DPI bypass — PQ crypto, GREASE, ChaCha20, H2 CONNECT, SNI rotation, DoH health check, reconnection"

# Отправить на GitHub
git push origin main
```

## Лицензия

Проект распространяется под лицензией MIT.
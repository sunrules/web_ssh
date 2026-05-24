# WebSSH — Web-терминал для SSH через браузер

**WebSSH** — это веб-приложение на Go, которое предоставляет терминал SSH прямо в браузере через WebSocket.  
Разработано для безопасного удалённого управления серверами без установки дополнительного ПО на клиентской машине.

## Возможности

- **Полноценный SSH-терминал** в браузере через WebSocket.
- **Два режима работы:**
  - **Стандартный** — полнофункциональный терминал с xterm.js (цвета, копирование/вставка, ресайз).
  - **HTML3** (`-html3`) — для текстовых/legacy-браузеров, совместимость с HTML 3.2.
- **Структурированное логирование** через `slog` с уровнями и поддержкой debug-режима.
- **IP-контроль доступа** — белый список IP/подсетей через `access.json`.
- **TLS 1.2/1.3** — автоматическое включение при наличии сертификатов.
- **Graceful shutdown** — корректное завершение сессий при перезапуске.
- **Настройки по умолчанию** — host/port из `webssh.conf` подставляются в форму браузера.

## Обход блокировок (РКН/DDoS-Guard)

Встроенные механизмы для работы в условиях сетевых ограничений:

| Механизм | Описание | Флаг/Файл |
|---|---|---|
| **DNS-over-HTTPS (DoH)** | Шифрованные DNS-запросы через Cloudflare, Google и др. | `-doh URL` |
| **SOCKS5-прокси** | Маршрутизация SSH через Tor, Shadowsocks, ProxyChains | `-proxy addr` |
| **Прямые IP-адреса** | Подключение напрямую по IP, минуя DNS-блокировки | `proxy.json` → `direct_ips` |
| **Альтернативные порты** | Подключение по нестандартным портам (2222, 22222 и т.д.) | `proxy.json` → `alt_ports` |
| **Автоматический перебор** | Последовательный перебор всех комбинаций: IP и порты | Встроено по умолчанию |
| **Таймауты** | TCP dial (12с), SSH handshake (20с) | Встроено |
| **TLS SNI (через reverse proxy)** | Обфускация SNI для WSS при использовании nginx/caddy | `proxy.json` → `sni_hostname` |

### Примеры обхода блокировок

```bash
# DoH через Cloudflare
webssh -doh https://dns.cloudflare.com/dns-query

# DoH + Tor (SOCKS5)
webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# Только Tor, без DoH
webssh -proxy 127.0.0.1:9050
```

## Быстрый старт

```bash
# Сборка
go build -o webssh -ldflags "-s -w" .

# Запуск на порту 3400 (по умолчанию)
./webssh

# С портом, debug, DoH и прокси
./webssh -p 8080 -debug -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050

# Режим HTML3 для старых браузеров
./webssh -html3

# С верификацией SSH-ключей хостов
./webssh -key ~/.ssh/known_hosts

# Справка
./webssh -h
```

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

Создать файл `/etc/systemd/system/webssh.service`:

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

### `webssh.conf` — настройки по умолчанию для формы в браузере (опционально)

INI-файл в директории с бинарником. Значения host/port подставляются в форму при загрузке страницы через endpoint `/config`.

```ini
# WebSSH configuration
[main]
host = 127.0.0.1
port = 2222
```

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

### `proxy.json` — настройки обхода блокировок (опционально)

```json
{
  "socks5": "127.0.0.1:9050",
  "doh": "https://dns.cloudflare.com/dns-query",
  "direct_ips": ["198.51.100.1:22"],
  "alt_ports": [2222, 22222],
  "enable_tor": false,
  "sni_hostname": "cloudflare.com"
}
```

CLI-флаги `-doh` и `-proxy` имеют приоритет над `proxy.json`.

### `cert.pem` / `key.pem` — TLS-сертификаты

Если сертификаты найдены — включится HTTPS (WSS).  
Создать самоподписанные:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Без TLS вся трафик (включая пароли) передаётся в открытом виде!**
Рекомендуется использовать nginx/caddy как reverse proxy с Let's Encrypt.

## Использованные технологии Go 1.26

- **`log/slog`** — структурированное логирование с уровнями Info, Warn, Debug.
- **`errors.Is` / `fmt.Errorf(%w)`** — корректная обработка и wrapping ошибок.
- **`map[string]any`** — типизированные слайсы вместо `interface{}`.
- **`net/http.ServeMux`** — роутинг без сторонних библиотек.
- **`golang.org/x/net/proxy`** — SOCKS5-прокси для SSH-соединений.
- **`golang.org/x/crypto/ssh`** — SSH-клиент с терминалом и PTY.

## .gitignore — что попадает в репозиторий

Конфигурационные файлы с IP/логинами/паролями и TLS-сертификаты **не** включаются в git:

| Файл | В git | Причина |
|---|---|---|
| `main.go` | ✅ | Исходный код |
| `go.mod` / `go.sum` | ✅ | Зависимости |
| `static/` | ✅ | Веб-интерфейс |
| `README.md` | ✅ | Документация |
| `webssh.service` | ✅ | Пример systemd unit |
| `.gitignore` | ✅ | Правила игнорирования |
| `access.json` | ❌ | IP-адреса и сети |
| `proxy.json` | ❌ | Адреса прокси и обхода |
| `webssh.conf` | ❌ | Настройки подключения |
| `cert.pem` / `key.pem` | ❌ | TLS-сертификаты |
| `webssh` / `webssh.exe` | ❌ | Бинарник |
| `debug.log` | ❌ | Логи |
| `temp/` | ❌ | Временные файлы |

## Структура проекта

```
web_ssh/
├── main.go            # Основной сервер и SSH-мост (Go 1.26)
├── go.mod             # Модуль и зависимости (в git)
├── go.sum             # Контрольные суммы (в git)
├── .gitignore         # Правила игнорирования (в git)
├── static/
│   ├── index.html     # Веб-интерфейс (xterm.js) (в git)
│   ├── script.js      # WebSocket-клиент (в git)
│   └── style.css      # Стили (в git)
├── webssh.service     # systemd unit (пример) (в git)
├── README.md          # Этот файл (в git)
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
git commit -m "refactor: Go 1.26, HTML3, DoH, SOCKS5, webssh.conf"

# Отправить на GitHub
git push origin main
```

## Лицензия

Проект распространяется под лицензией MIT.
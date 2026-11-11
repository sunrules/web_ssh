# WebSSH — Web-терминал для SSH через браузер

**WebSSH** — веб-приложение на Go, которое предоставляет SSH-терминал в браузере (WebSocket + xterm.js). Поддерживает обфускацию TLS/uTLS, DoH-резолв, SOCKS5/Tor, ChaCha20-Poly1305 обфускацию и ECH.

## Возможности

- Полноценный SSH-терминал в браузере (PTY, vim, nano, цвета).
- uTLS-фingerprint'ы: Chrome 133, Chrome 120/115 с Post-Quantum X25519Kyber768, Firefox, iOS, Edge, Safari, Randomized.
- DoH с пулом из 9 провайдеров + background health-check каждые 30 с.
- DoH-запросы через SOCKS5/Tor.
- Encrypted Client Hello (ECH) — опционально, через `ech_config`.
- ChaCha20-Poly1305 обфускация с KDF через HKDF-SHA256.
- Ротация SNI-доноров (встроенный пул из 21 домена).
- Рандомизированный WebSocket-путь `/<random_hex>` при старте (`/ws` работает как fallback).
- Кэширование последней успешной стратегии подключения.
- Anti-Siberia-flood: лимит TLS-хендшейков + backoff между батчами.
- IPv6-приоритет при DoH-резолве.
- IP-белый список (`access.json`), поддержка X-Forwarded-For через `trusted_proxies`.
- TLS 1.2/1.3 — автоматически включается при наличии `cert.pem`/`key.pem`.
- WebSocket: rate limit (512 KB/s, burst 1 MB), max message size, origin pinning.
- Graceful shutdown, структурированные логи через `slog`, debug-режим с файлом `debug.log`.

## Сборка

Требования: Go 1.27+.

```bash
go build -o webssh -ldflags "-s -w" .
```

Кросскомпиляция для Linux:

```bash
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o webssh .
```

## Запуск

```bash
./webssh                                  # порт 3400, конфиги из каталога бинарника
./webssh -p 8080                          # свой порт
./webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050
./webssh -key /path/to/known_hosts        # проверка SSH host key (рекомендуется)
./webssh -debug                           # debug-лог в stdout + debug.log
./webssh -h                               # справка
```

Флаги: `-p` порт, `-debug`, `-key known_hosts`, `-doh URL`, `-proxy socks5-адрес`, `-h`.

После запуска откройте `http://localhost:<порт>` (или `https://...` при наличии сертификатов). WebSocket-путь выводится в лог.

## Конфигурация

Все конфиги читаются из каталога, где лежит бинарник. Файлы опциональны.

### `webssh.conf` — значения по умолчанию для веб-формы и uTLS fingerprint

```ini
[main]
host = <host>
port = 22

[utls]
client_hello = HelloChrome_133
```

Доступные `client_hello`: `HelloChrome_Auto`, `HelloChrome_133`, `HelloChrome_120`, `HelloChrome_120_PQ`, `HelloChrome_115_PQ`, `HelloFirefox_Auto`, `HelloEdge_Auto`, `HelloSafari_Auto`, `HelloIOS_Auto`, `HelloRandomized`, `HelloGolang`.

### `proxy.json` — обход блокировок

```json
{
  "socks5": "",
  "enable_tor": false,
  "doh": "https://dns.cloudflare.com/dns-query",
  "doh_providers": [],
  "direct_ips": [],
  "alt_ports": [],
  "sni_hostname": "",
  "sni_hostnames": [],
  "obfs_secret": "",
  "ech_config": "",
  "max_tls_attempts": 4,
  "tls_strategy_delay": 25000000000,
  "ws_read_limit": 1048576,
  "ws_origin_pins": [],
  "direct_first": false
}
```

- `socks5` — адрес SOCKS5-прокси (например Tor `127.0.0.1:9050`).
- `enable_tor` — если `socks5` не задан, подставляется `127.0.0.1:9050`.
- `doh` / `doh_providers` — DoH-резолвер(ы); пустой список провайдеров → встроенный пул из 9.
- `direct_ips` — IP для прямого подключения (fallback).
- `alt_ports` — альтернативные порты SSH.
- `sni_hostname` / `sni_hostnames` — SNI-донор(ы); пусто → встроенный пул из 21 домена.
- `obfs_secret` — секрет для ChaCha20-Poly1305 (`openssl rand -base64 32`). Пусто → обфускация выключена.
- `ech_config` — ECH-конфиг (raw base64). Пусто → ECH выключен.
- `max_tls_attempts` / `tls_strategy_delay` — лимит TLS-хендшейков и пауза между батчами (наносекунды).
- `ws_read_limit` — макс. размер WS-сообщения, байты.
- `ws_origin_pins` — разрешённые Origin для CSRF-защиты; пусто → любой Origin.
- `direct_first` — для DoH-IP пробовать прямое соединение раньше SOCKS5 (полезно, когда Tor-exit режет порт 22).

### `access.json` — контроль доступа по IP

```json
{
  "allowed_ips": ["127.0.0.1", "::1", "10.0.0.0/8"],
  "trusted_proxies": []
}
```

- `"*"` — разрешить все IP (дефолт, если файла нет).
- `trusted_proxies` — CIDR reverse-proxy, которым можно верить заголовкам `X-Forwarded-For`/`X-Real-IP`. Пусто → заголовки игнорируются.

### `cert.pem` / `key.pem` — TLS-сертификаты

При наличии пары файлов сервер стартует с HTTPS/WSS. Самоподписанные:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Без TLS весь трафик (включая пароли) передаётся в открытом виде — для прода используйте reverse proxy (nginx/Caddy) с Let's Encrypt.

## Стратегии подключения

Стратегии применяются последовательно, пока одна не сработает:

1. Последняя успешная стратегия (кэш).
2. DoH-резолв (IPv6 приоритет, до 2 IPv6 + 2 IPv4): uTLS+SNI, ChaCha20, plain.
3. Original host: uTLS+SNI, ChaCha20, plain.
4. Direct IPs из `direct_ips` (plain).
5. Альтернативные порты: ChaCha20 / plain.

Для IP-литерала порядок другой: сначала plain direct (голый sshd обычно без TLS-терминатора), затем обфускация, затем SOCKS5.

## systemd

Пример `webssh.service` приложен в репозитории (`webssh.service`). Минимальный вариант:

```ini
[Unit]
Description=WebSSH
After=network.target

[Service]
Type=simple
User=<user>
WorkingDirectory=/path/to/web_ssh
ExecStart=/path/to/web_ssh/webssh -p 3400 -key /path/to/known_hosts
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Замечания по безопасности

1. Пароль передаётся в JSON WebSocket — без TLS это открытый текст. Рекомендуется SSH-ключ и TLS.
2. `-key known_hosts` обязателен для прода; без него включается `InsecureIgnoreHostKey`.
3. Для прода настройте `ws_origin_pins` и `trusted_proxies` (если за reverse proxy).
4. Не коммитьте реальные `obfs_secret`, сертификаты, IP-адреса и `access.json` с личными подсетями.

## Отладка

```bash
./webssh -debug
tail -f debug.log
```

## Лицензия

MIT.

# WebSSH — Web-based SSH client with WebSocket terminal

Веб-терминал для SSH через браузер.  
Поддерживает TLS, HTTP/3 (экспериментально), IP-фильтрацию и "секретный" заголовок (knock).

## Быстрый старт

```bash
# Сборка под Linux
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o webssh

# Запуск (HTTP, без сертификатов)
./webssh -p 3400

# Запуск с HTTPS (предварительно сгенерировать cert.pem + key.pem)
./webssh -p 443
```

Откройте браузер: `http://localhost:3400`

## Параметры

| Флаг | Описание | По умолчанию |
|------|----------|-------------|
| `-p` | Порт | `3400` |
| `-debug` | Режим отладки (лог в debug.log) | — |
| `-key <path>` | Путь к known_hosts | отключено |
| `-knock <value>` | Значение заголовка X-Knock для /ws | отключено |
| `-http3` | Включить HTTP/3 (экспериментально) | отключено |

## Генерация TLS-сертификатов

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Конфигурация доступа

`access.json` — список разрешённых IP или CIDR:

```json
{
  "allowed_ips": ["127.0.0.1", "::1", "192.168.1.0/24"]
}
```

Для разрешения всех адресов: `"*"`

## Требования

- Go 1.26.3+

## Зависимости

- `github.com/gorilla/websocket` — WebSocket
- `github.com/quic-go/quic-go` — HTTP/3
- `golang.org/x/crypto` — SSH-клиент
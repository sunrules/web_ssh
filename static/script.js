let term = null;
let ws = null;
let fitAddon = null;
let resizeSent = false;
let wsPath = '/ws'; // default, will be overridden by /config
let reconnectAttempt = 0;
let maxReconnectAttempts = 5;
let lastHost = '', lastPort = 0, lastUsername = '', lastPassword = '';
let connectionStatus = 'disconnected'; // 'connecting', 'connected', 'disconnected'
let selectionModeActive = false;

// Load default connection settings and WebSocket path from server
fetch('/config')
    .then(r => r.json())
    .then(cfg => {
        if (cfg.host) document.getElementById('host').value = cfg.host;
        if (cfg.port) document.getElementById('port').value = cfg.port;
        if (cfg.ws_path) wsPath = cfg.ws_path;
    })
    .catch(() => {
        // keep defaults if config endpoint unavailable
    });

document.getElementById('ssh-form').addEventListener('submit', (e) => {
    e.preventDefault();

    const host = document.getElementById('host').value;
    const port = parseInt(document.getElementById('port').value);
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    lastHost = host;
    lastPort = port;
    lastUsername = username;
    lastPassword = password;
    reconnectAttempt = 0;
    connectionStatus = 'connecting';

    connectSSH(host, port, username, password);
});

function sendResize() {
    if (!fitAddon || !term) return;
    try {
        fitAddon.fit();
    } catch (e) {
        return;
    }
    if (ws && ws.readyState === WebSocket.OPEN && term.rows && term.cols) {
        const msg = JSON.stringify({
            resize: {
                rows: term.rows,
                cols: term.cols
            }
        });
        ws.send(msg);
        resizeSent = true;
    }
}

function connectSSH(host, port, username, password) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}${wsPath}`;

    ws = new WebSocket(wsUrl);
    resizeSent = false;

    ws.onopen = () => {
        ws.send(JSON.stringify({
            host: host,
            port: port,
            username: username,
            password: password
        }));

        document.getElementById('login-form').style.display = 'none';
        const container = document.getElementById('terminal-container');
        container.style.display = 'flex';

        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                initTerminal();
                sendResize();
                setTimeout(() => {
                    sendResize();
                }, 300);
            });
        });
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'output') {
            if (term) {
                term.write(data.data);
            }
        } else if (data.type === 'error') {
            alert('SSH Error: ' + data.error);
            disconnect();
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        if (reconnectAttempt === 0) {
            alert('Connection error');
        }
    };

    ws.onclose = () => {
        if (term) {
            term.write('\r\n\x1b[31mConnection closed\x1b[0m\r\n');
        }

        // Auto-reconnect with exponential backoff
        if (reconnectAttempt < maxReconnectAttempts && lastHost) {
            reconnectAttempt++;
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempt), 30000);
            console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttempt}/${maxReconnectAttempts})`);
            if (term) {
                term.write(`\r\n\x1b[33mReconnecting in ${delay/1000}s (attempt ${reconnectAttempt}/${maxReconnectAttempts})...\x1b[0m\r\n`);
            }
            setTimeout(() => {
                connectSSH(lastHost, lastPort, lastUsername, lastPassword);
            }, delay);
        } else if (reconnectAttempt >= maxReconnectAttempts && lastHost) {
            if (term) {
                term.write('\r\n\x1b[31mMax reconnection attempts reached. Please reconnect manually.\x1b[0m\r\n');
            }
        }
    };
}

/**
 * Копирует всё видимое содержимое терминала (текущий экран) в буфер обмена.
 * Использует buffer API xterm.js для чтения строк.
 */
function copyVisibleTerminalContent() {
    if (!term) return;

    const buffer = term.buffer.active;
    const rows = buffer.baseY + buffer.cursorY;
    const startRow = Math.max(0, rows - term.rows);
    const lines = [];

    for (let y = startRow; y <= rows; y++) {
        const line = buffer.getLine(y);
        if (line) {
            const text = line.translateToString(true);
            lines.push(text);
        }
    }

    const content = lines.join('\n');
    if (!content.trim()) {
        showClipboardNotification('Nothing to copy');
        return;
    }

    navigator.clipboard.writeText(content).then(() => {
        showClipboardNotification('Screen content copied!');
    }).catch(() => {
        showClipboardNotification('Screen content copied!');
    });
}

function initTerminal() {
    term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: '"Consolas", "Monaco", "Courier New", monospace',
        fontWeight: 'normal',
        letterSpacing: 0,
        lineHeight: 1.2,
        cursorStyle: 'bar',
        theme: {
            background: '#1e1e1e',
            foreground: '#f0f0f0',
            cursor: '#f0f0f0',
            selectionBackground: '#264f78',
            selectionInactiveBackground: '#3a3a3a',
            black: '#000000',
            red: '#e06c75',
            green: '#98c379',
            yellow: '#d19a66',
            blue: '#61afef',
            magenta: '#c678dd',
            cyan: '#56b6c2',
            white: '#abb2bf',
            brightBlack: '#5c6370',
            brightRed: '#e06c75',
            brightGreen: '#98c379',
            brightYellow: '#d19a66',
            brightBlue: '#61afef',
            brightMagenta: '#c678dd',
            brightCyan: '#56b6c2',
            brightWhite: '#ffffff'
        },
        convertEol: true,
        disableStdin: false
    });

    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    term.open(document.getElementById('terminal'));

    // Input handling
    term.onData((data) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ command: data }));
        }
    });

    // Copy on Ctrl+Shift+C or browser native Ctrl+C
    document.addEventListener('copy', (e) => {
        if (!term) return;
        const selection = term.getSelection();
        if (selection) {
            e.clipboardData.setData('text/plain', selection);
            e.preventDefault();
            showClipboardNotification('Copied to clipboard!');
        }
    });

    // Paste on Ctrl+Shift+V or browser native Ctrl+V
    document.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = e.clipboardData.getData('text/plain');
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ command: text }));
        }
        showClipboardNotification('Pasted from clipboard!');
    });

    // Right-click to copy selection
    const terminalElement = document.getElementById('terminal');

    terminalElement.addEventListener('contextmenu', (e) => {
        if (selectionModeActive) {
            e.preventDefault();
            copyVisibleTerminalContent();
            return;
        }

        e.preventDefault();
        const selection = term.getSelection();
        if (selection) {
            navigator.clipboard.writeText(selection).then(() => {
                showClipboardNotification('Copied to clipboard!');
            }).catch(() => {
                showClipboardNotification('Copied to clipboard!');
            });
            term.clearSelection();
        } else {
            navigator.clipboard.readText().then(text => {
                if (text && ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ command: text }));
                    showClipboardNotification('Pasted from clipboard!');
                }
            }).catch(() => {});
        }
    });

    // --- Selection mode: Shift+мышь для копирования текста из mcedit/mc/tmux ---
    // Когда зажат Shift:
    // 1. CSS-класс "selection-mode" отключает pointer-events на canvas xterm.js,
    //    не давая mouse tracking последовательностям (mcedit) дойти до терминала.
    // 2. Клик левой кнопкой мыши копирует весь видимый экран через buffer API.
    // 3. Клик правой кнопкой мыши (контекстное меню) тоже копирует экран.
    //
    // Когда Shift отпущен — всё работает как обычно, mouse tracking активен.

    const terminalContainer = document.getElementById('terminal-container');

    // При клике с Shift копируем весь экран
    terminalElement.addEventListener('click', (e) => {
        if (selectionModeActive) {
            e.preventDefault();
            e.stopPropagation();
            copyVisibleTerminalContent();
        }
    });

    // Отслеживаем нажатие/отпускание Shift: добавляем/убираем CSS-класс,
    // который отключает pointer-events на canvas xterm
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Shift' && !selectionModeActive) {
            selectionModeActive = true;
            terminalContainer.classList.add('selection-mode');
        }
    });

    document.addEventListener('keyup', (e) => {
        if (e.key === 'Shift') {
            selectionModeActive = false;
            terminalContainer.classList.remove('selection-mode');
        }
    });
    // --- End selection mode ---

    // Resize handling — debounced
    let resizeTimer = null;
    window.addEventListener('resize', () => {
        if (resizeTimer) clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            sendResize();
        }, 150);
    });

    if (window.ResizeObserver) {
        const terminalEl = document.getElementById('terminal');
        const observer = new ResizeObserver(() => {
            if (resizeTimer) clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                sendResize();
            }, 150);
        });
        observer.observe(terminalEl);
    }
}

function disconnect() {
    reconnectAttempt = maxReconnectAttempts; // prevent auto-reconnect
    if (term) {
        term.dispose();
        term = null;
        fitAddon = null;
    }
    if (ws) {
        ws.close();
    }
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('terminal-container').style.display = 'none';
    document.getElementById('ssh-form').reset();
}

function showClipboardNotification(message) {
    const notification = document.getElementById('clipboard-notification');
    notification.textContent = message;
    notification.classList.add('show');
    setTimeout(() => {
        notification.classList.remove('show');
    }, 2000);
}

document.getElementById('disconnect-btn').addEventListener('click', disconnect);
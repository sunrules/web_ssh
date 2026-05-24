let term = null;
let ws = null;
let fitAddon = null;
let resizeSent = false;

// Load default connection settings from server webssh.conf
fetch('/config')
    .then(r => r.json())
    .then(cfg => {
        if (cfg.host) document.getElementById('host').value = cfg.host;
        if (cfg.port) document.getElementById('port').value = cfg.port;
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
    const wsUrl = `${protocol}//${window.location.host}/ws`;

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

        document.getElementById('connection-info').textContent = `${username}@${host}:${port}`;

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
        alert('Connection error');
    };

    ws.onclose = () => {
        if (term) {
            term.write('\r\n\x1b[31mConnection closed\x1b[0m\r\n');
        }
    };
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
        disableStdin: false,
        allowProposedApi: true
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
            // No selection — try to paste from clipboard
            navigator.clipboard.readText().then(text => {
                if (text && ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ command: text }));
                    showClipboardNotification('Pasted from clipboard!');
                }
            }).catch(() => {});
        }
    });

    // Double-click to select word
    terminalElement.addEventListener('dblclick', () => {
        // xterm handles word selection natively
    });

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
    if (ws) {
        ws.close();
    }
    if (term) {
        term.dispose();
        term = null;
        fitAddon = null;
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
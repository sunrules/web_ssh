let term = null;
let ws = null;
let fitAddon = null;

document.getElementById('ssh-form').addEventListener('submit', (e) => {
    e.preventDefault();
    
    const host = document.getElementById('host').value;
    const port = parseInt(document.getElementById('port').value);
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    connectSSH(host, port, username, password);
});

function connectSSH(host, port, username, password) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        ws.send(JSON.stringify({
            host: host,
            port: port,
            username: username,
            password: password
        }));
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
    
    // Инициализируем терминал после подключения
    setTimeout(() => {
        initTerminal();
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('terminal-container').style.display = 'block';
        document.getElementById('connection-info').textContent = `${username}@${host}:${port}`;
    }, 100);
}

function initTerminal() {
    term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'monospace',
        theme: {
            background: '#1e1e1e',
            foreground: '#ffffff',
            cursor: '#ffffff'
        }
    });
    
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    
    term.open(document.getElementById('terminal'));
    fitAddon.fit();
    
    // Обработка ввода с клавиатуры
    term.onData((data) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ command: data }));
        }
    });
    
    // Поддержка буфера обмена
    document.addEventListener('copy', (e) => {
        const selection = term.getSelection();
        if (selection) {
            e.clipboardData.setData('text/plain', selection);
            e.preventDefault();
            showClipboardNotification('Copied to clipboard!');
        }
    });
    
    document.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = e.clipboardData.getData('text/plain');
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ command: text }));
        }
        showClipboardNotification('Pasted from clipboard!');
    });
    
    // Обработка изменения размера окна
    window.addEventListener('resize', () => {
        if (fitAddon && term) {
            fitAddon.fit();
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    resize: {
                        rows: term.rows,
                        cols: term.cols
                    }
                }));
            }
        }
    });
    
    // Отправляем начальный размер
    setTimeout(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                resize: {
                    rows: term.rows,
                    cols: term.cols
                }
            }));
        }
    }, 100);
}

function disconnect() {
    if (ws) {
        ws.close();
    }
    if (term) {
        term.dispose();
        term = null;
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
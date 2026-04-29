// go build -o webssh -ldflags "-s -w " 2>&1

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

type WebSocketClient struct {
	conn     *websocket.Conn
	sshConn  *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	stdout   io.Reader
	stderr   io.Reader
	mu       sync.Mutex
	writeMu  sync.Mutex
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	accessConfig AccessConfig
)

func loadAccessConfig() error {
	file, err := os.ReadFile("access.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(file, &accessConfig)
}

func isIPAllowed(ip string) bool {
	// Удаляем порт если есть
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	
	for _, allowed := range accessConfig.AllowedIPs {
		if allowed == ip || allowed == "*" {
			return true
		}
		// Проверка CIDR
		_, ipnet, err := net.ParseCIDR(allowed)
		if err == nil {
			if ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func ipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Получаем реальный IP при использовании прокси
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			ip = strings.TrimSpace(ips[0])
		}
		if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
			ip = xRealIP
		}
		
		if !isIPAllowed(ip) {
			log.Printf("Access denied for IP: %s", ip)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		log.Printf("Access granted for IP: %s", ip)
		next(w, r)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	client := &WebSocketClient{
		conn: conn,
	}

	// Ждем данные для подключения к SSH
	var authData struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Error reading auth data: %v", err)
		return
	}

	if err := json.Unmarshal(msg, &authData); err != nil {
		log.Printf("Error parsing auth data: %v", err)
		client.sendError("Invalid authentication data")
		return
	}

	// Подключаемся к SSH
	if err := client.connectSSH(authData.Host, authData.Port, authData.Username, authData.Password); err != nil {
		log.Printf("SSH connection error: %v", err)
		client.sendError(fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.close()

	// Запускаем обмен данными
	client.handleMessages()
}

func (c *WebSocketClient) connectSSH(host string, port int, username, password string) error {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	sshConn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	c.sshConn = sshConn

	session, err := sshConn.NewSession()
	if err != nil {
		return err
	}
	c.session = session

	// Настройка PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm", 80, 24, modes); err != nil {
		return err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	c.stdin = stdin

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	c.stdout = stdout

	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	c.stderr = stderr

	if err := session.Shell(); err != nil {
		return err
	}

	// Запускаем чтение вывода
	go c.readOutput()
	go c.readError()

	return nil
}

func (c *WebSocketClient) readOutput() {
	buf := make([]byte, 4096)
	for {
		n, err := c.stdout.Read(buf)
		if err != nil {
			return
		}
		c.sendOutput(string(buf[:n]))
	}
}

func (c *WebSocketClient) readError() {
	buf := make([]byte, 4096)
	for {
		n, err := c.stderr.Read(buf)
		if err != nil {
			return
		}
		c.sendOutput(string(buf[:n]))
	}
}

func (c *WebSocketClient) handleMessages() {
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}

		var data map[string]interface{}
		if err := json.Unmarshal(msg, &data); err != nil {
			continue
		}

		if cmd, ok := data["command"].(string); ok {
			c.mu.Lock()
			if c.stdin != nil {
				c.writeMu.Lock()
				c.stdin.Write([]byte(cmd))
				c.writeMu.Unlock()
			}
			c.mu.Unlock()
		} else if resize, ok := data["resize"].(map[string]interface{}); ok {
			if rows, ok := resize["rows"].(float64); ok {
				if cols, ok := resize["cols"].(float64); ok {
					c.session.WindowChange(int(rows), int(cols))
				}
			}
		}
	}
}

func (c *WebSocketClient) sendOutput(data string) {
	msg := map[string]interface{}{
		"type": "output",
		"data": data,
	}
	c.sendJSON(msg)
}

func (c *WebSocketClient) sendError(errMsg string) {
	msg := map[string]interface{}{
		"type":  "error",
		"error": errMsg,
	}
	c.sendJSON(msg)
}

func (c *WebSocketClient) sendJSON(msg map[string]interface{}) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.conn.WriteJSON(msg)
}

func (c *WebSocketClient) close() {
	if c.session != nil {
		c.session.Close()
	}
	if c.sshConn != nil {
		c.sshConn.Close()
	}
	if c.stdin != nil {
		c.stdin.Close()
	}
}

func main() {
	if err := loadAccessConfig(); err != nil {
		log.Printf("Warning: Could not load access.json: %v", err)
		accessConfig = AccessConfig{AllowedIPs: []string{"*"}}
	}

	// Статические файлы
	http.HandleFunc("/", ipMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
		http.ServeFile(w, r, "static"+r.URL.Path)
	}))

	http.HandleFunc("/ws", handleWebSocket)

	port := ":3400"
	log.Printf("Web SSH Client starting on http://localhost%s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
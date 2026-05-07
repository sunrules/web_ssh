// go build -o webssh -ldflags "-s -w " 2>&1
//
// WebSSH — Web-based SSH client with WebSocket terminal
// Provides a web interface to connect to SSH servers
// through a browser with full terminal emulation.
//
// Usage:
//   webssh [-p port] [-debug] [-key known_hosts_file]
//
// Flags:
//   -p       Port to listen on (default: 3400)
//   -debug   Enable debug mode, logs written to debug.log
//   -key     Path to known_hosts file for SSH host key verification (optional)
//   -h       Show this help message

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

type WebSocketClient struct {
	conn         *websocket.Conn
	sshConn      *ssh.Client
	session      *ssh.Session
	stdin        io.WriteCloser
	stdout       io.Reader
	stderr       io.Reader
	mu           sync.Mutex
	writeMu      sync.Mutex
	shellStarted sync.Once
	done         chan struct{}
	closed       bool
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
	accessConfig AccessConfig
	debugMode    bool
	debugLog     *log.Logger
	knownHosts   ssh.HostKeyCallback
)

func loadAccessConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(file, &accessConfig)
}

func isIPAllowed(ip string) bool {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}

	for _, allowed := range accessConfig.AllowedIPs {
		if allowed == ip || allowed == "*" {
			return true
		}
		_, ipnet, err := net.ParseCIDR(allowed)
		if err == nil {
			if ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if strings.Contains(r.URL.Path, "/ws") {
			ua := r.Header.Get("User-Agent")
			referer := r.Header.Get("Referer")

			if ua == "" || (!strings.Contains(ua, "Mozilla/") &&
				!strings.Contains(ua, "Chrome/") &&
				!strings.Contains(ua, "Firefox/") &&
				!strings.Contains(ua, "Safari/") &&
				!strings.Contains(ua, "Edge/")) {
				debugPrintf("Suspicious WS User-Agent from %s: '%s'", r.RemoteAddr, ua)
			}
			if referer == "" {
				debugPrintf("WS connection without Referer from %s", r.RemoteAddr)
			}
		}

		next(w, r)
	}
}

func ipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
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
		done: make(chan struct{}),
	}

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

	if err := client.connectSSH(authData.Host, authData.Port, authData.Username, authData.Password); err != nil {
		log.Printf("SSH connection error: %v", err)
		client.sendError(fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.close()

	client.handleMessages()
}

func (c *WebSocketClient) connectSSH(host string, port int, username, password string) error {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: knownHosts,
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

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 160, 48, modes); err != nil {
		if err2 := session.RequestPty("xterm", 160, 48, modes); err2 != nil {
			return fmt.Errorf("request pty: %v (tried xterm: %v)", err, err2)
		}
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

	go c.readOutput()
	go c.readError()

	debugPrintf("Starting shell for %s@%s", username, host)
	go c.shellStarted.Do(func() {
		if err := c.session.Shell(); err != nil {
			log.Printf("Shell start error: %v", err)
			c.sendError("Failed to start shell: " + err.Error())
		}
	})

	return nil
}

func (c *WebSocketClient) readOutput() {
	buf := make([]byte, 8192)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := c.stdout.Read(buf)
		if n > 0 {
			c.sendOutput(string(buf[:n]))
		}
		if err != nil {
			debugPrintf("SSH stdout read finished: %v", err)
			return
		}
	}
}

func (c *WebSocketClient) readError() {
	buf := make([]byte, 8192)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := c.stderr.Read(buf)
		if n > 0 {
			c.sendOutput(string(buf[:n]))
		}
		if err != nil {
			debugPrintf("SSH stderr read finished: %v", err)
			return
		}
	}
}

func (c *WebSocketClient) handleMessages() {
	defer close(c.done)
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
				_, err := c.stdin.Write([]byte(cmd))
				if err != nil {
					log.Printf("stdin write error: %v", err)
				}
				c.writeMu.Unlock()
			}
			c.mu.Unlock()
		} else if resize, ok := data["resize"].(map[string]interface{}); ok {
			if rows, ok := resize["rows"].(float64); ok {
				if cols, ok := resize["cols"].(float64); ok {
					c.mu.Lock()
					if c.session != nil {
						if err := c.session.WindowChange(int(rows), int(cols)); err != nil {
							log.Printf("WindowChange error: %v", err)
						}
					}
					c.mu.Unlock()
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
	if err := c.conn.WriteJSON(msg); err != nil {
		log.Printf("WriteJSON error: %v", err)
	}
}

func (c *WebSocketClient) close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
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

func debugPrintf(format string, v ...interface{}) {
	if debugMode && debugLog != nil {
		debugLog.Printf(format, v...)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `WebSSH — Web-based SSH client with WebSocket terminal

Usage:
  webssh [options]

Options:
  -p <port>           Port to listen on (default: 3400)
  -debug              Enable debug mode; logs written to debug.log
  -key <path>         Path to SSH known_hosts file for host key verification
                      If not specified, host key verification is DISABLED (insecure)
  -h                  Show this help message and exit

Examples:
  webssh                        Start on default port 3400
  webssh -p 8080                Start on port 8080
  webssh -p 443 -debug          Start on port 443 with debug logging
  webssh -key ~/.ssh/known_hosts  Enable SSH host key verification

Note: For production use, always run behind TLS (cert.pem + key.pem).
      Without TLS, all traffic including passwords is sent in plaintext.

`)
	os.Exit(0)
}

func main() {
	flagPort := flag.Int("p", 3400, "Port to listen on")
	flagDebug := flag.Bool("debug", false, "Enable debug mode (logs to debug.log)")
	flagKey := flag.String("key", "", "Path to SSH known_hosts file for host key verification")
	flagHelp := flag.Bool("h", false, "Show help message")

	flag.Usage = printUsage
	flag.Parse()

	if *flagHelp {
		printUsage()
	}

	debugMode = *flagDebug

	// Определяем директорию, в которой находится исполняемый файл
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Cannot get executable path: %v", err)
	}
	baseDir := filepath.Dir(exePath)
	log.Printf("Base directory: %s", baseDir)

	if *flagKey != "" {
		hostKeyCallback, err := knownhosts.New(*flagKey)
		if err != nil {
			log.Printf("Warning: Could not load known_hosts file '%s': %v", *flagKey, err)
			log.Printf("Falling back to insecure host key verification")
			knownHosts = ssh.InsecureIgnoreHostKey()
		} else {
			knownHosts = hostKeyCallback
			log.Printf("SSH host key verification enabled using %s", *flagKey)
			debugPrintf("Known hosts file loaded: %s", *flagKey)
		}
	} else {
		log.Printf("Warning: SSH host key verification disabled (use -key to enable)")
		knownHosts = ssh.InsecureIgnoreHostKey()
	}

	if debugMode {
		logFilePath := filepath.Join(baseDir, "debug.log")
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Warning: Could not create debug.log: %v", err)
		} else {
			debugLog = log.New(logFile, "[DEBUG] ", log.Ldate|log.Ltime)
			debugLog.Println("Debug mode enabled")
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
			log.Printf("Debug logging to %s enabled", logFilePath)
		}
	}

	accessPath := filepath.Join(baseDir, "access.json")
	if err := loadAccessConfig(accessPath); err != nil {
		log.Printf("Warning: Could not load access.json: %v", err)
		accessConfig = AccessConfig{AllowedIPs: []string{"*"}}
	} else {
		debugPrintf("Loaded access.json with %d allowed IPs", len(accessConfig.AllowedIPs))
	}

	http.HandleFunc("/", securityMiddleware(ipMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(baseDir, "static", "index.html"))
			return
		}
		// Защита от path traversal
		if strings.Contains(r.URL.Path, "..") || !strings.HasPrefix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, "/")
		fullPath := filepath.Join(baseDir, "static", rel)
		// Дополнительная проверка, чтобы не выйти за пределы static/
		staticDir := filepath.Join(baseDir, "static")
		if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(staticDir)) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, fullPath)
	})))

	http.HandleFunc("/ws", securityMiddleware(ipMiddleware(handleWebSocket)))

	port := fmt.Sprintf(":%d", *flagPort)

	certFile := filepath.Join(baseDir, "cert.pem")
	keyFile := filepath.Join(baseDir, "key.pem")

	certExists := false
	if _, err := os.Stat(certFile); err == nil {
		certExists = true
	}

	keyExists := false
	if _, err := os.Stat(keyFile); err == nil {
		keyExists = true
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		SessionTicketsDisabled:   true,
		PreferServerCipherSuites: true,
	}

	server := &http.Server{
		Addr:           port,
		Handler:        nil,
		TLSConfig:      tlsConfig,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if certExists && keyExists {
		log.Printf("Web SSH Client starting on https://localhost%s", port)
		log.Printf("TLS 1.3 enabled, modern ciphers only")
		debugPrintf("TLS enabled with cert=%s key=%s", certFile, keyFile)

		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}()
	} else {
		log.Printf("CRITICAL: TLS certificates not found (%s, %s)", certFile, keyFile)
		log.Printf("Starting on http://localhost%s without encryption!", port)
		log.Printf("Generate with: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}()
	}

	<-stop
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped")
}

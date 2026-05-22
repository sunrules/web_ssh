// $env:GOOS = "linux"; $env:GOARCH = "amd64"; go build -o webssh
// go build -o webssh -ldflags "-s -w"
//
// WebSSH — Web-based SSH client with WebSocket terminal
// Enhanced with anti-scanning "knock", TLS hardening, and HTTP/3 readiness
//
// Usage:
//   webssh [-p port] [-debug] [-key known_hosts_file] [-knock KNOCK_VALUE] [-http3]

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
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Global package-level variables used across modules.
var (
	upgrader = websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
<<<<<<< HEAD
	debugMode  bool
	debugLog   *log.Logger
	knownHosts ssh.HostKeyCallback
	knockHeader string
)

// Wrapper functions to avoid import cycles between packages.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func netSplitHostPort(hostport string) (string, string, error) {
	return net.SplitHostPort(hostport)
}

func netParseCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(s)
	return ipnet, err
}

func netParseIP(s string) net.IP {
	return net.ParseIP(s)
=======
	accessConfig AccessConfig
	debugMode    bool
	debugLog     *log.Logger
	knownHosts   ssh.HostKeyCallback
	knockHeader  string
)

// knockMiddleware — проверка "секретного" заголовка перед доступом к /ws
func knockMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ws") && knockHeader != "" {
			if r.Header.Get("X-Knock") != knockHeader {
				debugPrintf("Knock failed from %s", r.RemoteAddr)
				http.NotFound(w, r) // 404 вместо 403 — меньше информации для сканеров
				return
			}
		}
		next(w, r)
	}
}

// masqueradeMiddleware — отдаёт "безобидный" контент не-браузерам на чувствительных путях
func masqueradeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		isBrowser := strings.Contains(ua, "Mozilla/") ||
			strings.Contains(ua, "Chrome/") ||
			strings.Contains(ua, "Firefox/") ||
			strings.Contains(ua, "Safari/") ||
			strings.Contains(ua, "Edge/")

		if !isBrowser && (strings.Contains(r.URL.Path, "/ws") || strings.Contains(r.URL.Path, "/api")) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Hello</h1></body></html>`)
			return
		}

		// Security headers для легитимных запросов
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next(w, r)
	}
}

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
		if err == nil && ipnet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ws") {
			ua := r.Header.Get("User-Agent")
			if ua == "" || (!strings.Contains(ua, "Mozilla/") && !strings.Contains(ua, "Chrome/") &&
				!strings.Contains(ua, "Firefox/") && !strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Edge/")) {
				debugPrintf("Suspicious WS User-Agent from %s: '%s'", r.RemoteAddr, ua)
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
			http.Error(w, "Not Found", http.StatusNotFound)
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

	client := &WebSocketClient{conn: conn, done: make(chan struct{})}

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
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
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

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	c.stdin, c.stdout, c.stderr = stdin, stdout, stderr

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
				_, _ = c.stdin.Write([]byte(cmd))
				c.writeMu.Unlock()
			}
			c.mu.Unlock()
		} else if resize, ok := data["resize"].(map[string]interface{}); ok {
			if rows, ok := resize["rows"].(float64); ok {
				if cols, ok := resize["cols"].(float64); ok {
					c.mu.Lock()
					if c.session != nil {
						_ = c.session.WindowChange(int(rows), int(cols))
					}
					c.mu.Unlock()
				}
			}
		}
	}
}

func (c *WebSocketClient) sendOutput(data string) {
	c.sendJSON(map[string]interface{}{"type": "output", "data": data})
}

func (c *WebSocketClient) sendError(errMsg string) {
	c.sendJSON(map[string]interface{}{"type": "error", "error": errMsg})
}

func (c *WebSocketClient) sendJSON(msg map[string]interface{}) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.WriteJSON(msg)
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
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
}

// debugPrintf logs debug messages when debug mode is enabled.
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
  -key <path>         Path to SSH known_hosts file
  -knock <value>      Required X-Knock header for WebSocket access
  -http3              Enable experimental HTTP/3 support
  -h                  Show this help

Example:
  webssh -p 443 -knock "secret123" -key ~/.ssh/known_hosts -http3
`)
	os.Exit(0)
}

<<<<<<< HEAD
// createHardenedTLSConfig creates a TLS config with modern ciphers.
=======
// createHardenedTLSConfig — TLS с современными шифрами для "естественного" fingerprint
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
func createHardenedTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
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
<<<<<<< HEAD
		NextProtos:               []string{"h2", "http/1.1"}, // ALPN for HTTP/2
	}, nil
}

// serveHTTP3 starts the HTTP/3 server (experimental).
=======
		NextProtos:               []string{"h2", "http/1.1"}, // ALPN для HTTP/2
	}, nil
}

// serveHTTP3 — запуск HTTP/3 сервера (экспериментально)
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
func serveHTTP3(addr string, handler http.Handler, certFile, keyFile string) error {
	tlsCfg, err := createHardenedTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
<<<<<<< HEAD
	tlsCfg.NextProtos = []string{"h3"} // ALPN for HTTP/3
=======
	tlsCfg.NextProtos = []string{"h3"} // ALPN для HTTP/3
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e

	h3Server := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	log.Printf("HTTP/3 listener on %s", addr)
	return h3Server.ListenAndServeTLS(certFile, keyFile)
}

<<<<<<< HEAD
// handleWebSocket upgrades the HTTP connection to WebSocket and manages the SSH session.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	client := &WebSocketClient{conn: conn, done: make(chan struct{})}

	var auth AuthData
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Error reading auth data: %v", err)
		return
	}
	if err := jsonUnmarshal(msg, &auth); err != nil {
		log.Printf("Error parsing auth data: %v", err)
		client.sendError("Invalid authentication data")
		return
	}

	if err := client.connectSSH(auth); err != nil {
		log.Printf("SSH connection error: %v", err)
		client.sendError(fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.close()

	client.handleMessages()
}

// staticFileHandler serves static files with path traversal protection.
func staticFileHandler(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(baseDir, "static", "index.html"))
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, "/")
		fullPath := filepath.Join(baseDir, "static", rel)
		staticDir := filepath.Join(baseDir, "static")
		if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(staticDir)) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, fullPath)
	}
}

=======
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
func main() {
	flagPort := flag.Int("p", 3400, "Port")
	flagDebug := flag.Bool("debug", false, "Debug mode")
	flagKey := flag.String("key", "", "SSH known_hosts path")
	flagKnock := flag.String("knock", "", "X-Knock header value")
	flagHTTP3 := flag.Bool("http3", false, "Enable HTTP/3")
	flagHelp := flag.Bool("h", false, "Help")

	flag.Usage = printUsage
	flag.Parse()
	if *flagHelp {
		printUsage()
	}

	debugMode = *flagDebug
	knockHeader = *flagKnock

	exePath, _ := os.Executable()
	baseDir := filepath.Dir(exePath)
<<<<<<< HEAD
	EnsureDirs(baseDir)
=======
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e

	// SSH host key verification
	if *flagKey != "" {
		cb, err := knownhosts.New(*flagKey)
		if err != nil {
			log.Printf("Warning: known_hosts load failed: %v", err)
			knownHosts = ssh.InsecureIgnoreHostKey()
		} else {
			knownHosts = cb
			log.Printf("SSH host key verification enabled: %s", *flagKey)
		}
	} else {
		log.Printf("Warning: SSH host key verification DISABLED")
		knownHosts = ssh.InsecureIgnoreHostKey()
	}

<<<<<<< HEAD
	// Debug logging (Go 1.21+ slog is available but we use standard log for simplicity)
=======
	// Debug logging
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
	if debugMode {
		logFile, err := os.OpenFile(filepath.Join(baseDir, "debug.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			debugLog = log.New(logFile, "[DEBUG] ", log.Ldate|log.Ltime)
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
		}
	}

	// Access config
<<<<<<< HEAD
	accessCfg := LoadAccessConfig(baseDir)

	// Handlers with middleware chain
	rootFileHandler := staticFileHandler(baseDir)
	rootHandler := securityMiddleware(ipMiddleware(accessCfg,
		knockMiddleware(masqueradeMiddleware(rootFileHandler)),
	))

	wsHandler := handleWebSocket
	wsHandler = securityMiddleware(ipMiddleware(accessCfg,
		knockMiddleware(masqueradeMiddleware(wsHandler)),
	))

=======
	accessPath := filepath.Join(baseDir, "access.json")
	if err := loadAccessConfig(accessPath); err != nil {
		log.Printf("Warning: access.json not loaded: %v", err)
		accessConfig = AccessConfig{AllowedIPs: []string{"*"}}
	}

	// Handlers with middleware chain
	rootHandler := securityMiddleware(ipMiddleware(knockMiddleware(masqueradeMiddleware(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.ServeFile(w, r, filepath.Join(baseDir, "static", "index.html"))
				return
			}
			if strings.Contains(r.URL.Path, "..") {
				http.NotFound(w, r)
				return
			}
			rel := strings.TrimPrefix(r.URL.Path, "/")
			fullPath := filepath.Join(baseDir, "static", rel)
			staticDir := filepath.Join(baseDir, "static")
			if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(staticDir)) {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, fullPath)
		},
	))))

	wsHandler := securityMiddleware(ipMiddleware(knockMiddleware(masqueradeMiddleware(handleWebSocket))))
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/ws", wsHandler)

	port := fmt.Sprintf(":%d", *flagPort)
	certFile := filepath.Join(baseDir, "cert.pem")
	keyFile := filepath.Join(baseDir, "key.pem")

	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	server := &http.Server{
		Addr:           port,
		Handler:        nil,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if certExists && keyExists {
		log.Printf("Starting HTTPS on https://localhost%s", port)
		tlsCfg, err := createHardenedTLSConfig(certFile, keyFile)
		if err != nil {
			log.Fatalf("TLS config error: %v", err)
		}
		server.TLSConfig = tlsCfg

		// HTTPS server
		go func() {
			ln, err := net.Listen("tcp", port)
			if err != nil {
				log.Fatalf("Listen error: %v", err)
			}
			defer ln.Close()
			tlsLn := tls.NewListener(ln, tlsCfg)
			if err := server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}()

<<<<<<< HEAD
		// HTTP/3 (experimental)
=======
		// HTTP/3 (optional)
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
		if *flagHTTP3 {
			go func() {
				if err := serveHTTP3(port, server.Handler, certFile, keyFile); err != nil {
					log.Printf("HTTP/3 error (optional): %v", err)
				}
			}()
			log.Println("HTTP/3 enabled (experimental)")
		}
<<<<<<< HEAD
=======

>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e
	} else {
		log.Printf("WARNING: No TLS certs found, starting HTTP on http://localhost%s", port)
		log.Printf("Generate certs: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}()
	}

	<-stop
	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	log.Println("Stopped")
<<<<<<< HEAD
}
=======
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
>>>>>>> 9bb450314f58ac9dbdd47e76d8a0087faa53b67e

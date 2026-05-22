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

// createHardenedTLSConfig creates a TLS config with modern ciphers.
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
		NextProtos:               []string{"h2", "http/1.1"}, // ALPN for HTTP/2
	}, nil
}

// serveHTTP3 starts the HTTP/3 server (experimental).
func serveHTTP3(addr string, handler http.Handler, certFile, keyFile string) error {
	tlsCfg, err := createHardenedTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsCfg.NextProtos = []string{"h3"} // ALPN for HTTP/3

	h3Server := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	log.Printf("HTTP/3 listener on %s", addr)
	return h3Server.ListenAndServeTLS(certFile, keyFile)
}

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
	EnsureDirs(baseDir)

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

	// Debug logging (Go 1.21+ slog is available but we use standard log for simplicity)
	if debugMode {
		logFile, err := os.OpenFile(filepath.Join(baseDir, "debug.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			debugLog = log.New(logFile, "[DEBUG] ", log.Ldate|log.Ltime)
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
		}
	}

	// Access config
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

		// HTTP/3 (experimental)
		if *flagHTTP3 {
			go func() {
				if err := serveHTTP3(port, server.Handler, certFile, keyFile); err != nil {
					log.Printf("HTTP/3 error (optional): %v", err)
				}
			}()
			log.Println("HTTP/3 enabled (experimental)")
		}
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
}
// go build -o webssh -ldflags "-s -w" 2>&1
//
// WebSSH — Web-based SSH client with WebSocket terminal
// Provides a web interface to connect to SSH servers
// through a browser with full terminal emulation.
//
// Usage:
//   webssh [-p port] [-debug] [-key known_hosts_file] [-doh URL] [-proxy addr]
//
// Flags:
//   -p         Port to listen on (default: 3400)
//   -debug     Enable debug mode; writes to debug.log
//   -key       Path to known_hosts file for SSH host key verification
//   -doh       DNS-over-HTTPS resolver URL (e.g. https://dns.cloudflare.com/dns-query)
//   -proxy     SOCKS5 proxy address for SSH connections (e.g. 127.0.0.1:9050)
//   -h         Show this help message

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
)

// AccessConfig defines IP-based access control.
type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

// ProxyConfig defines proxy and bypass settings for RKN circumvention.
type ProxyConfig struct {
	SOCKS5      string   `json:"socks5,omitempty"`
	DoH         string   `json:"doh,omitempty"`
	DirectIPs   []string `json:"direct_ips,omitempty"`
	AltPorts    []int    `json:"alt_ports,omitempty"`
	EnableTor   bool     `json:"enable_tor,omitempty"`
	SNIHostname string   `json:"sni_hostname,omitempty"`
	ObfsSecret  string   `json:"obfs_secret,omitempty"`
}

// WebSocketClient manages a WebSocket <-> SSH bridge.
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
}

// WebSSHConfig contains default connection settings from webssh.conf.
type WebSSHConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ConnectionStrategy — одна попытка подключения с определённым методом обфускации.
type ConnectionStrategy struct {
	Address     string
	Obfuscation string // "tls", "xor", "plain"
	Description string // для логов
}

// SSHConnector управляет всеми стратегиями подключения.
type SSHConnector struct {
	Host        string
	Port        int
	SSHConfig   *ssh.ClientConfig
	Ctx         context.Context
	SocksDialer proxy.Dialer
	NetDialer   *net.Dialer
}

// Global state.
var (
	upgrader = websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
	}
	accessConf   AccessConfig
	proxyConf    ProxyConfig
	websshConf   WebSSHConfig
	debugMode    bool
	knownHostsFn ssh.HostKeyCallback

	logger   *slog.Logger
	debugLog *slog.Logger
)

// ---------------------------------------------------------------------------
// Configuration loading
// ---------------------------------------------------------------------------

func loadAccessConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read access config: %w", err)
	}
	return json.Unmarshal(data, &accessConf)
}

func loadProxyConfig(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read proxy config: %w", err)
	}
	return json.Unmarshal(data, &proxyConf)
}

func loadWebSSHConfig(path string) {
	websshConf = WebSSHConfig{Host: "localhost", Port: 22}
	data, err := os.ReadFile(path)
	if err != nil {
		debugLog.Debug("webssh.conf not found, using defaults", "path", path, "error", err)
		return
	}

	// Карта известных ClientHello ID для uTLS
	helloIDs := map[string]utls.ClientHelloID{
		"HelloChrome_Auto":  utls.HelloChrome_Auto,
		"HelloFirefox_Auto": utls.HelloFirefox_Auto,
		"HelloEdge_Auto":    utls.HelloEdge_Auto,
		"HelloSafari_Auto":  utls.HelloSafari_Auto,
		"HelloIOS_Auto":     utls.HelloIOS_Auto,
		"HelloRandomized":   utls.HelloRandomized,
		"HelloGolang":       utls.HelloGolang,
	}

	currentSection := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch currentSection {
		case "main":
			switch key {
			case "host":
				websshConf.Host = val
			case "port":
				if p, e := strconv.Atoi(val); e == nil && p > 0 {
					websshConf.Port = p
				}
			}
		case "utls":
			if key == "client_hello" {
				if id, ok := helloIDs[val]; ok {
					utlsClientHelloID = id
					debugLog.Debug("uTLS client hello ID set", "id", val)
				} else {
					logger.Warn("unknown uTLS client hello ID, using default", "id", val, "default", utlsClientHelloID.Str())
				}
			}
		}
	}
	debugLog.Debug("webssh config loaded", "host", websshConf.Host, "port", websshConf.Port)
}

// ---------------------------------------------------------------------------
// IP access control
// ---------------------------------------------------------------------------

func isIPAllowed(ip string) bool {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	for _, allowed := range accessConf.AllowedIPs {
		if allowed == ip || allowed == "*" {
			return true
		}
		_, ipNet, cidrErr := net.ParseCIDR(allowed)
		if cidrErr == nil && ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS resolver
// ---------------------------------------------------------------------------

type dohResolver struct {
	client  *http.Client
	baseURL string
}

func newDoHResolver(dohURL string) *dohResolver {
	if dohURL == "" {
		return nil
	}
	return &dohResolver{
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: dohURL,
	}
}

func (r *dohResolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	if r == nil {
		return net.DefaultResolver.LookupHost(ctx, host)
	}

	// Сначала пытаемся получить и A (IPv4), и AAAA (IPv6) записи одним запросом типа AAAA,
	// но Cloudflare DNS-over-HTTPS поддерживает одновременно A+AAAA через POST с wire форматом.
	// Используем GET + JSON (RFC 8484) с type=A+AAAA если возможно, иначе раздельные запросы.

	var allIPs []string

	// Пробуем раздельные запросы A и AAAA для максимальной совместимости
	for _, dnsType := range []struct {
		qtype string
		rtype int
	}{
		{"A", 1},     // IPv4
		{"AAAA", 28}, // IPv6
	} {
		u := fmt.Sprintf("%s?name=%s&type=%s", r.baseURL, url.QueryEscape(host), dnsType.qtype)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			debugLog.Debug("DoH request creation failed", "type", dnsType.qtype, "error", err)
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", "Go-http-client/1.1")

		resp, err := r.client.Do(req)
		if err != nil {
			debugLog.Debug("DoH lookup failed", "type", dnsType.qtype, "error", err)
			continue
		}

		var dnsResp struct {
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if decErr := json.NewDecoder(resp.Body).Decode(&dnsResp); decErr != nil {
			resp.Body.Close()
			debugLog.Debug("DoH decode failed", "type", dnsType.qtype, "error", decErr)
			continue
		}
		resp.Body.Close()

		for _, a := range dnsResp.Answer {
			if a.Type == dnsType.rtype {
				allIPs = append(allIPs, a.Data)
			}
		}
	}

	if len(allIPs) > 0 {
		debugLog.Debug("DoH resolved", "host", host, "ips", allIPs)
		return allIPs, nil
	}

	// POST с wire format (application/dns-message) удалён из-за ненадёжности самописного парсера.
	// Используем только GET + JSON (RFC 8484) — он стабильно работает со всеми DoH-провайдерами.

	return nil, fmt.Errorf("DoH: no records for %s", host)
}

// ---------------------------------------------------------------------------
// SOCKS5 dialer
// ---------------------------------------------------------------------------

func socksDialer(addr string) proxy.Dialer {
	if addr == "" {
		return proxy.Direct
	}
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		logger.Warn("invalid SOCKS5 address, using direct connection", "addr", addr, "error", err)
		return proxy.Direct
	}
	return d
}

// (обёртки wrapConnection, wrapWithObfuscation, wrapWithXOROnly удалены — вся логика
//  обфускации теперь в SSHConnector.applyObfuscation)

// ---------------------------------------------------------------------------
// uTLS camouflage — эмуляция браузерного TLS (Chrome 124+) для обхода DPI
// ---------------------------------------------------------------------------

// utlsClientHelloID хранит выбранный fingerprint для uTLS.
// Загружается из webssh.conf (секция [utls] → key "client_hello").
// По умолчанию HelloChrome_133 (актуально на 2026).
var utlsClientHelloID = utls.HelloChrome_133

// uTLSCamouflageConn wraps a uTLS connection over plain TCP.
// To DPI it looks like a real Chrome TLS handshake to the specified SNI host.
type uTLSCamouflageConn struct {
	*utls.UConn
	sniHostname string
}

func newUTLSCamouflageConn(conn net.Conn, sniHostname string) (*uTLSCamouflageConn, error) {
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         sniHostname,
		InsecureSkipVerify: true,
	}, utlsClientHelloID)

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("uTLS camouflage handshake failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	helloIDStr := utlsClientHelloID.Str()

	debugLog.Debug("uTLS camouflage established",
		"sni", sniHostname,
		"client_hello_id", helloIDStr,
		"cipher", state.CipherSuite,
		"version", state.Version,
	)

	return &uTLSCamouflageConn{
		UConn:       tlsConn,
		sniHostname: sniHostname,
	}, nil
}

// Close закрывает uTLS соединение
func (tc *uTLSCamouflageConn) Close() error {
	if err := tc.UConn.CloseWrite(); err != nil {
		// Игнорируем ошибки
	}
	return tc.UConn.Close()
}

// ---------------------------------------------------------------------------
// Legacy XOR obfuscation (fallback)
// ---------------------------------------------------------------------------

type obfuscatedConn struct {
	net.Conn
	writeBuf []byte
	key      []byte
}

func newObfuscatedConn(conn net.Conn, secret string) (*obfuscatedConn, error) {
	key := make([]byte, 32)
	for i := 0; i < len(key); i++ {
		key[i] = secret[i%len(secret)]
	}
	oc := &obfuscatedConn{Conn: conn, writeBuf: make([]byte, 0, 65536), key: key}

	preamble := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
	padding := make([]byte, 64+int(time.Now().UnixNano()%256))
	for i := range padding {
		padding[i] = byte(i * 7)
	}
	preamble = append(preamble, padding...)
	oc.xor(preamble)
	if _, err := conn.Write(preamble); err != nil {
		return nil, fmt.Errorf("obfs preamble: %w", err)
	}
	debugLog.Debug("XOR obfuscation layer enabled", "secret_len", len(secret), "preamble_len", len(preamble))
	return oc, nil
}

func (oc *obfuscatedConn) xor(data []byte) {
	for i := range data {
		data[i] ^= oc.key[i%len(oc.key)]
	}
}

func (oc *obfuscatedConn) Read(b []byte) (int, error) {
	n, err := oc.Conn.Read(b)
	if n > 0 {
		oc.xor(b[:n])
	}
	return n, err
}

func (oc *obfuscatedConn) Write(b []byte) (int, error) {
	oc.writeBuf = append(oc.writeBuf[:0], b...)
	oc.xor(oc.writeBuf)
	return oc.Conn.Write(oc.writeBuf)
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		if strings.Contains(r.URL.Path, "/ws") {
			ua := r.Header.Get("User-Agent")
			ref := r.Header.Get("Referer")
			if ua == "" || (!strings.Contains(ua, "Mozilla/") &&
				!strings.Contains(ua, "Chrome/") &&
				!strings.Contains(ua, "Firefox/") &&
				!strings.Contains(ua, "Safari/") &&
				!strings.Contains(ua, "Edge/")) {
				debugLog.Warn("suspicious WS User-Agent", "remote", r.RemoteAddr, "ua", ua)
			}
			if ref == "" {
				debugLog.Warn("WS connection without Referer", "remote", r.RemoteAddr)
			}
		}
		next(w, r)
	}
}

func ipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ip = strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			ip = xrip
		}
		if !isIPAllowed(ip) {
			logger.Warn("access denied", "ip", ip)
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		logger.Debug("access granted", "ip", ip)
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// WebSocket → SSH bridge
// ---------------------------------------------------------------------------

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("WebSocket upgrade error", "error", err)
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
		logger.Warn("error reading auth data", "error", err)
		return
	}
	if err := json.Unmarshal(msg, &authData); err != nil {
		logger.Warn("error parsing auth data", "error", err)
		client.sendError("Invalid authentication data")
		return
	}
	if err := client.connectSSH(r.Context(), authData.Host, authData.Port, authData.Username, authData.Password); err != nil {
		logger.Warn("SSH connection error", "host", authData.Host, "port", authData.Port,
			"user", authData.Username, "error", err)
		client.sendError(fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer client.close()
	client.handleMessages()
}

func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

func isPrivateHost(host string) bool {
	if host == "localhost" || host == "localhost.localdomain" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}

func (c *WebSocketClient) connectSSH(ctx context.Context, host string, port int, username, password string) error {
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: knownHostsFn,
		Timeout:         15 * time.Second,
	}

	connector := &SSHConnector{
		Host:        host,
		Port:        port,
		SSHConfig:   sshConfig,
		Ctx:         ctx,
		SocksDialer: socksDialer(proxyConf.SOCKS5),
		NetDialer:   &net.Dialer{Timeout: 10 * time.Second},
	}

	strategies := connector.buildStrategies()

	var lastErr error
	for _, strategy := range strategies {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		debugLog.Debug("trying connection strategy",
			"addr", strategy.Address,
			"obfs", strategy.Obfuscation,
			"desc", strategy.Description)

		sshClient, err := connector.tryStrategy(strategy)
		if err != nil {
			lastErr = err
			debugLog.Debug("strategy failed", "addr", strategy.Address, "error", err)
			continue
		}

		c.sshConn = sshClient
		lastErr = nil
		break
	}

	if lastErr != nil {
		return fmt.Errorf("all connection strategies failed for %s: %w", host, lastErr)
	}

	if err := c.setupSession(); err != nil {
		return err
	}

	logger.Info("SSH connected", "user", username, "host", host, "port", port)
	return nil
}

// ---------------------------------------------------------------------------
// SSHConnector — управление стратегиями подключения
// ---------------------------------------------------------------------------

func (sc *SSHConnector) buildStrategies() []ConnectionStrategy {
	var strategies []ConnectionStrategy

	fullAddr := func(ipOrHost string, p int) string {
		return fmt.Sprintf("%s:%d", ipOrHost, p)
	}

	// 1. Direct IPs — самый высокий приоритет
	// Для direct IP всегда добавляем plain в конце, даже если есть TLS/XOR.
	// Это гарантирует, что если сервер не поддерживает обфускацию — будет fallback.
	for _, dip := range proxyConf.DirectIPs {
		addr := fullAddr(dip, sc.Port)
		if proxyConf.SNIHostname != "" {
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "tls",
				Description: "direct IP + TLS",
			})
		}
		if proxyConf.ObfsSecret != "" {
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "xor",
				Description: "direct IP + XOR",
			})
		}
		// Plain добавляем всегда как последний fallback для direct IP
		strategies = append(strategies, ConnectionStrategy{
			Address:     addr,
			Obfuscation: "plain",
			Description: "direct IP",
		})
	}

	// 2. DoH resolved IPs (IPv6 → IPv4)
	var ips []string
	doh := newDoHResolver(proxyConf.DoH)
	if !isIPAddress(sc.Host) && !isPrivateHost(sc.Host) && doh != nil {
		var dohErr error
		ips, dohErr = doh.lookupHost(sc.Ctx, sc.Host)
		if dohErr != nil {
			debugLog.Debug("DoH lookup failed", "host", sc.Host, "error", dohErr)
		}
	}

	// IPv6 first
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			obfs := "plain"
			if proxyConf.SNIHostname != "" {
				obfs = "tls"
			}
			strategies = append(strategies, ConnectionStrategy{
				Address:     fullAddr(ip, sc.Port),
				Obfuscation: obfs,
				Description: "DoH IPv6",
			})
		}
	}
	// IPv4
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			obfs := "plain"
			if proxyConf.SNIHostname != "" {
				obfs = "tls"
			}
			strategies = append(strategies, ConnectionStrategy{
				Address:     fullAddr(ip, sc.Port),
				Obfuscation: obfs,
				Description: "DoH IPv4",
			})
		}
	}

	// 3. Original host
	obfs := "plain"
	if proxyConf.SNIHostname != "" {
		obfs = "tls"
	}
	strategies = append(strategies, ConnectionStrategy{
		Address:     fullAddr(sc.Host, sc.Port),
		Obfuscation: obfs,
		Description: "original host",
	})

	// 4. Alt ports
	for _, altPort := range proxyConf.AltPorts {
		strategies = append(strategies, ConnectionStrategy{
			Address:     fullAddr(sc.Host, altPort),
			Obfuscation: obfs,
			Description: fmt.Sprintf("alt port %d", altPort),
		})
	}

	return strategies
}

func (sc *SSHConnector) tryStrategy(s ConnectionStrategy) (*ssh.Client, error) {
	conn, err := sc.dial(s.Address)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	// applyObfuscation может вернуть ту же conn (plain) или обёрнутую
	wrappedConn, obfsErr := sc.applyObfuscation(conn, s.Obfuscation)
	if obfsErr != nil {
		conn.Close()
		return nil, fmt.Errorf("obfuscation failed: %w", obfsErr)
	}

	// SSH Handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(wrappedConn, s.Address, sc.SSHConfig)
	if err != nil {
		wrappedConn.Close()
		return nil, fmt.Errorf("SSH handshake failed: %w", err)
	}

	debugLog.Debug("strategy succeeded",
		"addr", s.Address,
		"obfs", s.Obfuscation,
		"desc", s.Description)
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (sc *SSHConnector) dial(addr string) (net.Conn, error) {
	if proxyConf.SOCKS5 != "" {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		ch := make(chan dialResult, 1)
		go func() {
			c, e := sc.SocksDialer.Dial("tcp", addr)
			ch <- dialResult{c, e}
		}()
		select {
		case res := <-ch:
			return res.conn, res.err
		case <-time.After(12 * time.Second):
			return nil, fmt.Errorf("SOCKS5 dial timeout after 12s")
		case <-sc.Ctx.Done():
			return nil, sc.Ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(sc.Ctx, 12*time.Second)
	defer cancel()
	return sc.NetDialer.DialContext(ctx, "tcp", addr)
}

func (sc *SSHConnector) applyObfuscation(conn net.Conn, method string) (net.Conn, error) {
	switch method {
	case "tls":
		if proxyConf.SNIHostname != "" {
			tlsConn, err := newUTLSCamouflageConn(conn, proxyConf.SNIHostname)
			if err != nil {
				return conn, fmt.Errorf("uTLS camouflage failed: %w", err)
			}
			return tlsConn, nil
		}
		// Если sni_hostname не задан — возвращаем conn без ошибки (пропускаем TLS стратегию)
		return conn, nil
	case "xor":
		if proxyConf.ObfsSecret != "" {
			xorConn, err := newObfuscatedConn(conn, proxyConf.ObfsSecret)
			if err != nil {
				return conn, fmt.Errorf("XOR obfuscation failed: %w", err)
			}
			return xorConn, nil
		}
		return conn, nil
	default:
		return conn, nil
	}
}

// setupSession создаёт SSH-сессию, PTY, pipes и запускает shell.
func (c *WebSocketClient) setupSession() error {
	session, err := c.sshConn.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	c.session = session

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if e := session.RequestPty("xterm-256color", 160, 48, modes); e != nil {
		if e2 := session.RequestPty("xterm", 160, 48, modes); e2 != nil {
			if e3 := session.RequestPty("vt100", 160, 48, modes); e3 != nil {
				return fmt.Errorf("request pty: xterm-256color: %v, xterm: %v, vt100: %v", e, e2, e3)
			}
		}
	}

	c.stdin, _ = session.StdinPipe()
	c.stdout, _ = session.StdoutPipe()
	c.stderr, _ = session.StderrPipe()

	go c.readOutput(c.stdout)
	go c.readOutput(c.stderr)

	c.shellStarted.Do(func() {
		if e := c.session.Shell(); e != nil {
			logger.Warn("shell start error", "error", e)
			c.sendError("Failed to start shell")
		}
	})

	return nil
}

func (c *WebSocketClient) readOutput(reader io.Reader) {
	buf := make([]byte, 8192)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := reader.Read(buf)
		if n > 0 {
			c.sendOutput(string(buf[:n]))
		}
		if err != nil {
			debugLog.Debug("SSH read finished", "error", err)
			return
		}
	}
}

func (c *WebSocketClient) handleMessages() {
	defer close(c.done)
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			debugLog.Debug("WS read finished", "error", err)
			return
		}
		var data map[string]any
		if err := json.Unmarshal(msg, &data); err != nil {
			continue
		}
		switch {
		case data["command"] != nil:
			cmd, ok := data["command"].(string)
			if !ok {
				continue
			}
			c.writeMu.Lock()
			_, e := c.stdin.Write([]byte(cmd))
			c.writeMu.Unlock()
			if e != nil {
				logger.Warn("stdin write error", "error", e)
			}
		case data["resize"] != nil:
			resize, ok := data["resize"].(map[string]any)
			if !ok {
				continue
			}
			rows, _ := resize["rows"].(float64)
			cols, _ := resize["cols"].(float64)
			c.mu.Lock()
			if c.session != nil {
				if e := c.session.WindowChange(int(rows), int(cols)); e != nil {
					logger.Warn("WindowChange error", "error", e)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *WebSocketClient) sendOutput(data string) {
	c.sendJSON(map[string]any{"type": "output", "data": data})
}

func (c *WebSocketClient) sendError(errMsg string) {
	c.sendJSON(map[string]any{"type": "error", "error": errMsg})
}

func (c *WebSocketClient) sendJSON(msg map[string]any) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.WriteJSON(msg); err != nil {
		logger.Warn("WriteJSON error", "error", err)
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

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

func printUsage() {
	fmt.Fprintf(os.Stderr, `WebSSH — Web-based SSH client with WebSocket terminal

Usage: webssh [options]

Options:
  -p <port>     Port to listen on (default: 3400)
  -debug        Enable debug mode; logs to debug.log
  -key <path>   SSH known_hosts file for host key verification
  -doh <url>    DNS-over-HTTPS resolver (e.g. https://dns.cloudflare.com/dns-query)
  -proxy <addr> SOCKS5 proxy (e.g. 127.0.0.1:9050)
  -h            Show this help message

RKN bypass:
  -doh, -proxy, direct_ips, alt_ports, obfs_secret (in proxy.json)
  Obfuscated SSH hides the SSH protocol from DPI.

Examples:
  webssh
  webssh -p 8080 -debug
  webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050
`)
	os.Exit(0)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	flagPort := flag.Int("p", 3400, "Port to listen on")
	flagDebug := flag.Bool("debug", false, "Enable debug mode")
	flagKey := flag.String("key", "", "Path to known_hosts file")
	flagDoH := flag.String("doh", "", "DNS-over-HTTPS URL")
	flagProxy := flag.String("proxy", "", "SOCKS5 proxy address")
	flagHelp := flag.Bool("h", false, "Show help")
	flag.Usage = printUsage
	flag.Parse()

	if *flagHelp {
		printUsage()
	}

	debugMode = *flagDebug

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot get executable path: %v\n", err)
		os.Exit(1)
	}
	baseDir := filepath.Dir(exePath)

	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	debugLog = logger

	if debugMode {
		logLevel.Set(slog.LevelDebug)
		logFilePath := filepath.Join(baseDir, "debug.log")
		logFile, ferr := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if ferr != nil {
			logger.Warn("could not create debug.log", "error", ferr)
		} else {
			debugLog = slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, logFile),
				&slog.HandlerOptions{Level: slog.LevelDebug}))
			debugLog.Info("debug mode enabled")
		}
	}

	logger.Info("starting WebSSH",
		"go_version", runtime.Version(),
		"port", *flagPort,
		"debug", debugMode,
		"doh", *flagDoH,
		"proxy", *flagProxy,
	)

	loadWebSSHConfig(filepath.Join(baseDir, "webssh.conf"))

	accessPath := filepath.Join(baseDir, "access.json")
	if err := loadAccessConfig(accessPath); err != nil {
		logger.Warn("could not load access.json, allowing all IPs", "error", err)
		accessConf = AccessConfig{AllowedIPs: []string{"*"}}
	} else {
		debugLog.Debug("access config loaded", "allowed_ips", len(accessConf.AllowedIPs))
	}

	proxyPath := filepath.Join(baseDir, "proxy.json")
	if err := loadProxyConfig(proxyPath); err != nil {
		logger.Warn("could not load proxy.json, continuing with defaults", "error", err)
	}
	if *flagDoH != "" {
		proxyConf.DoH = *flagDoH
	}
	if *flagProxy != "" {
		proxyConf.SOCKS5 = *flagProxy
	}
	// Автоматическая настройка Tor: если enable_tor: true и SOCKS5 не задан явно
	if proxyConf.EnableTor && proxyConf.SOCKS5 == "" {
		proxyConf.SOCKS5 = "127.0.0.1:9050"
		logger.Info("Tor mode enabled, SOCKS5 set to 127.0.0.1:9050")
	}
	debugLog.Debug("proxy config", "doh", proxyConf.DoH, "socks5", proxyConf.SOCKS5,
		"direct_ips", proxyConf.DirectIPs, "alt_ports", proxyConf.AltPorts)

	if *flagKey != "" {
		hostKeyCallback, kerr := knownhosts.New(*flagKey)
		if kerr != nil {
			logger.Warn("could not load known_hosts, falling back to insecure", "path", *flagKey, "error", kerr)
			knownHostsFn = ssh.InsecureIgnoreHostKey()
		} else {
			knownHostsFn = hostKeyCallback
			logger.Info("SSH host key verification enabled", "path", *flagKey)
		}
	} else {
		logger.Warn("SSH host key verification disabled (use -key to enable)")
		knownHostsFn = ssh.InsecureIgnoreHostKey()
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", securityMiddleware(ipMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(baseDir, "static", "index.html"))
			return
		}
		if strings.Contains(r.URL.Path, "..") || !strings.HasPrefix(r.URL.Path, "/") {
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
	})))

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(websshConf)
	})

	mux.HandleFunc("/ws", securityMiddleware(ipMiddleware(handleWebSocket)))

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
		Addr:           fmt.Sprintf(":%d", *flagPort),
		Handler:        mux,
		TLSConfig:      tlsConfig,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	certFile := filepath.Join(baseDir, "cert.pem")
	keyFile := filepath.Join(baseDir, "key.pem")

	_, certExists := os.Stat(certFile)
	_, keyExists := os.Stat(keyFile)

	if certExists == nil && keyExists == nil {
		logger.Info("starting with TLS", "addr", server.Addr)
		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		}()
	} else {
		logger.Warn("TLS certificates not found, starting without encryption")
		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("server error", "error", err)
				os.Exit(1)
			}
		}()
	}

	<-stop
	logger.Info("shutting down gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("forced shutdown", "error", err)
	}
	logger.Info("server stopped")
}

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
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "host":
			websshConf.Host = val
		case "port":
			if p, e := strconv.Atoi(val); e == nil && p > 0 {
				websshConf.Port = p
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
	u := fmt.Sprintf("%s?name=%s&type=A", r.baseURL, url.QueryEscape(host))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH lookup failed: %w", err)
	}
	defer resp.Body.Close()

	var dnsResp struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, fmt.Errorf("DoH decode failed: %w", err)
	}
	var ips []string
	for _, a := range dnsResp.Answer {
		if a.Type == 1 {
			ips = append(ips, a.Data)
		}
	}
	if len(ips) > 0 {
		return ips, nil
	}
	return nil, fmt.Errorf("DoH: no A records for %s", host)
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

// ---------------------------------------------------------------------------
// Obfuscated SSH
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
	debugLog.Debug("obfuscation layer enabled", "secret_len", len(secret), "preamble_len", len(preamble))
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

func wrapWithObfuscation(conn net.Conn) net.Conn {
	if proxyConf.ObfsSecret == "" {
		return conn
	}
	oc, err := newObfuscatedConn(conn, proxyConf.ObfsSecret)
	if err != nil {
		logger.Warn("obfuscation setup failed, using plain connection", "error", err)
		return conn
	}
	return oc
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

	var ips []string
	doh := newDoHResolver(proxyConf.DoH)
	if isIPAddress(host) {
		debugLog.Debug("bare IP address detected, skipping DoH", "host", host)
	} else if isPrivateHost(host) {
		debugLog.Debug("private host detected, skipping DoH", "host", host)
	} else if doh != nil {
		var dohErr error
		ips, dohErr = doh.lookupHost(ctx, host)
		if dohErr != nil {
			debugLog.Debug("DoH lookup failed, falling back to OS resolver", "host", host, "error", dohErr)
		}
	}

	tryAddrs := make([]string, 0, 6)

	for _, dip := range proxyConf.DirectIPs {
		if !strings.Contains(dip, ":") {
			dip = fmt.Sprintf("%s:%d", dip, port)
		}
		tryAddrs = append(tryAddrs, dip)
	}
	if len(ips) > 0 {
		for _, ip := range ips {
			tryAddrs = append(tryAddrs, fmt.Sprintf("%s:%d", ip, port))
		}
	}
	origAddr := fmt.Sprintf("%s:%d", host, port)
	tryAddrs = append(tryAddrs, origAddr)
	for _, aPort := range proxyConf.AltPorts {
		altAddr := fmt.Sprintf("%s:%d", host, aPort)
		tryAddrs = append(tryAddrs, altAddr)
		for _, ip := range ips {
			tryAddrs = append(tryAddrs, fmt.Sprintf("%s:%d", ip, aPort))
		}
	}

	socksDialer := socksDialer(proxyConf.SOCKS5)
	netDialer := &net.Dialer{Timeout: 10 * time.Second}

	seen := make(map[string]bool, len(tryAddrs))
	uniqueAddrs := make([]string, 0, len(tryAddrs))
	for _, a := range tryAddrs {
		if !seen[a] {
			seen[a] = true
			uniqueAddrs = append(uniqueAddrs, a)
		}
	}

	var lastErr error
dials:
	for _, addr := range uniqueAddrs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		debugLog.Debug("attempting SSH connection", "addr", addr, "via_socks5", proxyConf.SOCKS5 != "")
		var nconn net.Conn
		var dialErr error

		if proxyConf.SOCKS5 != "" {
			type result struct {
				conn net.Conn
				err  error
			}
			ch := make(chan result, 1)
			go func() {
				c, e := socksDialer.Dial("tcp", addr)
				ch <- result{c, e}
			}()
			select {
			case res := <-ch:
				nconn, dialErr = res.conn, res.err
			case <-time.After(12 * time.Second):
				dialErr = fmt.Errorf("SOCKS5 dial timed out after 12s")
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			nconn, dialErr = netDialer.DialContext(dialCtx, "tcp", addr)
			cancel()
		}

		if dialErr != nil {
			debugLog.Debug("dial failed", "addr", addr, "error", dialErr)
			lastErr = dialErr
			continue
		}
		debugLog.Debug("dial succeeded, starting SSH handshake", "addr", addr)

		// Wrap with obfuscation if configured.
		hsConn := wrapWithObfuscation(nconn)
		isWrapped := hsConn != nconn

		type hsResult struct {
			sconn ssh.Conn
			chans <-chan ssh.NewChannel
			reqs  <-chan *ssh.Request
			err   error
		}

		hsCh := make(chan hsResult, 1)
		go func() {
			sconn, chans, reqs, e := ssh.NewClientConn(hsConn, addr, sshConfig)
			hsCh <- hsResult{sconn, chans, reqs, e}
		}()

		var handshakeOK bool
		select {
		case hs := <-hsCh:
			if hs.err != nil {
				hsConn.Close()
				debugLog.Debug("SSH handshake failed", "addr", addr, "obfuscated", isWrapped, "error", hs.err)
				// If obfuscation was active and handshake failed with EOF (or "connection reset"),
				// the server does not support it. Fall through to plain below.
				// Note: ssh.NewClientConn wraps errors without %w, so we check the message.
				isEOF := isWrapped && (strings.Contains(hs.err.Error(), "EOF") || strings.Contains(hs.err.Error(), "connection reset"))
				if isEOF {
					debugLog.Debug("obfuscation rejected by server, retrying with plain connection", "addr", addr)
				} else {
					lastErr = hs.err
					continue dials
				}
			} else {
				c.sshConn = ssh.NewClient(hs.sconn, hs.chans, hs.reqs)
				handshakeOK = true
			}
		case <-time.After(20 * time.Second):
			hsConn.Close()
			lastErr = fmt.Errorf("SSH handshake timed out after 20s for %s", addr)
			debugLog.Debug("SSH handshake timed out", "addr", addr)
			// Can't retry plain on timeout — the raw TCP connection was already consumed.
			continue dials
		case <-ctx.Done():
			hsConn.Close()
			return ctx.Err()
		}

		// If obfuscation failed with EOF, try again on the same addr without obfuscation.
		// This requires a fresh TCP connection since the raw one was already consumed.
		if !handshakeOK && isWrapped {
			debugLog.Debug("re-dialing for plain SSH handshake", "addr", addr)
			var plainConn net.Conn
			var plainErr error
			if proxyConf.SOCKS5 != "" {
				type pResult struct{ c net.Conn; e error }
				pCh := make(chan pResult, 1)
				go func() {
					c, e := socksDialer.Dial("tcp", addr)
					pCh <- pResult{c, e}
				}()
				select {
				case pr := <-pCh:
					plainConn, plainErr = pr.c, pr.e
				case <-time.After(12 * time.Second):
					plainErr = fmt.Errorf("SOCKS5 dial timed out after 12s")
				case <-ctx.Done():
					return ctx.Err()
				}
			} else {
				dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				plainConn, plainErr = netDialer.DialContext(dialCtx, "tcp", addr)
				cancel()
			}
			if plainErr != nil {
				debugLog.Debug("re-dial failed", "addr", addr, "error", plainErr)
				lastErr = plainErr
				continue dials
			}
			hsCh2 := make(chan hsResult, 1)
			go func() {
				sconn, chans, reqs, e := ssh.NewClientConn(plainConn, addr, sshConfig)
				hsCh2 <- hsResult{sconn, chans, reqs, e}
			}()
			select {
			case hs := <-hsCh2:
				if hs.err != nil {
					plainConn.Close()
					debugLog.Debug("plain SSH handshake also failed", "addr", addr, "error", hs.err)
					lastErr = hs.err
					continue dials
				}
				c.sshConn = ssh.NewClient(hs.sconn, hs.chans, hs.reqs)
				handshakeOK = true
			case <-time.After(20 * time.Second):
				plainConn.Close()
				lastErr = fmt.Errorf("plain SSH handshake timed out after 20s for %s", addr)
				continue dials
			case <-ctx.Done():
				plainConn.Close()
				return ctx.Err()
			}
		}

		if !handshakeOK {
			continue dials
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return fmt.Errorf("failed to connect to any address for %s: %w", host, lastErr)
	}

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

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	c.stdin = stdin

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	c.stdout = stdout

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	c.stderr = stderr

	go c.readOutput(c.stdout)
	go c.readOutput(c.stderr)

	c.shellStarted.Do(func() {
		if e := c.session.Shell(); e != nil {
			logger.Warn("shell start error", "error", e)
			c.sendError("Failed to start shell: " + e.Error())
		}
	})

	logger.Info("SSH connected", "user", username, "host", host, "port", port)
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
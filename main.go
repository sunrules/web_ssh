// go build -o webssh -ldflags "-s -w" .
// $env:CGO_ENABLED=0; $env:GOOS='linux'; $env:GOARCH='amd64'; go build -ldflags "-s -w" -o webssh .
// WebSSH — Web-based SSH client with WebSocket terminal.
// Usage: webssh [-p port] [-debug] [-key known_hosts] [-doh URL] [-proxy addr]

package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
	// TrustedProxies — CIDR/IP reverse-proxy, которым можно верить
	// X-Forwarded-For / X-Real-IP. Пусто = заголовки игнорируются.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

type ProxyConfig struct {
	SOCKS5          string   `json:"socks5,omitempty"`
	DoH             string   `json:"doh,omitempty"`
	DoHProviders    []string `json:"doh_providers,omitempty"`
	DirectIPs       []string `json:"direct_ips,omitempty"`
	AltPorts        []int    `json:"alt_ports,omitempty"`
	EnableTor       bool     `json:"enable_tor,omitempty"`
	SNIHostname     string   `json:"sni_hostname,omitempty"`
	SNIHostnames    []string `json:"sni_hostnames,omitempty"`
	ObfsSecret      string   `json:"obfs_secret,omitempty"`
	ECHConfigBase64 string   `json:"ech_config,omitempty"`

	MaxTLSAttempts   int           `json:"max_tls_attempts,omitempty"`
	TLSStrategyDelay time.Duration `json:"tls_strategy_delay,omitempty"`

	WSReadLimit  int64    `json:"ws_read_limit,omitempty"`
	WSOriginPins []string `json:"ws_origin_pins,omitempty"`

	// DirectFirst: для DoH-резолвленных IP пробовать прямое соединение
	// раньше SOCKS5 (актуально, когда Tor-exit режет порт 22).
	DirectFirst bool `json:"direct_first,omitempty"`
}

type WebSSHConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	WSPATH string `json:"ws_path"`
}

// ConnectionStrategy — одна попытка подключения.
type ConnectionStrategy struct {
	Address     string
	Obfuscation string // "tls" | "chacha" | "plain"
	Fingerprint utls.ClientHelloID
	SNI         string
	Direct      bool // true = минуя SOCKS5
	Description string
}

type SSHConnector struct {
	Host        string
	Port        int
	SSHConfig   *ssh.ClientConfig
	Ctx         context.Context
	SocksDialer proxy.Dialer
	NetDialer   *net.Dialer
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
	closeOnce    sync.Once
	closed       atomic.Bool
	limiter      *rate.Limiter
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	accessConf   AccessConfig
	proxyConf    ProxyConfig
	websshConf   WebSSHConfig
	debugMode    bool
	knownHostsFn ssh.HostKeyCallback

	logger   *slog.Logger
	debugLog *slog.Logger

	wsPath string

	utlsClientHelloID = utls.HelloChrome_Auto

	globalDoH *dohResolver

	utlsFingerprintPool = []utls.ClientHelloID{
		utls.HelloChrome_133,
		utls.HelloChrome_120_PQ,
		utls.HelloChrome_115_PQ,
		utls.HelloFirefox_Auto,
		utls.HelloIOS_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
		utls.HelloRandomizedALPN,
	}

	workingFingerprint    utls.ClientHelloID
	hasWorkingFingerprint bool
	fingerprintMu         sync.Mutex

	dohUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
	}

	defaultSNIPool = []string{
		"www.asus.com", "www.samsung.com", "www.dell.com", "www.lenovo.com",
		"www.microsoft.com", "www.google.com", "www.apple.com", "www.sony.com",
		"www.hp.com", "www.canon.com", "www.nvidia.com", "www.amd.com",
		"www.intel.com", "www.adobe.com", "www.office.com", "www.bing.com",
		"github.com", "www.mojeek.com", "duckduckgo.com", "www.wikipedia.org",
		"www.yahoo.com",
	}

	defaultDoHProviders = []string{
		"https://dns.cloudflare.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
		"https://mozilla.cloudflare-dns.com/dns-query",
		"https://doh.mullvad.net/dns-query",
		"https://dns.nextdns.io/dns-query",
		"https://dns.adguard-dns.com/dns-query",
		"https://dns.electrolab.ru/dns-query",
		"https://doh.opendns.com/dns-query",
	}

	// single-flight: не даём одному IP запускать параллельные подключения
	// (двойные клики Connect множили «шторм» мусорных handshake в sshd).
	guard = &connectGuard{active: make(map[string]bool)}
)

type connectGuard struct {
	mu     sync.Mutex
	active map[string]bool
}

func (g *connectGuard) acquire(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[ip] {
		return false
	}
	g.active[ip] = true
	return true
}

func (g *connectGuard) release(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.active, ip)
}

// ---------------------------------------------------------------------------
// Кэш последней успешной стратегии (per host:port)
// ---------------------------------------------------------------------------

type strategyCacheEntry struct {
	s ConnectionStrategy
	t time.Time
}

var stratCache = struct {
	sync.Mutex
	m map[string]strategyCacheEntry
}{m: make(map[string]strategyCacheEntry)}

const strategyCacheTTL = 10 * time.Minute

func cacheKey(host string, port int) string { return fmt.Sprintf("%s:%d", host, port) }

func getCachedStrategy(host string, port int) (ConnectionStrategy, bool) {
	stratCache.Lock()
	defer stratCache.Unlock()
	e, ok := stratCache.m[cacheKey(host, port)]
	if !ok || time.Since(e.t) > strategyCacheTTL {
		return ConnectionStrategy{}, false
	}
	return e.s, true
}

func putCachedStrategy(host string, port int, s ConnectionStrategy) {
	stratCache.Lock()
	defer stratCache.Unlock()
	stratCache.m[cacheKey(host, port)] = strategyCacheEntry{s: s, t: time.Now()}
}

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

func applyProxyDefaults() {
	if proxyConf.MaxTLSAttempts <= 0 {
		proxyConf.MaxTLSAttempts = 4
	}
	if proxyConf.TLSStrategyDelay <= 0 {
		proxyConf.TLSStrategyDelay = 25 * time.Second
	}
	if proxyConf.WSReadLimit <= 0 {
		proxyConf.WSReadLimit = 1 << 20
	}
	if len(proxyConf.DoHProviders) == 0 {
		proxyConf.DoHProviders = defaultDoHProviders
	}
}

func loadProxyConfig(path string) error {
	// Дефолты применяются ВСЕГДА, в т.ч. когда файла нет (раньше при отсутствии
	// proxy.json оставались нулевые лимиты и пустой пул DoH).
	proxyConf = ProxyConfig{DirectFirst: true}
	applyProxyDefaults()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read proxy config: %w", err)
	}
	if err := json.Unmarshal(data, &proxyConf); err != nil {
		return err
	}
	applyProxyDefaults()
	return nil
}

func loadWebSSHConfig(path string) {
	websshConf = WebSSHConfig{Host: "localhost", Port: 22}
	data, err := os.ReadFile(path)
	if err != nil {
		debugLog.Debug("webssh.conf not found, using defaults", "path", path, "error", err)
		return
	}

	helloIDs := map[string]utls.ClientHelloID{
		"HelloChrome_Auto":   utls.HelloChrome_Auto,
		"HelloChrome_133":    utls.HelloChrome_133,
		"HelloChrome_120":    utls.HelloChrome_120,
		"HelloChrome_120_PQ": utls.HelloChrome_120_PQ,
		"HelloChrome_115_PQ": utls.HelloChrome_115_PQ,
		"HelloFirefox_Auto":  utls.HelloFirefox_Auto,
		"HelloEdge_Auto":     utls.HelloEdge_Auto,
		"HelloSafari_Auto":   utls.HelloSafari_Auto,
		"HelloIOS_Auto":      utls.HelloIOS_Auto,
		"HelloRandomized":    utls.HelloRandomized,
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
				if p, e := strconv.Atoi(val); e == nil && p > 0 && p < 65536 {
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

func ipInNets(ip string, nets []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n == ip {
			return true
		}
		if _, ipNet, err := net.ParseCIDR(n); err == nil && ipNet.Contains(parsed) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIP учитывает X-Forwarded-For/X-Real-IP ТОЛЬКО от доверенных прокси.
func clientIP(r *http.Request) string {
	rip := remoteIP(r)
	if len(accessConf.TrustedProxies) == 0 || !ipInNets(rip, accessConf.TrustedProxies) {
		return rip
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return rip
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS resolver
// ---------------------------------------------------------------------------

type dohResolver struct {
	providers    []string
	client       *http.Client
	healthMu     sync.RWMutex
	healthStatus map[int]bool
	lastCheck    time.Time
}

func newDoHResolver(primaryURL string, additionalProviders []string, proxyAddr string) *dohResolver {
	if primaryURL == "" && len(additionalProviders) == 0 {
		return nil
	}
	providers := make([]string, 0, 1+len(additionalProviders))
	if primaryURL != "" {
		providers = append(providers, primaryURL)
	}
	for _, p := range additionalProviders {
		if p != "" && p != primaryURL {
			providers = append(providers, p)
		}
	}
	if len(providers) == 0 {
		return nil
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          5,
		IdleConnTimeout:       30 * time.Second,
	}

	if proxyAddr != "" {
		socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err == nil {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				debugLog.Debug("DoH request routed through SOCKS5", "proxy", proxyAddr, "target", addr)
				return socksDialer.Dial(network, addr)
			}
			debugLog.Info("DoH resolver configured with SOCKS5 proxy", "proxy", proxyAddr)
		} else {
			logger.Warn("failed to create SOCKS5 dialer for DoH, using direct", "error", err)
		}
	}

	healthStatus := make(map[int]bool, len(providers))
	for i := range providers {
		healthStatus[i] = true
	}
	return &dohResolver{
		providers:    providers,
		client:       &http.Client{Timeout: 10 * time.Second, Transport: transport},
		healthStatus: healthStatus,
	}
}

func (r *dohResolver) healthCheck(ctx context.Context, interval time.Duration) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	r.runHealthCheck(ctx)
	for {
		select {
		case <-ticker.C:
			r.runHealthCheck(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// runHealthCheck: запросы ПАРАЛЛЕЛЬНО и ВНЕ лока; под локом только обновление карты.
// Раньше write-lock держался до 90с и блокировал все новые подключения.
func (r *dohResolver) runHealthCheck(ctx context.Context) {
	results := make([]bool, len(r.providers))
	var wg sync.WaitGroup
	for i, p := range r.providers {
		wg.Add(1)
		go func(i int, provider string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err := dohWireQuery(cctx, r.client, provider, "cloudflare.com", dnsmessage.TypeA)
			results[i] = err == nil
		}(i, p)
	}
	wg.Wait()

	r.healthMu.Lock()
	for i, ok := range results {
		if r.healthStatus[i] && !ok {
			debugLog.Warn("DoH provider became unhealthy", "provider", r.providers[i], "index", i)
		}
		if !r.healthStatus[i] && ok {
			debugLog.Info("DoH provider recovered", "provider", r.providers[i], "index", i)
		}
		r.healthStatus[i] = ok
	}
	r.lastCheck = time.Now()
	r.healthMu.Unlock()
}

func (r *dohResolver) getHealthyProviders() []string {
	if r == nil {
		return nil
	}
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	healthy := make([]string, 0, len(r.providers))
	for i, p := range r.providers {
		if r.healthStatus[i] {
			healthy = append(healthy, p)
		}
	}
	return healthy
}

func (r *dohResolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	if r == nil {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	healthy := r.getHealthyProviders()
	if len(healthy) == 0 {
		debugLog.Warn("DoH: all providers unhealthy, using original list")
		healthy = r.providers
	}
	for _, providerURL := range healthy {
		ips, err := r.queryProvider(ctx, providerURL, host)
		if err == nil && len(ips) > 0 {
			debugLog.Debug("DoH resolved", "host", host, "ips", ips, "provider", providerURL)
			return ips, nil
		}
		debugLog.Debug("DoH provider failed", "provider", providerURL, "host", host, "error", err)
	}
	return nil, fmt.Errorf("DoH: all providers failed for %s", host)
}

func (r *dohResolver) queryProvider(ctx context.Context, providerURL, host string) ([]string, error) {
	var allIPs []string
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		ips, err := dohWireQuery(qctx, r.client, providerURL, host, qtype)
		cancel()
		if err != nil {
			debugLog.Debug("DoH wire query failed", "provider", providerURL, "host", host, "type", qtype, "error", err)
			continue
		}
		allIPs = append(allIPs, ips...)
	}
	if len(allIPs) > 0 {
		return allIPs, nil
	}
	return nil, fmt.Errorf("DoH: no records for %s via %s", host, providerURL)
}

func dohWireQuery(ctx context.Context, client *http.Client, providerURL, host string, qtype dnsmessage.Type) ([]string, error) {
	fqdn := host
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	// NewName вместо MustNewName: кривой host из формы больше не паникует.
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %w", host, err)
	}

	msg := new(dnsmessage.Message)
	msg.Header.ID = uint16(time.Now().UnixNano())
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnsmessage pack: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, providerURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", dohUserAgents[mrand.IntN(len(dohUserAgents))])

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("dnsmessage unpack: %w", err)
	}
	if reply.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DoH rcode %d for %s", reply.Header.RCode, host)
	}

	var ips []string
	for _, ans := range reply.Answers {
		switch rr := ans.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, net.IP(rr.A[:]).String())
		case *dnsmessage.AAAAResource:
			ips = append(ips, net.IP(rr.AAAA[:]).String())
		}
	}
	return ips, nil
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
// uTLS camouflage
// ---------------------------------------------------------------------------

func getFingerprintCandidates() []utls.ClientHelloID {
	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()

	candidates := make([]utls.ClientHelloID, 0, len(utlsFingerprintPool)+1)
	if hasWorkingFingerprint {
		candidates = append(candidates, workingFingerprint)
	}
	if !hasWorkingFingerprint || workingFingerprint != utlsClientHelloID {
		candidates = append(candidates, utlsClientHelloID)
	}
	seen := make(map[utls.ClientHelloID]bool, len(candidates))
	for _, fp := range candidates {
		seen[fp] = true
	}
	for _, fp := range utlsFingerprintPool {
		if !seen[fp] {
			candidates = append(candidates, fp)
			seen[fp] = true
		}
	}
	return candidates
}

func recordWorkingFingerprint(fp utls.ClientHelloID) {
	fingerprintMu.Lock()
	defer fingerprintMu.Unlock()
	if !hasWorkingFingerprint || workingFingerprint != fp {
		workingFingerprint = fp
		hasWorkingFingerprint = true
		debugLog.Info("uTLS fingerprint cached as working", "fingerprint", fp.Str())
	}
}

func getSNIHostnames() []string {
	if len(proxyConf.SNIHostnames) > 0 {
		return proxyConf.SNIHostnames
	}
	if proxyConf.SNIHostname != "" {
		return []string{proxyConf.SNIHostname}
	}
	return defaultSNIPool
}

type uTLSCamouflageConn struct {
	*utls.UConn
	mu     sync.Mutex
	closed atomic.Bool
}

// newUTLSCamouflageConn: handshake с таймаутом через HandshakeContext.
// Раньше Handshake() без дедлайна мог висеть вечно при дропе пакетов ТСПУ.
func newUTLSCamouflageConn(ctx context.Context, conn net.Conn, sniHostname string, fp utls.ClientHelloID) (*uTLSCamouflageConn, error) {
	tlsConfig := &utls.Config{
		ServerName:         sniHostname,
		InsecureSkipVerify: true,
	}
	if proxyConf.ECHConfigBase64 != "" {
		if echConf, err := base64.RawStdEncoding.DecodeString(proxyConf.ECHConfigBase64); err == nil {
			tlsConfig.EncryptedClientHelloConfigList = echConf
			debugLog.Debug("ECH enabled", "config_len", len(echConf))
		} else {
			debugLog.Warn("ECH config decode failed, proceeding without ECH", "error", err)
		}
	}

	tlsConn := utls.UClient(conn, tlsConfig, fp)

	if isCustomFingerprint(fp) {
		if err := tlsConn.ApplyPreset(buildCustomFingerprintSpec()); err != nil {
			debugLog.Debug("uTLS ApplyPreset failed, using parrot defaults", "fingerprint", fp.Str(), "error", err)
		}
	}

	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed [%s]: %w", fp.Str(), err)
	}

	state := tlsConn.ConnectionState()
	debugLog.Debug("uTLS camouflage established",
		"sni", sniHostname, "client_hello_id", fp.Str(),
		"cipher", state.CipherSuite, "version", state.Version)

	return &uTLSCamouflageConn{UConn: tlsConn}, nil
}

func isCustomFingerprint(fp utls.ClientHelloID) bool {
	switch fp {
	case utls.HelloCustom, utls.HelloRandomizedALPN, utls.HelloRandomized, utls.HelloRandomizedNoALPN:
		return true
	default:
		return false
	}
}

func buildCustomFingerprintSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMax:         utls.VersionTLS13,
		TLSVersMin:         utls.VersionTLS12,
		CompressionMethods: []uint8{0},
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519Kyber768Draft00, utls.X25519, utls.CurveP256, utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.ECDSAWithP521AndSHA512, utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519Kyber768Draft00, Data: make([]byte, 32)},
				{Group: utls.X25519, Data: make([]byte, 32)},
				{Group: utls.CurveP256, Data: make([]byte, 32)},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.UtlsGREASEExtension{},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

func (tc *uTLSCamouflageConn) Close() error {
	if !tc.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = tc.UConn.CloseWrite()
	return tc.UConn.Close()
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 obfuscation (HKDF-SHA256 KDF)
// ---------------------------------------------------------------------------

type obfuscatedConn struct {
	net.Conn
	aead     cipher.AEAD
	writeMu  sync.Mutex
	writeBuf []byte
}

func newObfuscatedConn(conn net.Conn, secret string) (*obfuscatedConn, error) {
	if secret == "" {
		return nil, errors.New("chacha: empty obfs_secret")
	}
	salt := []byte("WebSSH/ChaCha20-Poly1305/v1")
	info := []byte("key")
	reader := hkdf.New(sha256.New, []byte(secret), salt, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("chacha hkdf: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 new: %w", err)
	}

	oc := &obfuscatedConn{Conn: conn, aead: aead, writeBuf: make([]byte, 0, 65536)}

	preamble := make([]byte, 64+mrand.IntN(256))
	if _, err := rand.Read(preamble); err != nil {
		return nil, fmt.Errorf("preamble rand: %w", err)
	}
	preamble[0] = 0x16
	preamble[1] = 0x03
	preamble[2] = 0x03

	// Таймаут на запись преамбулы (раньше мог висеть вечно).
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, werr := conn.Write(preamble)
	_ = conn.SetWriteDeadline(time.Time{})
	if werr != nil {
		return nil, fmt.Errorf("chacha preamble: %w", werr)
	}
	debugLog.Debug("ChaCha20-Poly1305 obfuscation enabled (HKDF-SHA256 KDF)", "secret_len", len(secret), "preamble_len", len(preamble))
	return oc, nil
}

func (oc *obfuscatedConn) Read(b []byte) (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(oc.Conn, lenBuf); err != nil {
		return 0, fmt.Errorf("chacha read len: %w", err)
	}
	dataLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if dataLen > 65536 {
		return 0, fmt.Errorf("chacha: packet too large: %d", dataLen)
	}
	packet := make([]byte, chacha20poly1305.NonceSizeX+dataLen+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(oc.Conn, packet); err != nil {
		return 0, fmt.Errorf("chacha read packet: %w", err)
	}
	pktNonce := packet[:chacha20poly1305.NonceSizeX]
	ciphertext := packet[chacha20poly1305.NonceSizeX:]
	plaintext, err := oc.aead.Open(b[:0], pktNonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("chacha decrypt: %w", err)
	}
	return len(plaintext), nil
}

func (oc *obfuscatedConn) Write(b []byte) (int, error) {
	oc.writeMu.Lock()
	defer oc.writeMu.Unlock()
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("chacha nonce: %w", err)
	}
	ciphertext := oc.aead.Seal(nil, nonce, b, nil)
	oc.writeBuf = append(oc.writeBuf[:0], byte(len(ciphertext)>>8), byte(len(ciphertext)))
	oc.writeBuf = append(oc.writeBuf, nonce...)
	oc.writeBuf = append(oc.writeBuf, ciphertext...)
	if _, err := oc.Conn.Write(oc.writeBuf); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------

func buildUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" || len(proxyConf.WSOriginPins) == 0 {
				return true
			}
			for _, pin := range proxyConf.WSOriginPins {
				if strings.EqualFold(origin, pin) {
					return true
				}
			}
			debugLog.Warn("WS upgrade with non-pinned Origin", "origin", origin, "remote", r.RemoteAddr)
			return false
		},
	}
}

func securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Для полностью self-hosted xterm уберите https://cdn.jsdelivr.net из CSP.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self' wss: ws:; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net data:")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

		if r.URL.Path == wsPath {
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
		ip := clientIP(r)
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

	limit := proxyConf.WSReadLimit
	if limit <= 0 {
		limit = 1 << 20
	}
	conn.SetReadLimit(limit)

	limiter := rate.NewLimiter(rate.Limit(512*1024), 1024*1024)
	const (
		pongWait   = 60 * time.Second
		pingPeriod = 30 * time.Second
	)

	client := &WebSocketClient{conn: conn, done: make(chan struct{}), limiter: limiter}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ip := remoteIP(r)
	if !guard.acquire(ip) {
		client.sendError("A connection attempt is already in progress for your IP")
		return
	}
	defer guard.release(ip)

	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()
	go func() {
		for {
			select {
			case <-client.done:
				return
			case <-pingTicker.C:
				client.writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := conn.WriteMessage(websocket.PingMessage, nil)
				client.writeMu.Unlock()
				if err != nil {
					// Браузер ушёл: прерываем connectSSH/сессию и закрываем WS.
					cancel()
					_ = conn.Close()
					return
				}
			}
		}
	}()

	var authData struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		logger.Warn("error reading auth data", "error", err)
		return
	}
	if err := json.Unmarshal(msg, &authData); err != nil {
		client.sendError("Invalid authentication data")
		return
	}
	host := strings.TrimSpace(authData.Host)
	port := authData.Port
	username := strings.TrimSpace(authData.Username)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\") {
		client.sendError("Invalid host")
		return
	}
	if port <= 0 || port > 65535 {
		client.sendError("Invalid port")
		return
	}
	if username == "" {
		client.sendError("Invalid username")
		return
	}

	// Во время connectSSH НЕ читаем WS и НЕ держим read-deadline:
	// любая ошибка чтения (в т.ч. timeout) необратимо ломает gorilla-соединение.
	_ = conn.SetReadDeadline(time.Time{})

	connectErr := client.connectSSH(ctx, host, port, username, authData.Password)
	if connectErr != nil {
		logger.Warn("SSH connection error", "host", host, "port", port, "user", username, "error", connectErr)
		client.sendError(fmt.Sprintf("SSH connection failed: %v", connectErr))
		client.close()
		return
	}

	// Дедлайн и pong-handler взводим только после успешного подключения.
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	defer client.close()
	client.handleMessages()
}

func isIPAddress(host string) bool { return net.ParseIP(host) != nil }

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

// ---------------------------------------------------------------------------
// SSH connector
// ---------------------------------------------------------------------------

func (c *WebSocketClient) connectSSH(ctx context.Context, host string, port int, username, password string) error {
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: knownHostsFn,
		Timeout:         20 * time.Second, // внимание: работает только в ssh.Dial; реальный лимит — SetDeadline в tryStrategy
	}

	connector := &SSHConnector{
		Host:        host,
		Port:        port,
		SSHConfig:   sshConfig,
		Ctx:         ctx,
		SocksDialer: socksDialer(proxyConf.SOCKS5),
		NetDialer:   &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
	}

	strategies := connector.buildStrategies()

	maxAttempts := proxyConf.MaxTLSAttempts
	if maxAttempts <= 0 {
		maxAttempts = 4
	}
	delay := proxyConf.TLSStrategyDelay
	if delay <= 0 {
		delay = 25 * time.Second
	}

	var lastErr error
	perAddrFail := make(map[string]int)

	for i, strategy := range strategies {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		debugLog.Debug("trying connection strategy",
			"idx", i+1, "of", len(strategies),
			"addr", strategy.Address, "obfs", strategy.Obfuscation,
			"sni", strategy.SNI, "direct", strategy.Direct,
			"fingerprint", strategy.Fingerprint.Str(), "desc", strategy.Description)

		// Прогресс для фронтенда (неизвестные типы сообщений он игнорирует).
		c.sendJSON(map[string]any{"type": "progress", "data": strategy.Description})

		if strategy.Obfuscation == "tls" && perAddrFail[strategy.Address] >= maxAttempts {
			logger.Info("TLS handshake budget exhausted for addr, backing off",
				"addr", strategy.Address, "failures", perAddrFail[strategy.Address], "delay", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
			perAddrFail[strategy.Address] = 0
		}

		sshClient, err := connector.tryStrategy(strategy)
		if err != nil {
			lastErr = err
			if strategy.Obfuscation == "tls" {
				perAddrFail[strategy.Address]++
			}
			debugLog.Debug("strategy failed", "addr", strategy.Address, "error", err)
			continue
		}

		c.sshConn = sshClient
		putCachedStrategy(host, port, strategy)
		lastErr = nil
		break
	}

	if lastErr != nil {
		return fmt.Errorf("all connection strategies failed for %s: %w", host, lastErr)
	}
	if c.sshConn == nil {
		return errors.New("no strategy succeeded")
	}
	if err := c.setupSession(); err != nil {
		c.sshConn.Close()
		c.sshConn = nil
		return err
	}
	logger.Info("SSH connected", "user", username, "host", host, "port", port)
	return nil
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

// TLS-стратегий на адрес не больше бюджета MaxTLSAttempts,
// иначе backoff срабатывал на КАЖДОМ подключении (6 > 4).
func maxTLSPerAddr() int {
	n := proxyConf.MaxTLSAttempts
	if n <= 0 {
		n = 4
	}
	if n > 4 {
		n = 4
	}
	return n
}

func buildTLSStrategies(addr, label string, fps []utls.ClientHelloID, sniHostnames []string, direct bool) []ConnectionStrategy {
	if len(fps) == 0 || len(sniHostnames) == 0 {
		return nil
	}
	cap := maxTLSPerAddr()
	var out []ConnectionStrategy
	topFP := fps[0]

	const maxInitialSNI = 3
	for i := 0; i < len(sniHostnames) && i < maxInitialSNI && len(out) < cap; i++ {
		sni := sniHostnames[i]
		out = append(out, ConnectionStrategy{
			Address: addr, Obfuscation: "tls", Fingerprint: topFP, SNI: sni, Direct: direct,
			Description: fmt.Sprintf("%s + TLS [%s] SNI:%s", label, topFP.Str(), sni),
		})
	}

	type combo struct {
		fp  utls.ClientHelloID
		sni string
	}
	rest := make([]combo, 0, (len(fps)-1)*len(sniHostnames))
	for _, fp := range fps {
		if fp == topFP {
			continue
		}
		for _, sni := range sniHostnames {
			rest = append(rest, combo{fp, sni})
		}
	}
	mrand.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	for _, cb := range rest {
		if len(out) >= cap {
			break
		}
		out = append(out, ConnectionStrategy{
			Address: addr, Obfuscation: "tls", Fingerprint: cb.fp, SNI: cb.sni, Direct: direct,
			Description: fmt.Sprintf("%s + TLS [%s] SNI:%s", label, cb.fp.Str(), cb.sni),
		})
	}
	return out
}

func (sc *SSHConnector) buildStrategies() []ConnectionStrategy {
	var strategies []ConnectionStrategy
	seen := make(map[string]bool)
	add := func(s ConnectionStrategy) {
		k := fmt.Sprintf("%s|%s|%s|%v|%s", s.Address, s.Obfuscation, s.SNI, s.Direct, s.Fingerprint.Str())
		if seen[k] {
			return
		}
		seen[k] = true
		strategies = append(strategies, s)
	}

	fps := getFingerprintCandidates()
	sniHostnames := getSNIHostnames()
	hasSNI := len(sniHostnames) > 0
	hasObfs := proxyConf.ObfsSecret != ""
	hasProxy := proxyConf.SOCKS5 != ""
	origAddr := net.JoinHostPort(sc.Host, strconv.Itoa(sc.Port))

	// 0) Последняя успешная стратегия — первой.
	if cached, ok := getCachedStrategy(sc.Host, sc.Port); ok {
		add(cached)
	}

	bundle := func(addr, label string, direct, withTLS bool) {
		if withTLS && hasSNI {
			for _, s := range buildTLSStrategies(addr, label, fps, sniHostnames, direct) {
				add(s)
			}
		}
		if hasObfs {
			add(ConnectionStrategy{Address: addr, Obfuscation: "chacha", Direct: direct,
				Description: label + " + ChaCha20"})
		}
		add(ConnectionStrategy{Address: addr, Obfuscation: "plain", Direct: direct,
			Description: label + " (plain SSH)"})
	}

	if isIPAddress(sc.Host) {
		// IP-литерал: голый sshd почти всегда без TLS-терминатора.
		// Plain direct первым; обфускация и SOCKS — только фолбэк.
		add(ConnectionStrategy{Address: origAddr, Obfuscation: "plain", Direct: true,
			Description: "IP literal: plain SSH direct"})
		if hasObfs {
			add(ConnectionStrategy{Address: origAddr, Obfuscation: "chacha", Direct: true,
				Description: "IP literal + ChaCha20 direct"})
		}
		if hasSNI {
			for _, s := range buildTLSStrategies(origAddr, "IP literal", fps, sniHostnames, true) {
				add(s)
			}
		}
		if hasProxy {
			bundle(origAddr, "IP literal via SOCKS5", false, true)
		}
	} else {
		// Hostname: DoH (IPv6 приоритет), ограничиваем число IP.
		var ips []string
		doh := globalDoH
		if doh == nil {
			doh = newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
		}
		if !isPrivateHost(sc.Host) && doh != nil {
			if resolved, err := doh.lookupHost(sc.Ctx, sc.Host); err == nil {
				ips = resolved
				debugLog.Debug("DoH resolved", "host", sc.Host, "ips", ips)
			} else {
				debugLog.Debug("DoH lookup failed", "host", sc.Host, "error", err)
			}
		}
		ipv6 := make([]string, 0)
		ipv4 := make([]string, 0)
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				ipv6 = append(ipv6, ip)
			} else {
				ipv4 = append(ipv4, ip)
			}
		}
		if len(ipv6) > 2 {
			ipv6 = ipv6[:2]
		}
		if len(ipv4) > 2 {
			ipv4 = ipv4[:2]
		}

		directDoH := !hasProxy || proxyConf.DirectFirst
		for _, ip := range ipv6 {
			bundle(net.JoinHostPort(ip, strconv.Itoa(sc.Port)), "DoH IPv6", directDoH, true)
		}
		for _, ip := range ipv4 {
			bundle(net.JoinHostPort(ip, strconv.Itoa(sc.Port)), "DoH IPv4", directDoH, true)
		}

		// Direct-фолбэк мимо SOCKS5/Tor (exit-ноды часто режут порт 22).
		if hasProxy && !proxyConf.DirectFirst {
			add(ConnectionStrategy{Address: origAddr, Obfuscation: "plain", Direct: true,
				Description: "original host (plain SSH direct fallback)"})
			for _, ip := range append(append([]string{}, ipv6...), ipv4...) {
				add(ConnectionStrategy{Address: net.JoinHostPort(ip, strconv.Itoa(sc.Port)),
					Obfuscation: "plain", Direct: true, Description: "DoH IP plain direct fallback"})
			}
		}

		bundle(origAddr, "original host", !hasProxy, true)
	}

	// Direct IPs (всегда напрямую).
	for _, ip := range proxyConf.DirectIPs {
		add(ConnectionStrategy{Address: net.JoinHostPort(ip, strconv.Itoa(sc.Port)),
			Obfuscation: "plain", Direct: true, Description: fmt.Sprintf("direct IP %s", ip)})
	}

	// Alt ports.
	for _, altPort := range proxyConf.AltPorts {
		addr := net.JoinHostPort(sc.Host, strconv.Itoa(altPort))
		if hasObfs {
			add(ConnectionStrategy{Address: addr, Obfuscation: "chacha", Direct: true,
				Description: fmt.Sprintf("alt port %d + ChaCha20", altPort)})
		}
		add(ConnectionStrategy{Address: addr, Obfuscation: "plain", Direct: true,
			Description: fmt.Sprintf("alt port %d", altPort)})
	}

	return strategies
}

func (sc *SSHConnector) tryStrategy(s ConnectionStrategy) (*ssh.Client, error) {
	conn, err := sc.dial(s.Address, s.Direct)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	wrappedConn, obfsErr := sc.applyObfuscation(sc.Ctx, conn, s.Obfuscation, s.Fingerprint, s.SNI)
	if obfsErr != nil {
		conn.Close()
		return nil, fmt.Errorf("obfuscation failed: %w", obfsErr)
	}

	// known_hosts проверяем по исходному hostname, а не по DoH-IP.
	checkAddr := s.Address
	if !isIPAddress(sc.Host) {
		checkAddr = net.JoinHostPort(sc.Host, strconv.Itoa(sc.Port))
	}

	// ClientConfig.Timeout НЕ применяется в NewClientConn — ставим дедлайн сами.
	_ = wrappedConn.SetDeadline(time.Now().Add(20 * time.Second))
	sshConn, chans, reqs, err := ssh.NewClientConn(wrappedConn, checkAddr, sc.SSHConfig)
	if err != nil {
		wrappedConn.Close()
		return nil, fmt.Errorf("SSH handshake failed: %w", err)
	}
	_ = wrappedConn.SetDeadline(time.Time{}) // снимаем для интерактивной сессии

	if s.Obfuscation == "tls" {
		recordWorkingFingerprint(s.Fingerprint)
	}
	debugLog.Debug("strategy succeeded", "addr", s.Address, "obfs", s.Obfuscation,
		"direct", s.Direct, "fingerprint", s.Fingerprint.Str(), "desc", s.Description)
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (sc *SSHConnector) dial(addr string, direct bool) (net.Conn, error) {
	if host, _, err := net.SplitHostPort(addr); err == nil && isPrivateHost(host) {
		if proxyConf.SOCKS5 != "" {
			debugLog.Debug("bypassing SOCKS5 for private/loopback host", "addr", addr, "host", host)
		}
		ctx, cancel := context.WithTimeout(sc.Ctx, 15*time.Second)
		defer cancel()
		return sc.NetDialer.DialContext(ctx, "tcp", addr)
	}
	if direct || proxyConf.SOCKS5 == "" {
		ctx, cancel := context.WithTimeout(sc.Ctx, 15*time.Second)
		defer cancel()
		return sc.NetDialer.DialContext(ctx, "tcp", addr)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	ctx, cancel := context.WithTimeout(sc.Ctx, 15*time.Second)
	defer cancel()
	go func() {
		c, e := sc.SocksDialer.Dial("tcp", addr)
		select {
		case ch <- dialResult{c, e}:
		case <-ctx.Done():
			if c != nil {
				c.Close()
			}
		}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("SOCKS5 dial timeout after 15s")
	case <-sc.Ctx.Done():
		return nil, sc.Ctx.Err()
	}
}

func (sc *SSHConnector) applyObfuscation(ctx context.Context, conn net.Conn, method string, fp utls.ClientHelloID, sniHostname string) (net.Conn, error) {
	switch method {
	case "tls":
		if sniHostname == "" {
			sniList := getSNIHostnames()
			if len(sniList) == 0 {
				conn.Close()
				return nil, errors.New("tls obfuscation requires sni_hostname(s)")
			}
			sniHostname = sniList[0]
		}
		tlsConn, err := newUTLSCamouflageConn(ctx, conn, sniHostname, fp)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("uTLS camouflage failed: %w", err)
		}
		return tlsConn, nil
	case "chacha":
		if proxyConf.ObfsSecret == "" {
			conn.Close()
			return nil, errors.New("chacha obfuscation requires obfs_secret")
		}
		chachaConn, err := newObfuscatedConn(conn, proxyConf.ObfsSecret)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("ChaCha20 obfuscation failed: %w", err)
		}
		return chachaConn, nil
	default:
		return conn, nil
	}
}

// ---------------------------------------------------------------------------
// SSH session management
// ---------------------------------------------------------------------------

func (c *WebSocketClient) setupSession() error {
	session, err := c.sshConn.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	c.session = session

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	// RequestPty(term, rows, cols): раньше было 160 строк × 48 колонок.
	if e := session.RequestPty("xterm-256color", 48, 160, modes); e != nil {
		if e2 := session.RequestPty("xterm", 48, 160, modes); e2 != nil {
			if e3 := session.RequestPty("vt100", 48, 160, modes); e3 != nil {
				return fmt.Errorf("request pty: xterm-256color: %v, xterm: %v, vt100: %v", e, e2, e3)
			}
		}
	}

	c.stdin, _ = session.StdinPipe()
	c.stdout, _ = session.StdoutPipe()
	c.stderr, _ = session.StderrPipe()

	// Shell ДО запуска читателей; ошибка больше не глотается.
	var shellErr error
	c.shellStarted.Do(func() { shellErr = c.session.Shell() })
	if shellErr != nil {
		return fmt.Errorf("shell: %w", shellErr)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.readOutput(c.stdout) }()
	go func() { defer wg.Done(); c.readOutput(c.stderr) }()
	// Оба потока вывода завершились (exit/обрыв) → закрываем и WS,
	// чтобы фронтенд увидел закрытие, а не «зомби-терминал».
	go func() {
		wg.Wait()
		c.close()
		_ = c.conn.Close()
	}()
	return nil
}

func (c *WebSocketClient) readOutput(reader io.Reader) {
	buf := make([]byte, 8192)
	for {
		if c.closed.Load() {
			return
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
	for {
		if c.closed.Load() {
			return
		}
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
			if c.limiter != nil && !c.limiter.Allow() {
				debugLog.Warn("WS rate limit exceeded for command")
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
	if c.closed.Load() {
		return
	}
	c.sendJSON(map[string]any{"type": "output", "data": data})
}

func (c *WebSocketClient) sendError(errMsg string) {
	if c.closed.Load() {
		return
	}
	c.sendJSON(map[string]any{"type": "error", "error": errMsg})
}

func (c *WebSocketClient) sendJSON(msg map[string]any) {
	if c.closed.Load() {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteJSON(msg); err != nil {
		logger.Warn("WriteJSON error", "error", err)
	}
}

func (c *WebSocketClient) close() {
	c.closeOnce.Do(func() {
		if !c.closed.Load() {
			close(c.done)
			c.closed.Store(true)
		}
	})
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
// Random path generation
// ---------------------------------------------------------------------------

func generateWSPath() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		return fmt.Sprintf("/w%016x", n.Uint64())
	}
	return "/" + hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Main
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

Notes:
  - Для IP-целей plain SSH пробуется первым; TLS/ChaCha — фолбэк (нужен терминатор на сервере).
  - direct_first (proxy.json): DoH-IP пробуются напрямую раньше SOCKS5/Tor.
  - trusted_proxies (access.json): только эти proxy могут задавать X-Forwarded-For/X-Real-IP.
  - Для прода рекомендуется Xray-core (VLESS+Reality+Vision) или AmneziaWG отдельным процессом.

Examples:
  webssh
  webssh -p 8080 -debug
  webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050
`)
	os.Exit(0)
}

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

	wsPath = generateWSPath()
	websshConf.WSPATH = wsPath

	logger.Info("starting WebSSH",
		"go_version", runtime.Version(), "port", *flagPort, "debug", debugMode,
		"doh", *flagDoH, "proxy", *flagProxy, "ws_path", wsPath)

	loadWebSSHConfig(filepath.Join(baseDir, "webssh.conf"))

	accessPath := filepath.Join(baseDir, "access.json")
	if err := loadAccessConfig(accessPath); err != nil {
		logger.Warn("could not load access.json, allowing all IPs", "error", err)
		accessConf = AccessConfig{AllowedIPs: []string{"*"}}
	} else {
		debugLog.Debug("access config loaded", "allowed_ips", len(accessConf.AllowedIPs),
			"trusted_proxies", len(accessConf.TrustedProxies))
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
	if proxyConf.EnableTor && proxyConf.SOCKS5 == "" {
		proxyConf.SOCKS5 = "127.0.0.1:9050"
		logger.Info("Tor mode enabled, SOCKS5 set to 127.0.0.1:9050")
	}

	globalDoH = newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
	if globalDoH != nil {
		go globalDoH.healthCheck(context.Background(), 30*time.Second)
		debugLog.Debug("DoH health check background worker started", "interval", "30s")
	}

	debugLog.Debug("proxy config",
		"doh", proxyConf.DoH, "doh_providers", len(proxyConf.DoHProviders),
		"socks5", proxyConf.SOCKS5, "direct_ips", proxyConf.DirectIPs,
		"alt_ports", proxyConf.AltPorts, "sni_hostname", proxyConf.SNIHostname,
		"sni_hostnames", len(proxyConf.SNIHostnames), "ech_config", proxyConf.ECHConfigBase64 != "",
		"fingerprints_pool", len(utlsFingerprintPool), "origin_pins", len(proxyConf.WSOriginPins),
		"max_tls_attempts", proxyConf.MaxTLSAttempts, "direct_first", proxyConf.DirectFirst)

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

	upgrader = buildUpgrader()

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

	mux.HandleFunc("/config", securityMiddleware(ipMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(websshConf)
	})))

	mux.HandleFunc(wsPath, securityMiddleware(ipMiddleware(handleWebSocket)))
	if wsPath != "/ws" {
		mux.HandleFunc("/ws", securityMiddleware(ipMiddleware(handleWebSocket)))
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		SessionTicketsDisabled: false,
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", *flagPort),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, // не влияет на WS: gorilla сбрасывает дедлайны при Upgrade
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
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

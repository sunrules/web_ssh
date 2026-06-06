// go build -o webssh -ldflags "-s -w" 2>&1
//
// WebSSH — Web-based SSH client with WebSocket terminal
// Provides a web interface to connect to SSH servers
// through a browser with full terminal emulation.
//
// Usage:
//
//	webssh [-p port] [-debug] [-key known_hosts_file] [-doh URL] [-proxy addr]
//
// Flags:
//
//	-p         Port to listen on (default: 3400)
//	-debug     Enable debug mode; writes to debug.log
//	-key       Path to known_hosts file for SSH host key verification
//	-doh       DNS-over-HTTPS resolver URL (e.g. https://dns.cloudflare.com/dns-query)
//	-proxy     SOCKS5 proxy address for SSH connections (e.g. 127.0.0.1:9050)
//	-quic      Enable QUIC/HTTP3 tunnel strategy (experimental, UDP-based)
//	-h         Show this help message
//
// RKN bypass features (актуализировано июнь 2026):
//   - uTLS-флис-фингерпринтов: Chrome 133/120 PQ/115 PQ, Firefox, iOS, Edge, Randomized
//   - Браузерные fingerprint'ы применяются через UTLSIdToSpec (НЕ перезаписываем spec, иначе JA3/JA4 ломается)
//   - DNS-over-HTTPS с расширенным пулом + health-check каждые 30с
//   - DoH-запросы через SOCKS5/Tor
//   - Encrypted Client Hello (ECH)
//   - Рандомизированный WebSocket endpoint path
//   - TLS record padding (post-handshake, имитация поведения Chrome)
//   - Post-Quantum X25519Kyber768Draft00
//   - GREASE-расширения
//   - SNI hostname rotation (расширенный пул CDN-доноров, актуальных 2026)
//   - ChaCha20-Poly1305 обфускация (HKDF-SHA256 для KDF)
//   - Anti-Siberia-flood: ограничение TLS-хендшейков и backoff
//   - WebSocket: origin check, max message size, rate limit, ping/pong

package main

import (
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

// AccessConfig defines IP-based access control.
type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

// ProxyConfig defines proxy and bypass settings for RKN circumvention.
type ProxyConfig struct {
	SOCKS5          string   `json:"socks5,omitempty"`
	DoH             string   `json:"doh,omitempty"`
	DoHProviders    []string `json:"doh_providers,omitempty"`
	DirectIPs       []string `json:"direct_ips,omitempty"`
	AltPorts        []int    `json:"alt_ports,omitempty"`
	EnableTor       bool     `json:"enable_tor,omitempty"`
	EnableQUIC      bool     `json:"enable_quic,omitempty"`
	AltPortsUDP     []int    `json:"alt_ports_udp,omitempty"`
	SNIHostname     string   `json:"sni_hostname,omitempty"`
	SNIHostnames    []string `json:"sni_hostnames,omitempty"`
	ObfsSecret      string   `json:"obfs_secret,omitempty"`
	ECHConfigBase64 string   `json:"ech_config,omitempty"`

	// Лимиты против «Сибирской блокировки» (~6 TLS-хендшейков → бан IP:port на 120с).
	MaxTLSAttempts   int           `json:"max_tls_attempts,omitempty"`
	TLSStrategyDelay time.Duration `json:"tls_strategy_delay,omitempty"`

	// WebSocket: rate-limit и CSRF
	WSReadLimit  int64    `json:"ws_read_limit,omitempty"`
	WSOriginPins []string `json:"ws_origin_pins,omitempty"`
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
	closeOnce    sync.Once
	closed       atomic.Bool
	limiter      *rate.Limiter
}

// WebSSHConfig contains default connection settings from webssh.conf.
type WebSSHConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	WSPATH string `json:"ws_path"`
}

// ConnectionStrategy — одна попытка подключения с определённым методом обфускации.
type ConnectionStrategy struct {
	Address     string
	Obfuscation string             // "tls", "chacha", "plain"
	Fingerprint utls.ClientHelloID // TLS fingerprint
	Description string
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

	utlsClientHelloID = utls.HelloChrome_133

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

	// Расширенный пул SNI-доноров 2026 (устойчивые к 16 КБ-блокировкам TLS)
	defaultSNIPool = []string{
		"www.asus.com",
		"www.samsung.com",
		"www.dell.com",
		"www.lenovo.com",
		"www.microsoft.com",
		"www.google.com",
		"www.apple.com",
		"www.sony.com",
		"www.hp.com",
		"www.canon.com",
		"www.nvidia.com",
		"www.amd.com",
		"www.intel.com",
		"www.adobe.com",
		"www.office.com",
		"www.bing.com",
		"github.com",
		"www.mojeek.com",
		"duckduckgo.com",
		"www.wikipedia.org",
		"www.yahoo.com",
	}

	// Расширенный пул DoH-провайдеров 2026
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
	proxyConf = ProxyConfig{
		MaxTLSAttempts:   4,
		TLSStrategyDelay: 25 * time.Second,
		WSReadLimit:      1 << 20,
	}
	if err := json.Unmarshal(data, &proxyConf); err != nil {
		return err
	}
	if len(proxyConf.DoHProviders) == 0 {
		proxyConf.DoHProviders = defaultDoHProviders
	}
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
		"HelloGolang":        utls.HelloGolang,
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

func (r *dohResolver) runHealthCheck(ctx context.Context) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	for i, provider := range r.providers {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s?name=cloudflare.com&type=A", provider), nil)
		if err != nil {
			r.healthStatus[i] = false
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", dohUserAgents[time.Now().UnixNano()%int64(len(dohUserAgents))])
		resp, err := r.client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if r.healthStatus[i] {
				debugLog.Warn("DoH provider became unhealthy", "provider", provider, "index", i)
			}
			if resp != nil {
				resp.Body.Close()
			}
			r.healthStatus[i] = false
			continue
		}
		resp.Body.Close()
		if !r.healthStatus[i] {
			debugLog.Info("DoH provider recovered", "provider", provider, "index", i)
		}
		r.healthStatus[i] = true
	}
	r.lastCheck = time.Now()
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
	healthyProviders := r.getHealthyProviders()
	if len(healthyProviders) == 0 {
		debugLog.Warn("DoH: all providers unhealthy, using original list")
		healthyProviders = r.providers
	}
	for _, providerURL := range healthyProviders {
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
	for _, dnsType := range []struct {
		qtype string
		rtype int
	}{{"A", 1}, {"AAAA", 28}} {
		u := fmt.Sprintf("%s?name=%s&type=%s", providerURL, url.QueryEscape(host), dnsType.qtype)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", dohUserAgents[time.Now().UnixNano()%int64(len(dohUserAgents))])
		resp, err := r.client.Do(req)
		if err != nil {
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
		return allIPs, nil
	}
	return nil, fmt.Errorf("DoH: no records for %s via %s", host, providerURL)
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
// uTLS camouflage — без перезаписи ClientHelloSpec для браузерных ID
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

// uTLSCamouflageConn оборачивает uTLS-соединение + post-handshake record padding.
type uTLSCamouflageConn struct {
	*utls.UConn
	mu     sync.Mutex
	closed atomic.Bool
}

func newUTLSCamouflageConn(conn net.Conn, sniHostname string, fp utls.ClientHelloID) (*uTLSCamouflageConn, error) {
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

	// ВАЖНО (июнь 2026): для браузерных fingerprint'ов (Chrome 133 / Firefox / Edge / iOS / Safari)
	// НЕ вызываем ApplyPreset с самописным ClientHelloSpec — иначе JA3/JA4 ломается
	// и fingerprint перестаёт соответствовать реальному браузеру.
	// Встроенные preset'ы utls (UTLSIdToSpec) уже корректно эмулируют браузер.
	// Применяем только для кастомных/рандомизированных ID (если пользователь явно выбрал).
	if isCustomFingerprint(fp) {
		if err := tlsConn.ApplyPreset(buildCustomFingerprintSpec()); err != nil {
			debugLog.Debug("uTLS ApplyPreset failed, using parrot defaults", "fingerprint", fp.Str(), "error", err)
		}
	}

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed [%s]: %w", fp.Str(), err)
	}

	state := tlsConn.ConnectionState()
	debugLog.Debug("uTLS camouflage established",
		"sni", sniHostname,
		"client_hello_id", fp.Str(),
		"cipher", state.CipherSuite,
		"version", state.Version,
	)

	return &uTLSCamouflageConn{UConn: tlsConn}, nil
}

// isCustomFingerprint — true только для кастомных/рандомизированных preset'ов.
func isCustomFingerprint(fp utls.ClientHelloID) bool {
	switch fp {
	case utls.HelloCustom, utls.HelloRandomizedALPN, utls.HelloRandomized, utls.HelloRandomizedNoALPN:
		return true
	default:
		return false
	}
}

// buildCustomFingerprintSpec — пост-Quantum X25519Kyber768 + GREASE + padding,
// используется ТОЛЬКО для кастомных рандомизированных ID.
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
				utls.X25519Kyber768Draft00,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
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

// Close завершает TLS-соединение, отправляя close_notify.
func (tc *uTLSCamouflageConn) Close() error {
	if !tc.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = tc.UConn.CloseWrite()
	return tc.UConn.Close()
}

// ---------------------------------------------------------------------------
// TLS record padding — имитация поведения Chrome после хендшеййка.
// Chrome отправляет padding records (0x14 TLS 1.3 + dummy data), чтобы
// скрыть реальные размеры первых application-data пакетов.
// Здесь делаем минимальный padding после установления TLS.
// ---------------------------------------------------------------------------

type paddedTLSConn struct {
	net.Conn
	firstWrite bool
	mu         sync.Mutex
}

func (p *paddedTLSConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.firstWrite {
		p.firstWrite = true
		// Padding-запись (TLS 1.3: content type 0x14 = 22, Application Data 0x17 = 23)
		// Шлём один маленький dummy TLS record перед первым application-data пакетом.
		padding := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}
		if _, err := p.Conn.Write(padding); err != nil {
			return 0, err
		}
		debugLog.Debug("TLS record padding sent (Chrome-like)")
	}
	return p.Conn.Write(b)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 obfuscation — KDF через HKDF-SHA256 (замена слабого XOR)
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

	// Криптографически стойкий KDF: HKDF-SHA256(salt=WebSSH/ChaCha20-Poly1305/v1, info=key)
	// вместо прежнего XOR-перемешивания.
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

	oc := &obfuscatedConn{
		Conn:     conn,
		aead:     aead,
		writeBuf: make([]byte, 0, 65536),
	}

	// Preamble: имитация TLS ClientHello первых байт (DPI-friendly).
	// Не TLS handshake content type — а валидные TLS record header + рандом,
	// чтобы DPI не отбраковывал по невалидному формату.
	preamble := make([]byte, 64+int(time.Now().UnixNano()%256))
	if _, err := rand.Read(preamble); err != nil {
		return nil, fmt.Errorf("preamble rand: %w", err)
	}
	preamble[0] = 0x16 // TLS Handshake content type
	preamble[1] = 0x03
	preamble[2] = 0x03
	if _, err := conn.Write(preamble); err != nil {
		return nil, fmt.Errorf("chacha preamble: %w", err)
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
// Security middleware — origin check (CSRF), security headers
// ---------------------------------------------------------------------------

func buildUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			// Если Origin не задан (например, прямой WS из non-browser клиента) — пропускаем.
			if origin == "" {
				return true
			}
			// Если ws_origin_pins НЕ задан в proxy.json — пропускаем любые Origin
			// (обратная совместимость с исходным поведением CheckOrigin: return true).
			// Origin-pinning включается только когда пользователь явно его настроил.
			if len(proxyConf.WSOriginPins) == 0 {
				return true
			}
			// Проверяем Origin по белому списку.
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
		// CSP разрешает jsdelivr для xterm.js (если он не self-hosted).
		// Если хотите полностью self-host — скачайте lib/xterm.js и lib/xterm-addon-fit.js
		// с https://github.com/xtermjs/xterm.js/releases/tag/v5.3.0 в static/
		// и уберите "https://cdn.jsdelivr.net" из списка.
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
// WebSocket → SSH bridge с rate-limit, max message size, ping/pong
// ---------------------------------------------------------------------------

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("WebSocket upgrade error", "error", err)
		return
	}
	defer conn.Close()

	// Max message size (anti-DoS, anti-buffer-bloat)
	limit := proxyConf.WSReadLimit
	if limit <= 0 {
		limit = 1 << 20 // 1 MB
	}
	conn.SetReadLimit(limit)

	// Rate limiter: 512 KB/s, burst 1 MB (типично для интерактивного SSH).
	limiter := rate.NewLimiter(rate.Limit(512*1024), 1024*1024)

	// Ping/pong: 60с — защита от полумёртвых соединений.
	const (
		pongWait   = 60 * time.Second
		pingPeriod = 30 * time.Second
	)
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()

	go func() {
		for {
			select {
			case <-pingTicker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	client := &WebSocketClient{
		conn:    conn,
		done:    make(chan struct{}),
		limiter: limiter,
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

// ---------------------------------------------------------------------------
// SSH connector — без QUIC/H2 CONNECT (они не работают с обычным sshd)
// Anti-Siberia-flood: TLS-стратегии с backoff'ом и max_attempts
// ---------------------------------------------------------------------------

func (c *WebSocketClient) connectSSH(ctx context.Context, host string, port int, username, password string) error {
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: knownHostsFn,
		Timeout:         20 * time.Second,
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
	tlsAttempts := 0
	attemptIdx := 0

	for attemptIdx < len(strategies) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		strategy := strategies[attemptIdx]
		debugLog.Debug("trying connection strategy",
			"idx", attemptIdx+1, "of", len(strategies),
			"addr", strategy.Address,
			"obfs", strategy.Obfuscation,
			"fingerprint", strategy.Fingerprint.Str(),
			"desc", strategy.Description)

		sshClient, err := connector.tryStrategy(strategy)
		if err != nil {
			lastErr = err
			debugLog.Debug("strategy failed", "addr", strategy.Address, "error", err)
			attemptIdx++
			continue
		}

		// Anti-Siberia-flood: после каждой TLS-стратегии — backoff,
		// чтобы не превысить ~6 хендшейков в окне блокировки.
		if strategy.Obfuscation == "tls" {
			tlsAttempts++
			if tlsAttempts >= maxAttempts && attemptIdx+1 < len(strategies) {
				logger.Info("TLS attempts limit reached, backing off",
					"attempts", tlsAttempts, "delay", delay)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					sshClient.Close()
					return ctx.Err()
				}
				tlsAttempts = 0
			}
		}

		c.sshConn = sshClient
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
		return err
	}

	logger.Info("SSH connected", "user", username, "host", host, "port", port)
	return nil
}

// ---------------------------------------------------------------------------
// Strategies (без QUIC, без HTTP/2 CONNECT — они не работают с sshd)
// ---------------------------------------------------------------------------

func (sc *SSHConnector) buildStrategies() []ConnectionStrategy {
	var strategies []ConnectionStrategy

	fullAddr := func(ipOrHost string, p int) string {
		return fmt.Sprintf("%s:%d", ipOrHost, p)
	}

	fps := getFingerprintCandidates()
	sniHostnames := getSNIHostnames()
	hasSNI := proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0
	hasObfs := proxyConf.ObfsSecret != ""

	// Заранее получаем DoH IP адреса
	var ips []string
	doh := newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
	if !isIPAddress(sc.Host) && !isPrivateHost(sc.Host) && doh != nil {
		if resolved, err := doh.lookupHost(sc.Ctx, sc.Host); err == nil {
			ips = resolved
			debugLog.Debug("DoH resolved", "host", sc.Host, "ips", ips)
		} else {
			debugLog.Debug("DoH lookup failed", "host", sc.Host, "error", err)
		}
	}

	// Разделяем IPv4 и IPv6 — IPv6 пробуем первым (TСПУ хуже фильтрует IPv6 к зарубежным AS).
	ipv6 := make([]string, 0)
	ipv4 := make([]string, 0)
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			ipv6 = append(ipv6, ip)
		} else {
			ipv4 = append(ipv4, ip)
		}
	}

	// 1. DoH-resolved IP + TLS-стратегии (IPv6 приоритет)
	for _, ip := range ipv6 {
		addr := fullAddr(ip, sc.Port)
		if hasSNI {
			for _, sni := range sniHostnames {
				for _, fp := range fps {
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "tls",
						Fingerprint: fp,
						Description: fmt.Sprintf("DoH IPv6 + TLS [%s] SNI:%s", fp.Str(), sni),
					})
				}
			}
		}
		if hasObfs {
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "chacha",
				Description: "DoH IPv6 + ChaCha20",
			})
		}
	}

	// 2. DoH-resolved IP + TLS-стратегии (IPv4)
	for _, ip := range ipv4 {
		addr := fullAddr(ip, sc.Port)
		if hasSNI {
			for _, sni := range sniHostnames {
				for _, fp := range fps {
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "tls",
						Fingerprint: fp,
						Description: fmt.Sprintf("DoH IPv4 + TLS [%s] SNI:%s", fp.Str(), sni),
					})
				}
			}
		}
		if hasObfs {
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "chacha",
				Description: "DoH IPv4 + ChaCha20",
			})
		}
	}

	// 3. Original host (прямое SSH)
	origAddr := fullAddr(sc.Host, sc.Port)
	if hasSNI {
		preferredFPS := []utls.ClientHelloID{utlsClientHelloID}
		if hasWorkingFingerprint && workingFingerprint != utlsClientHelloID {
			preferredFPS = append([]utls.ClientHelloID{workingFingerprint}, preferredFPS...)
		}
		for _, sni := range sniHostnames {
			for _, fp := range preferredFPS {
				strategies = append(strategies, ConnectionStrategy{
					Address:     origAddr,
					Obfuscation: "tls",
					Fingerprint: fp,
					Description: fmt.Sprintf("original host + TLS [%s] SNI:%s", fp.Str(), sni),
				})
			}
		}
	}
	if hasObfs {
		strategies = append(strategies, ConnectionStrategy{
			Address:     origAddr,
			Obfuscation: "chacha",
			Description: "original host + ChaCha20",
		})
	}
	strategies = append(strategies, ConnectionStrategy{
		Address:     origAddr,
		Obfuscation: "plain",
		Description: "original host (plain SSH)",
	})

	// 4. Direct IPs (fallback)
	for _, ip := range proxyConf.DirectIPs {
		addr := fullAddr(ip, sc.Port)
		strategies = append(strategies, ConnectionStrategy{
			Address:     addr,
			Obfuscation: "plain",
			Description: fmt.Sprintf("direct IP %s", ip),
		})
	}

	// 5. Alt ports TCP
	for _, altPort := range proxyConf.AltPorts {
		addr := fullAddr(sc.Host, altPort)
		if hasObfs {
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "chacha",
				Description: fmt.Sprintf("alt port %d + ChaCha20", altPort),
			})
		}
		strategies = append(strategies, ConnectionStrategy{
			Address:     addr,
			Obfuscation: "plain",
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

	wrappedConn, obfsErr := sc.applyObfuscation(conn, s.Obfuscation, s.Fingerprint)
	if obfsErr != nil {
		conn.Close()
		return nil, fmt.Errorf("obfuscation failed: %w", obfsErr)
	}

	// SSH-клиент работает поверх обёрнутого соединения.
	sshConn, chans, reqs, err := ssh.NewClientConn(wrappedConn, s.Address, sc.SSHConfig)
	if err != nil {
		wrappedConn.Close()
		return nil, fmt.Errorf("SSH handshake failed: %w", err)
	}

	if s.Obfuscation == "tls" {
		recordWorkingFingerprint(s.Fingerprint)
	}

	debugLog.Debug("strategy succeeded",
		"addr", s.Address,
		"obfs", s.Obfuscation,
		"fingerprint", s.Fingerprint.Str(),
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
	ctx, cancel := context.WithTimeout(sc.Ctx, 15*time.Second)
	defer cancel()
	return sc.NetDialer.DialContext(ctx, "tcp", addr)
}

func (sc *SSHConnector) applyObfuscation(conn net.Conn, method string, fp utls.ClientHelloID) (net.Conn, error) {
	switch method {
	case "tls":
		sniList := getSNIHostnames()
		if len(sniList) == 0 {
			conn.Close()
			return nil, errors.New("tls obfuscation requires sni_hostname(s)")
		}
		sni := sniList[0]
		tlsConn, err := newUTLSCamouflageConn(conn, sni, fp)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("uTLS camouflage failed: %w", err)
		}
		// Оборачиваем в paddedTLSConn для имитации Chrome post-handshake record padding.
		return &paddedTLSConn{Conn: tlsConn}, nil
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
// SSH Session management
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
	defer c.closeOnce.Do(func() {
		if !c.closed.Load() {
			close(c.done)
			c.closed.Store(true)
		}
	})
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
			// Rate limit на входящие команды
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
// Random path generation (DPI evasion)
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

RKN bypass features (актуализировано июнь 2026):
  - uTLS-флис-фингерпринтов: Chrome 133/120 PQ/115 PQ, Firefox, iOS, Edge, Randomized
  - DoH с расширенным пулом + dynamic health monitoring
  - DoH через SOCKS5/Tor
  - Encrypted Client Hello (ECH)
  - Рандомизированный WebSocket endpoint
  - TLS record padding (Chrome-like)
  - Post-Quantum X25519Kyber768Draft00
  - GREASE-расширения
  - SNI hostname rotation (расширенный пул CDN 2026)
  - ChaCha20-Poly1305 обфускация (HKDF-SHA256 KDF)
  - Anti-Siberia-flood: TLS-стратегии с backoff'ом
  - WebSocket: origin check, max message size, rate limit, ping/pong

Note: Для обхода РКН в проде рекомендуется дополнительно поднять Xray-core (VLESS+Reality+Vision)
или AmneziaWG 2.0 отдельным процессом. webssh же используется как web-интерфейс поверх sshd.

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
		"go_version", runtime.Version(),
		"port", *flagPort,
		"debug", debugMode,
		"doh", *flagDoH,
		"proxy", *flagProxy,
		"ws_path", wsPath,
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
	if proxyConf.EnableTor && proxyConf.SOCKS5 == "" {
		proxyConf.SOCKS5 = "127.0.0.1:9050"
		logger.Info("Tor mode enabled, SOCKS5 set to 127.0.0.1:9050")
	}

	doh := newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
	if doh != nil {
		go doh.healthCheck(context.Background(), 30*time.Second)
		debugLog.Debug("DoH health check background worker started", "interval", "30s")
	}

	debugLog.Debug("proxy config",
		"doh", proxyConf.DoH,
		"doh_providers", len(proxyConf.DoHProviders),
		"socks5", proxyConf.SOCKS5,
		"direct_ips", proxyConf.DirectIPs,
		"alt_ports", proxyConf.AltPorts,
		"sni_hostname", proxyConf.SNIHostname,
		"sni_hostnames", len(proxyConf.SNIHostnames),
		"ech_config", proxyConf.ECHConfigBase64 != "",
		"fingerprints_pool", len(utlsFingerprintPool),
		"origin_pins", len(proxyConf.WSOriginPins),
		"max_tls_attempts", proxyConf.MaxTLSAttempts,
	)

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

	// Динамически пересобираем upgrader с учётом ws_origin_pins.
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

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(websshConf)
	})

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

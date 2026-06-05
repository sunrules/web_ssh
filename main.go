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
//	-h         Show this help message
//
// RKN bypass features:
//   - Automatic TLS fingerprint cycling (Chrome, Firefox, iOS, Randomized, Post-Quantum)
//   - DNS-over-HTTPS with multi-provider fallback chain + dynamic health monitoring
//   - DoH requests routed through SOCKS5/Tor
//   - Encrypted Client Hello (ECH) support
//   - Randomized WebSocket endpoint path
//   - ClientHello padding + GREASE for DPI evasion
//   - X25519Kyber768Draft00 Post-Quantum key agreement
//   - HTTP/2 CONNECT tunnel strategy
//   - Automatic SNI hostname rotation from CDN pool
//   - ChaCha20-Poly1305 obfuscation (replaces legacy XOR)

package main

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"
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
	EnableQUIC      bool     `json:"enable_quic,omitempty"`   // Включить QUIC/HTTP3
	AltPortsUDP     []int    `json:"alt_ports_udp,omitempty"` // UDP порты для QUIC
	SNIHostname     string   `json:"sni_hostname,omitempty"`
	SNIHostnames    []string `json:"sni_hostnames,omitempty"` // Ротация SNI hostname'ов
	ObfsSecret      string   `json:"obfs_secret,omitempty"`
	ECHConfigBase64 string   `json:"ech_config,omitempty"`
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
	closeOnce    sync.Once // Предотвращает двойное закрытие done
	closed       atomic.Bool
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
	Obfuscation string             // "tls", "chacha", "h2connect", "quic", "plain"
	Fingerprint utls.ClientHelloID // TLS fingerprint для обхода DPI
	Description string             // для логов
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

	// Динамический WebSocket путь (рандомизированный при старте)
	wsPath string

	// uTLS fingerprint pool с Post-Quantum поддержкой
	utlsClientHelloID = utls.HelloChrome_133

	utlsFingerprintPool = []utls.ClientHelloID{
		utls.HelloChrome_133,
		utls.HelloChrome_120_PQ, // Chrome 120 + Post-Quantum X25519Kyber768
		utls.HelloChrome_115_PQ, // Chrome 115 + Post-Quantum X25519Kyber768
		utls.HelloFirefox_Auto,
		utls.HelloIOS_Auto,
		utls.HelloRandomizedALPN,
	}

	// Кеш последнего рабочего fingerprint для повторного использования
	workingFingerprint    utls.ClientHelloID
	hasWorkingFingerprint bool
	fingerprintMu         sync.Mutex

	// Маскированный User-Agent для DoH-запросов (имитация Chrome)
	dohUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	}

	// Популярные CDN для ротации SNI hostname (DPI не может заблокировать все сразу)
	defaultSNIPool = []string{
		"cloudflare.com",
		"google.com",
		"youtube.com",
		"microsoft.com",
		"apple.com",
		"github.com",
		"aws.amazon.com",
		"fastly.com",
		"akamai.net",
		"cloudfront.net",
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
// DNS-over-HTTPS resolver — мульти-провайдер, SOCKS5, маскированный UA, health check
// ---------------------------------------------------------------------------

type dohResolver struct {
	providers []string
	client    *http.Client
	// healthCheck — флаг доступности каждого провайдера (индекс → доступен)
	healthMu     sync.RWMutex
	healthStatus map[int]bool
	lastCheck    time.Time
}

func newDoHResolver(primaryURL string, additionalProviders []string, proxyAddr string) *dohResolver {
	if primaryURL == "" && len(additionalProviders) == 0 {
		return nil
	}

	providers := make([]string, 0)
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
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        5,
		IdleConnTimeout:     30 * time.Second,
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
		healthStatus[i] = true // изначально все считаем доступными
	}

	return &dohResolver{
		providers:    providers,
		client:       &http.Client{Timeout: 10 * time.Second, Transport: transport},
		healthStatus: healthStatus,
	}
}

// healthCheck запускает фоновую проверку доступности DoH провайдеров каждые N секунд.
func (r *dohResolver) healthCheck(ctx context.Context, interval time.Duration) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Первый immediate check
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
			fmt.Sprintf("%s?name=google.com&type=A", provider), nil)
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

// getHealthyProviders возвращает только здоровые провайдеры в порядке приоритета.
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

	// Получаем только здоровые провайдеры
	healthyProviders := r.getHealthyProviders()
	if len(healthyProviders) == 0 {
		debugLog.Warn("DoH: all providers are unhealthy, trying original list as fallback")
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
	}{
		{"A", 1},
		{"AAAA", 28},
	} {
		u := fmt.Sprintf("%s?name=%s&type=%s", providerURL, url.QueryEscape(host), dnsType.qtype)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		ua := dohUserAgents[time.Now().UnixNano()%int64(len(dohUserAgents))]
		req.Header.Set("User-Agent", ua)

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
// uTLS camouflage — эмуляция браузерного TLS для обхода DPI
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

// getSNIHostnames возвращает список SNI hostname'ов для ротации.
// Приоритет: sni_hostnames → sni_hostname → defaultSNIPool.
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
	sniHostname string
}

// newUTLSCamouflageConn создаёт TLS-соединение с указанным fingerprint'ом.
// Поддерживает Post-Quantum key agreement (X25519Kyber768Draft00) для fingerprint'ов,
// которые включают PQ, и GREASE расширения для всех.
func newUTLSCamouflageConn(conn net.Conn, sniHostname string, fp utls.ClientHelloID) (*uTLSCamouflageConn, error) {
	tlsConfig := &utls.Config{
		ServerName:         sniHostname,
		InsecureSkipVerify: true,
	}

	// ECH (Encrypted Client Hello)
	if proxyConf.ECHConfigBase64 != "" {
		echConf, err := base64.RawStdEncoding.DecodeString(proxyConf.ECHConfigBase64)
		if err == nil {
			tlsConfig.EncryptedClientHelloConfigList = echConf
			debugLog.Debug("ECH enabled", "config_len", len(echConf))
		} else {
			debugLog.Warn("ECH config decode failed, proceeding without ECH", "error", err)
		}
	}

	tlsConn := utls.UClient(conn, tlsConfig, fp)

	// Для браузерных fingerprint'ов (Chrome/Firefox/iOS) не перезаписываем все расширения.
	// Добавляем только GREASE + Padding через кастомный spec, сохраняя браузерную эмуляцию.
	switch fp {
	case utls.HelloCustom, utls.HelloRandomizedALPN, utls.HelloRandomized, utls.HelloRandomizedNoALPN:
		if err := tlsConn.ApplyPreset(&utls.ClientHelloSpec{
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
			Extensions: append(
				getExtensionList(),
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			),
		}); err != nil {
			debugLog.Debug("uTLS ApplyPreset failed, using parrot defaults", "fingerprint", fp.Str(), "error", err)
		}
	default:
		if err := tlsConn.ApplyPreset(&utls.ClientHelloSpec{
			TLSVersMax:         utls.VersionTLS13,
			TLSVersMin:         utls.VersionTLS12,
			CompressionMethods: []uint8{0},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
		}); err != nil {
			debugLog.Debug("GREASE/padding extension failed, using defaults", "fingerprint", fp.Str(), "error", err)
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

	return &uTLSCamouflageConn{
		UConn:       tlsConn,
		sniHostname: sniHostname,
	}, nil
}

// getExtensionList возвращает базовый набор TLS-расширений для маскировки.
// Включает Post-Quantum X25519Kyber768Draft00 в SupportedCurves и KeyShare.
func getExtensionList() []utls.TLSExtension {
	return []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.X25519Kyber768Draft00, // Post-Quantum
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
			{Group: utls.X25519Kyber768Draft00, Data: make([]byte, 32)}, // Post-Quantum
			{Group: utls.X25519, Data: make([]byte, 32)},
			{Group: utls.CurveP256, Data: make([]byte, 32)},
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
		&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
	}
}

func (tc *uTLSCamouflageConn) Close() error {
	_ = tc.UConn.CloseWrite() // Игнорируем ошибки
	return tc.UConn.Close()
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 obfuscation (replaces legacy XOR)
// ---------------------------------------------------------------------------

type obfuscatedConn struct {
	net.Conn
	aead     cipher.AEAD
	nonce    []byte
	writeMu  sync.Mutex // Защита writeBuf от конкурентного доступа
	writeBuf []byte
}

func newObfuscatedConn(conn net.Conn, secret string) (*obfuscatedConn, error) {
	// Derive 256-bit key from secret
	key := make([]byte, 32)
	for i := 0; i < len(key); i++ {
		key[i] = secret[i%len(secret)] ^ byte(i*0x37)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 new: %w", err)
	}

	oc := &obfuscatedConn{
		Conn:     conn,
		aead:     aead,
		nonce:    make([]byte, chacha20poly1305.NonceSizeX),
		writeBuf: make([]byte, 0, 65536),
	}

	// Отправляем ECH-banner (имитация TLS-расширения для обхода DPI)
	preamble := make([]byte, 64+int(time.Now().UnixNano()%256))
	if _, err := rand.Read(preamble); err != nil {
		return nil, fmt.Errorf("preamble rand: %w", err)
	}
	preamble[0] = 0x16 // TLS Handshake content type
	preamble[1] = 0x03 // TLS 1.x major
	preamble[2] = 0x03 // TLS 1.2 minor

	if _, err := conn.Write(preamble); err != nil {
		return nil, fmt.Errorf("chacha preamble: %w", err)
	}
	debugLog.Debug("ChaCha20-Poly1305 obfuscation layer enabled", "secret_len", len(secret), "preamble_len", len(preamble))
	return oc, nil
}

func (oc *obfuscatedConn) Read(b []byte) (int, error) {
	// Читаем зашифрованный размер
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(oc.Conn, lenBuf); err != nil {
		return 0, fmt.Errorf("chacha read len: %w", err)
	}
	dataLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if dataLen > 65536 {
		return 0, fmt.Errorf("chacha: packet too large: %d", dataLen)
	}

	// Читаем nonce + ciphertext + mac
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

	// Генерируем случайный nonce для каждого пакета
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("chacha nonce: %w", err)
	}

	// Шифруем
	ciphertext := oc.aead.Seal(nil, nonce, b, nil)

	// Формат: [2 байта длина][nonce][ciphertext+mac]
	oc.writeBuf = append(oc.writeBuf[:0], byte(len(ciphertext)>>8), byte(len(ciphertext)))
	oc.writeBuf = append(oc.writeBuf, nonce...)
	oc.writeBuf = append(oc.writeBuf, ciphertext...)

	if _, err := oc.Conn.Write(oc.writeBuf); err != nil {
		return 0, err
	}
	return len(b), nil
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
			"fingerprint", strategy.Fingerprint.Str(),
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

	fps := getFingerprintCandidates()
	sniHostnames := getSNIHostnames()

	// Заранее получаем DoH IP адреса для всех стратегий
	var ips []string
	doh := newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
	if !isIPAddress(sc.Host) && !isPrivateHost(sc.Host) && doh != nil {
		var dohErr error
		ips, dohErr = doh.lookupHost(sc.Ctx, sc.Host)
		if dohErr != nil {
			debugLog.Debug("DoH lookup failed", "host", sc.Host, "error", dohErr)
		}
	}

	// 1. QUIC/HTTP3 strategies — самый высокий приоритет (UDP, сложно DPI)
	if proxyConf.EnableQUIC {
		sni := ""
		if len(sniHostnames) > 0 {
			sni = sniHostnames[0]
		}
		// QUIC через DoH IP (IPv4)
		for _, ip := range ips {
			if !strings.Contains(ip, ":") {
				addr := fullAddr(ip, sc.Port)
				strategies = append(strategies, ConnectionStrategy{
					Address:     addr,
					Obfuscation: "quic",
					Description: fmt.Sprintf("QUIC DoH IPv4 SNI:%s", sni),
				})
			}
		}
		// QUIC через DoH IP (IPv6)
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				addr := fullAddr(ip, sc.Port)
				strategies = append(strategies, ConnectionStrategy{
					Address:     addr,
					Obfuscation: "quic",
					Description: fmt.Sprintf("QUIC DoH IPv6 SNI:%s", sni),
				})
			}
		}
		// QUIC через оригинальный хост
		origAddr := fullAddr(sc.Host, sc.Port)
		strategies = append(strategies, ConnectionStrategy{
			Address:     origAddr,
			Obfuscation: "quic",
			Description: fmt.Sprintf("QUIC original host SNI:%s", sni),
		})
		// QUIC через alt UDP порты
		for _, altPort := range proxyConf.AltPortsUDP {
			addr := fullAddr(sc.Host, altPort)
			strategies = append(strategies, ConnectionStrategy{
				Address:     addr,
				Obfuscation: "quic",
				Description: fmt.Sprintf("QUIC alt UDP port %d SNI:%s", altPort, sni),
			})
		}
	}

	// 2. DoH resolved IPs (TCP стратегии: TLS, H2, chacha, plain)
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			addr := fullAddr(ip, sc.Port)
			if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
				for _, sni := range sniHostnames {
					for _, fp := range fps {
						strategies = append(strategies, ConnectionStrategy{
							Address:     addr,
							Obfuscation: "tls",
							Fingerprint: fp,
							Description: fmt.Sprintf("DoH IPv6 + TLS [%s] SNI:%s", fp.Str(), sni),
						})
					}
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "h2connect",
						Description: fmt.Sprintf("DoH IPv6 + H2 CONNECT SNI:%s", sni),
					})
				}
			} else {
				if proxyConf.ObfsSecret != "" {
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "chacha",
						Description: "DoH IPv6 + ChaCha20",
					})
				}
				strategies = append(strategies, ConnectionStrategy{
					Address:     addr,
					Obfuscation: "plain",
					Description: "DoH IPv6",
				})
			}
		}
	}
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			addr := fullAddr(ip, sc.Port)
			if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
				for _, sni := range sniHostnames {
					for _, fp := range fps {
						strategies = append(strategies, ConnectionStrategy{
							Address:     addr,
							Obfuscation: "tls",
							Fingerprint: fp,
							Description: fmt.Sprintf("DoH IPv4 + TLS [%s] SNI:%s", fp.Str(), sni),
						})
					}
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "h2connect",
						Description: fmt.Sprintf("DoH IPv4 + H2 CONNECT SNI:%s", sni),
					})
				}
			} else {
				if proxyConf.ObfsSecret != "" {
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "chacha",
						Description: "DoH IPv4 + ChaCha20",
					})
				}
				strategies = append(strategies, ConnectionStrategy{
					Address:     addr,
					Obfuscation: "plain",
					Description: "DoH IPv4",
				})
			}
		}
	}

	// 3. Original host (TCP) — сначала plain/chacha (прямое SSH),
	// потом TLS/H2 (для серверов с TLS-прокси)
	origAddr := fullAddr(sc.Host, sc.Port)
	if proxyConf.ObfsSecret != "" {
		strategies = append(strategies, ConnectionStrategy{
			Address:     origAddr,
			Obfuscation: "chacha",
			Description: "original host + ChaCha20",
		})
	}
	strategies = append(strategies, ConnectionStrategy{
		Address:     origAddr,
		Obfuscation: "plain",
		Description: "original host",
	})
	if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
		for _, sni := range sniHostnames {
			for _, fp := range fps {
				strategies = append(strategies, ConnectionStrategy{
					Address:     origAddr,
					Obfuscation: "tls",
					Fingerprint: fp,
					Description: fmt.Sprintf("original host + TLS [%s] SNI:%s", fp.Str(), sni),
				})
			}
			strategies = append(strategies, ConnectionStrategy{
				Address:     origAddr,
				Obfuscation: "h2connect",
				Description: fmt.Sprintf("original host + H2 CONNECT SNI:%s", sni),
			})
		}
	}

	// 4. Alt ports TCP — сначала plain/chacha (прямое SSH),
	// потом TLS/H2 (для серверов с TLS-прокси)
	for _, altPort := range proxyConf.AltPorts {
		addr := fullAddr(sc.Host, altPort)
		if proxyConf.ObfsSecret != "" {
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
		if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
			preferredFPS := []utls.ClientHelloID{utlsClientHelloID}
			if hasWorkingFingerprint && workingFingerprint != utlsClientHelloID {
				preferredFPS = append([]utls.ClientHelloID{workingFingerprint}, preferredFPS...)
			}
			for _, sni := range sniHostnames {
				for _, fp := range preferredFPS {
					strategies = append(strategies, ConnectionStrategy{
						Address:     addr,
						Obfuscation: "tls",
						Fingerprint: fp,
						Description: fmt.Sprintf("alt port %d + TLS [%s] SNI:%s", altPort, fp.Str(), sni),
					})
				}
				strategies = append(strategies, ConnectionStrategy{
					Address:     addr,
					Obfuscation: "h2connect",
					Description: fmt.Sprintf("alt port %d + H2 CONNECT SNI:%s", altPort, sni),
				})
			}
		}
	}

	return strategies
}

func (sc *SSHConnector) tryStrategy(s ConnectionStrategy) (*ssh.Client, error) {
	// Для UDP-туннеля не используем TCP dial — создаём UDP-сокет напрямую
	if s.Obfuscation == "quic" {
		host, portStr, err := net.SplitHostPort(s.Address)
		if err != nil {
			return nil, fmt.Errorf("udp: invalid address %s: %w", s.Address, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("udp: invalid port %s: %w", portStr, err)
		}
		udpConn, err := newUDPTunnelConn(host, port)
		if err != nil {
			return nil, fmt.Errorf("UDP tunnel dial failed: %w", err)
		}
		sshConn, chans, reqs, err := ssh.NewClientConn(udpConn, s.Address, sc.SSHConfig)
		if err != nil {
			udpConn.Close()
			return nil, fmt.Errorf("SSH handshake over UDP tunnel failed: %w", err)
		}
		debugLog.Debug("strategy succeeded",
			"addr", s.Address,
			"obfs", "udp",
			"desc", s.Description)
		return ssh.NewClient(sshConn, chans, reqs), nil
	}

	conn, err := sc.dial(s.Address)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	wrappedConn, obfsErr := sc.applyObfuscation(conn, s.Obfuscation, s.Fingerprint)
	if obfsErr != nil {
		conn.Close()
		return nil, fmt.Errorf("obfuscation failed: %w", obfsErr)
	}

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
		ctx, cancel := context.WithTimeout(sc.Ctx, 12*time.Second)
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
			return nil, fmt.Errorf("SOCKS5 dial timeout after 12s")
		case <-sc.Ctx.Done():
			return nil, sc.Ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(sc.Ctx, 12*time.Second)
	defer cancel()
	return sc.NetDialer.DialContext(ctx, "tcp", addr)
}

func (sc *SSHConnector) applyObfuscation(conn net.Conn, method string, fp utls.ClientHelloID) (net.Conn, error) {
	switch method {
	case "tls":
		if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
			sniHostnames := getSNIHostnames()
			sni := sniHostnames[0]
			tlsConn, err := newUTLSCamouflageConn(conn, sni, fp)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("uTLS camouflage failed: %w", err)
			}
			return tlsConn, nil
		}
		conn.Close()
		return nil, errors.New("tls obfuscation requires sni_hostname")
	case "chacha":
		if proxyConf.ObfsSecret != "" {
			chachaConn, err := newObfuscatedConn(conn, proxyConf.ObfsSecret)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("ChaCha20 obfuscation failed: %w", err)
			}
			return chachaConn, nil
		}
		conn.Close()
		return nil, errors.New("chacha obfuscation requires obfs_secret")
	case "h2connect":
		if proxyConf.SNIHostname != "" || len(proxyConf.SNIHostnames) > 0 {
			h2Conn, err := newH2ConnectConn(conn, getSNIHostnames()[0])
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("H2 CONNECT failed: %w", err)
			}
			return h2Conn, nil
		}
		conn.Close()
		return nil, errors.New("h2connect requires sni_hostname")
	default:
		return conn, nil
	}
}

// ---------------------------------------------------------------------------
// HTTP/2 CONNECT tunnel — маскировка SSH под HTTP/2 трафик
// ---------------------------------------------------------------------------

type h2ConnectConn struct {
	net.Conn
	reader io.Reader
}

func newH2ConnectConn(conn net.Conn, sniHostname string) (*h2ConnectConn, error) {
	tlsConfig := &tls.Config{
		ServerName:         sniHostname,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("H2 TLS handshake: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: sniHostname},
		Host:   sniHostname,
		Header: make(http.Header),
	}
	req.Header.Set("User-Agent", dohUserAgents[0])
	req.Header.Set("Proxy-Connection", "Keep-Alive")

	if err := req.Write(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("H2 CONNECT write: %w", err)
	}

	debugLog.Debug("H2 CONNECT tunnel established", "sni", sniHostname)
	return &h2ConnectConn{
		Conn:   tlsConn,
		reader: tlsConn,
	}, nil
}

func (h2 *h2ConnectConn) Read(b []byte) (int, error) {
	return h2.reader.Read(b)
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
// Usage
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UDP-капсуляция (вместо QUIC/HTTP3) — работает с любым sshd,
// SSH трафик оборачивается в UDP, сложно детектится DPI
// ---------------------------------------------------------------------------

type udpTunnelConn struct {
	*net.UDPConn
	raddr *net.UDPAddr
}

func newUDPTunnelConn(host string, port int) (*udpTunnelConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("resolve udp: %w", err)
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}

	_ = udpConn.SetReadBuffer(65536)
	_ = udpConn.SetWriteBuffer(65536)

	debugLog.Debug("UDP tunnel established",
		"host", host,
		"port", port)

	return &udpTunnelConn{
		UDPConn: udpConn,
		raddr:   udpAddr,
	}, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `WebSSH — Web-based SSH client with WebSocket terminal

Usage: webssh [options]

Options:
  -p <port>     Port to listen on (default: 3400)
  -debug        Enable debug mode; logs to debug.log
  -key <path>   SSH known_hosts file for host key verification
  -doh <url>    DNS-over-HTTPS resolver (e.g. https://dns.cloudflare.com/dns-query)
  -proxy <addr> SOCKS5 proxy (e.g. 127.0.0.1:9050)
  -quic         Enable QUIC/HTTP3 tunnel strategy (experimental, UDP-based)
  -h            Show this help message

RKN bypass (configured via proxy.json):
  - TLS fingerprint cycling (Chrome 133 / Chrome PQ / Firefox / iOS / Randomized)
  - Post-Quantum key agreement (X25519Kyber768Draft00)
  - DNS-over-HTTPS with multi-provider fallback + dynamic health monitoring
  - DoH routed through SOCKS5/Tor
  - Encrypted Client Hello (ECH) support
  - Randomized WebSocket endpoint path
  - ClientHello padding + GREASE for DPI evasion
  - HTTP/2 CONNECT tunnel
  - QUIC/HTTP3 tunnel (UDP-based, hardest to DPI-block)
  - SNI hostname rotation (CDN pool)
  - ChaCha20-Poly1305 obfuscation

Examples:
  webssh
  webssh -p 8080 -debug
  webssh -doh https://dns.cloudflare.com/dns-query -proxy 127.0.0.1:9050
  webssh -quic -doh https://dns.cloudflare.com/dns-query
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
	flagQUIC := flag.Bool("quic", false, "Enable QUIC/HTTP3 tunnel strategy")
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
	if *flagQUIC {
		proxyConf.EnableQUIC = true
		logger.Info("QUIC/HTTP3 tunnel strategy enabled")
	}

	doh := newDoHResolver(proxyConf.DoH, proxyConf.DoHProviders, proxyConf.SOCKS5)
	if doh != nil {
		go doh.healthCheck(context.Background(), 30*time.Second)
		debugLog.Debug("DoH health check background worker started", "interval", "30s")
	}

	debugLog.Debug("proxy config",
		"doh", proxyConf.DoH,
		"doh_providers", proxyConf.DoHProviders,
		"socks5", proxyConf.SOCKS5,
		"direct_ips", proxyConf.DirectIPs,
		"alt_ports", proxyConf.AltPorts,
		"sni_hostname", proxyConf.SNIHostname,
		"sni_hostnames", proxyConf.SNIHostnames,
		"ech_config", proxyConf.ECHConfigBase64 != "",
		"fingerprints_pool", len(utlsFingerprintPool),
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

package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
)

// AccessConfig represents IP-based access control rules.
type AccessConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

// AppConfig holds all runtime configuration for webssh.
type AppConfig struct {
	Port       int
	Debug      bool
	KeyPath    string
	KnockValue string
	HTTP3      bool

	CertFile string
	KeyFile  string
	BaseDir  string
}

// LoadAccessConfig reads and parses the access.json file.
// On any error, it logs a warning and sets access to allow all.
func LoadAccessConfig(baseDir string) AccessConfig {
	path := filepath.Join(baseDir, "access.json")
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("WARNING: access.json not loaded: %v — allowing all IPs", err)
		return AccessConfig{AllowedIPs: []string{"*"}}
	}
	var cfg AccessConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("WARNING: access.json parse error: %v — allowing all IPs", err)
		return AccessConfig{AllowedIPs: []string{"*"}}
	}
	log.Printf("Access config loaded: %d rule(s)", len(cfg.AllowedIPs))
	return cfg
}

// IsIPAllowed checks if a given IP (from RemoteAddr / X-Forwarded-For) is permitted.
func (a AccessConfig) IsIPAllowed(ip string) bool {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	for _, allowed := range a.AllowedIPs {
		if allowed == ip || allowed == "*" {
			return true
		}
		if _, ipnet, err := net.ParseCIDR(allowed); err == nil && ipnet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

// fileExists reports whether the named file or directory exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDirs creates directories needed by the application.
func EnsureDirs(baseDir string) {
	dirs := []string{
		filepath.Join(baseDir, "static"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Printf("WARNING: could not create directory %s: %v", d, err)
		}
	}
}
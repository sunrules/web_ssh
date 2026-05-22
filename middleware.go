package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// knockMiddleware проверяет "секретный" заголовок X-Knock перед доступом к /ws.
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

// masqueradeMiddleware отдаёт "безобидный" контент не-браузерам на чувствительных путях.
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

// securityMiddleware логирует подозрительные User-Agent на WS-пути.
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

// ipMiddleware проверяет IP адрес клиента по правилам access.json.
func ipMiddleware(accessConfig AccessConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			ip = strings.TrimSpace(ips[0])
		}
		if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
			ip = xRealIP
		}
		if !accessConfig.IsIPAllowed(ip) {
			log.Printf("Access denied for IP: %s", ip)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}
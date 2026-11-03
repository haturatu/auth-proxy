package logging

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
)

var (
	AppLog         *slog.Logger
	SecurityLog    *slog.Logger
	trustedProxies []netip.Prefix
	proxyMu        sync.RWMutex
)

func InitLoggers() {
	level := slog.LevelInfo
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}
	AppLog = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	SecurityLog = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// ConfigureTrustedProxies accepts only the addresses of immediate, controlled reverse proxies.
// An empty value (the default) never trusts X-Forwarded-* from a direct VLAN client.
func ConfigureTrustedProxies(raw string) error {
	prefixes := []netip.Prefix{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			ip, ipErr := netip.ParseAddr(entry)
			if ipErr != nil {
				return fmt.Errorf("invalid proxy address %q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		prefix = prefix.Masked()
		// Trusting every remote address defeats the security boundary.
		if prefix.Bits() == 0 {
			return fmt.Errorf("wildcard TRUSTED_PROXY_CIDRS %q is unsafe; specify immediate proxies only", entry)
		}
		prefixes = append(prefixes, prefix)
	}
	proxyMu.Lock()
	trustedProxies = prefixes
	proxyMu.Unlock()
	return nil
}

func isTrusted(ip netip.Addr) bool {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	for _, prefix := range trustedProxies {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func peerIP(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return ip.Unmap(), err == nil
}

// GetClientIP walks a trusted forwarding chain from right to left.
// Direct clients cannot spoof the address by sending X-Forwarded-For.
func GetClientIP(r *http.Request) string {
	peer, ok := peerIP(r)
	if !ok {
		return r.RemoteAddr
	}
	if !isTrusted(peer) {
		return peer.String()
	}
	// Limit both bytes and hops before parsing to keep attacker-supplied
	// forwarding chains bounded even when the immediate proxy is trusted.
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer.String()
	}
	joined := strings.Join(values, ",")
	if len(joined) > 4096 {
		return peer.String()
	}
	chain := strings.Split(joined, ",")
	if len(chain) > 32 {
		return peer.String()
	}
	current := peer
	for i := len(chain) - 1; i >= 0 && isTrusted(current); i-- {
		next, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return peer.String()
		}
		current = next.Unmap()
	}
	// If every hop in the chain claims to be trusted, there is no
	// verifiable untrusted source. Use the observed peer instead.
	if isTrusted(current) {
		return peer.String()
	}
	return current.String()
}

// GetClientScheme trusts X-Forwarded-Proto only from configured proxies.
func GetClientScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if peer, ok := peerIP(r); ok && isTrusted(peer) &&
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}

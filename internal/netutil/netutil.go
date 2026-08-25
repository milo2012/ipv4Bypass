// Package netutil provides small networking helpers shared across packages:
// CIDR enumeration, MAC normalisation, EUI-64 mapping and a token-bucket
// rate limiter used to throttle scanning.
package netutil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NormalizeMAC canonicalises any common MAC representation to lowercase
// colon-separated hex (aa:bb:cc:dd:ee:ff). Accepts colon, dash, dot (Cisco)
// and bare-hex forms and tolerates unpadded octets ("0:de:ad:be:ef:0").
func NormalizeMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return ""
	}
	allHex := func(s string) bool {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	join := func(hex12 string) string {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(hex12[i : i+2])
		}
		return b.String()
	}

	switch {
	case strings.Contains(mac, ":"), strings.Contains(mac, "-"):
		sep := byte(':')
		if !strings.Contains(mac, ":") {
			sep = '-'
		}
		parts := strings.Split(mac, string(sep))
		if len(parts) != 6 {
			return ""
		}
		hex := make([]byte, 0, 17)
		for i, p := range parts {
			p = strings.TrimSpace(p)
			for len(p) > 0 && len(p) < 2 {
				p = "0" + p
			}
			if len(p) != 2 || !allHex(p) {
				return ""
			}
			if i > 0 {
				hex = append(hex, ':')
			}
			hex = append(hex, p...)
		}
		return string(hex)

	default: // dotted quad (Cisco) or bare 12-nibble form
		compact := strings.ReplaceAll(mac, ".", "")
		if len(compact) == 12 && allHex(compact) {
			return join(compact)
		}
		return ""
	}
}

// ValidMAC reports whether s parses as a hardware address.
func ValidMAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

// MACToEUI64 derives the RFC 4291 link-local address (fe80::/10) that a host
// with the given MAC would use when EUI-64 autoconfiguration applies.
// Privacy extensions (RFC 4941) mean this is only ever a *candidate*.
func MACToEUI64(mac string) (string, error) {
	norm := NormalizeMAC(mac)
	if norm == "" {
		return "", fmt.Errorf("invalid mac %q", mac)
	}
	hw, err := net.ParseMAC(norm)
	if err != nil {
		return "", err
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("unsupported mac length %d", len(hw))
	}
	b := make([]byte, 8)
	b[0] = hw[0] ^ 0x02 // flip universal/local bit
	copy(b[1:3], hw[1:3])
	b[3] = 0xff
	b[4] = 0xfe
	copy(b[5:8], hw[3:6])
	ip := make([]byte, 16)
	ip[0], ip[1] = 0xfe, 0x80
	copy(ip[8:], b)
	v6 := net.IP(ip).String()
	if v6 == "" {
		return "", fmt.Errorf("eui64 conversion failed for %s", norm)
	}
	return v6, nil
}

// IPv6ToMAC performs the inverse of MACToEUI64. It only succeeds when the
// address is genuinely EUI-64 derived (contains ff:fe in the interface id);
// randomised privacy addresses return an error.
func IPv6ToMAC(addr string) (string, error) {
	addr = StripZone(addr)
	ip := net.ParseIP(addr)
	if ip == nil || ip.To16() == nil {
		return "", fmt.Errorf("invalid ipv6 %q", addr)
	}
	b := ip.To16()
	if b[11] != 0xff || b[12] != 0xfe {
		return "", fmt.Errorf("%s is not EUI-64 derived", addr)
	}
	mac := net.HardwareAddr{b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]}
	return mac.String(), nil
}

// StripZone removes a "%iface" scope suffix from an IP literal.
func StripZone(addr string) string {
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// Scoped returns addr joined with zone if it is link-local and lacks one.
func Scoped(addr, zone string) string {
	base := StripZone(addr)
	ip := net.ParseIP(base)
	if ip == nil || !ip.IsLinkLocalUnicast() || zone == "" {
		return base
	}
	return base + "%" + zone
}

// ExpandCIDR returns every IPv4 address inside cidr. /31 and /32 are handled
// per RFC 3021 semantics (all addresses listed). Huge ranges are rejected to
// avoid accidental /8 sweeps.
func ExpandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("%q is not an IPv4 range", cidr)
	}
	if ones < 16 {
		return nil, fmt.Errorf("refusing to expand %q (>65k hosts); use a narrower range", cidr)
	}
	base := ipnet.IP.To4()
	size := 1 << uint(32-ones)
	out := make([]string, 0, size)
	for i := 0; i < size; i++ {
		ip := net.IPv4(base[0], base[1], base[2], base[3]).To4()
		out = append(out, ip.String())
		base = nextIP(base)
	}
	return out, nil
}

func nextIP(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// PortSpec parses user port selections such as "22", "22,80,443",
// "1-1024" or "80,1000-2000,5900".
func PortSpec(spec string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(lo)
			b, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || a > b {
				return nil, fmt.Errorf("bad port range %q", part)
			}
			for p := a; p <= b && p <= 65535; p++ {
				add(p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		add(p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty port spec")
	}
	return out, nil
}

// RateLimiter is a simple blocking token bucket safe for concurrent use.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	rate     float64
	burst    float64
	lastFill time.Time
}

// NewRateLimiter creates a limiter allowing `rate` events per second with the
// given burst size. rate<=0 means unlimited.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{tokens: float64(burst), rate: rate, burst: float64(burst), lastFill: time.Now()}
}

// Wait blocks until a token is available (or immediately when unlimited).
func (r *RateLimiter) Wait() {
	if r.rate <= 0 {
		return
	}
	for {
		r.mu.Lock()
		now := time.Now()
		r.tokens += now.Sub(r.lastFill).Seconds() * r.rate
		r.lastFill = now
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return
		}
		deficit := (1 - r.tokens) / r.rate
		r.mu.Unlock()
		time.Sleep(time.Duration(deficit * float64(time.Second)))
	}
}

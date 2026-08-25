// Package model defines the shared data structures exchanged between the
// discovery, scanner and report packages of ipv4Bypass.
package model

import (
	"strings"
	"time"
)

// Protocol is the transport protocol a port result belongs to.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// PortState describes the outcome of probing a single port.
type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered" // no reply / unreachable (UDP) or timeout
)

// Family identifies the IP address family of a scan target ("v4" or "v6").
type Family string

const (
	V4 Family = "v4"
	V6 Family = "v6"
)

// Service captures everything we know about one probed port.
type Service struct {
	Port        int       `json:"port"`
	Protocol    Protocol  `json:"protocol"`
	State       PortState `json:"state"`
	Fingerprint string    `json:"fingerprint,omitempty"` // guessed service name (banner or well-known)
	Banner      string    `json:"banner,omitempty"`      // captured application banner, if any
}

// Host is a correlated dual-stack endpoint discovered on the local network.
type Host struct {
	MAC        string   `json:"mac,omitempty"` // aa:bb:cc:dd:ee:ff, empty when unknown
	IPv4       string   `json:"ipv4,omitempty"`
	IPv6       []string `json:"ipv6,omitempty"`        // may carry %zone for link-locals
	Vendor     string   `json:"vendor,omitempty"`      // OUI vendor when resolvable
	HostnameV4 string   `json:"hostname_v4,omitempty"` // PTR for IPv4
	HostnameV6 string   `json:"hostname_v6,omitempty"` // PTR for primary IPv6
	MDNSName   string   `json:"mdns_name,omitempty"`   // mDNS/DNS-SD name if discovered
}

// PrimaryIPv6 picks the address used for scanning: GUA/ULA first, then scoped link-local.
func (h *Host) PrimaryIPv6() string {
	var ll string
	for _, a := range h.IPv6 {
		if !isLinkLocal(a) {
			return stripZone(a)
		}
		if ll == "" {
			ll = a
		}
	}
	return ll // scoped link-local (may be "")
}

// String renders a compact host identifier for logs/sorting.
func (h *Host) String() string {
	parts := make([]string, 0, 4)
	if h.IPv4 != "" {
		parts = append(parts, h.IPv4)
	}
	if v6 := h.PrimaryIPv6(); v6 != "" {
		parts = append(parts, stripZone(v6))
	}
	if h.MAC != "" {
		parts = append(parts, h.MAC)
	}
	return strings.Join(parts, " ")
}

func isLinkLocal(addr string) bool {
	for i := 0; i+4 <= len(addr); i++ {
		if addr[i] == 'f' && addr[i+1] == 'e' && addr[i+2] == '8' && addr[i+3] == '0' {
			return true
		}
		if addr[i] != ':' && addr[i] != '0' {
			break
		}
	}
	return false
}

// StripZone removes a "%iface" scope suffix from an address literal.
func StripZone(addr string) string { return stripZone(addr) }

func stripZone(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == '%' {
			return addr[:i]
		}
	}
	return addr
}

// HostResult holds the full scan outcome for one host.
type HostResult struct {
	Host       Host                 `json:"host"`
	Open       map[string][]Service `json:"open"` // key "v4:tcp", "v6:tcp", "v4:udp", "v6:udp"
	ScannedAt  time.Time            `json:"scanned_at"`
	DurationMs int64                `json:"duration_ms"`
}

// OpenMap initialises the internal map of a HostResult.
func (r *HostResult) OpenMap() map[string][]Service {
	if r.Open == nil {
		r.Open = map[string][]Service{}
	}
	return r.Open
}

// Category classifies a dual-stack difference.
type Category string

const (
	CatNewExposure    Category = "new_exposure_ipv6" // open on v6, closed/filtered on v4
	CatMissingOnV6    Category = "missing_on_ipv6"   // open on v4, closed/filtered on v6
	CatProtoMismatch  Category = "protocol_mismatch" // open both, but fingerprint/banner differs
	CatUDPNewExposure Category = "udp_new_exposure_ipv6"
	CatUDPMissingOnV6 Category = "udp_missing_on_ipv6"
	CatPTRMismatch    Category = "ptr_mismatch" // v4/v6 reverse DNS disagree
	CatGUAExposed     Category = "gua_exposed"  // globally routable v6 addr with open ports
)

// Severity is the risk rating of a finding.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var severityOrder = map[Severity]int{
	SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4,
}

// Less orders severities from most to least severe.
func (s Severity) Less(o Severity) bool { return severityOrder[s] < severityOrder[o] }

// Finding is one reportable observation about a host.
type Finding struct {
	Host     Host     `json:"host"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Protocol Protocol `json:"protocol,omitempty"`
	Port     int      `json:"port,omitempty"` // 0 => aggregate finding
	Detail   string   `json:"detail,omitempty"`
}

// Stats summarises a run.
type Stats struct {
	StartedAt    time.Time        `json:"started_at"`
	Duration     time.Duration    `json:"-"`
	DurationSecs float64          `json:"duration_seconds"`
	HostsFound   int              `json:"hosts_found"`
	HostsScanned int              `json:"hosts_scanned"`
	OpenV4TCP    int              `json:"open_tcp_v4"`
	OpenV6TCP    int              `json:"open_tcp_v6"`
	OpenV4UDP    int              `json:"open_udp_v4"`
	OpenV6UDP    int              `json:"open_udp_v6"`
	Findings     map[Severity]int `json:"findings_by_severity"`
}

// Report is the full tool output document.
type Report struct {
	Interface string        `json:"interface"`
	CIDR      string        `json:"cidr"`
	Stats     Stats         `json:"stats"`
	Hosts     []*HostResult `json:"hosts"`
	Findings  []Finding     `json:"findings"`
	Warnings  []string      `json:"warnings,omitempty"`
}

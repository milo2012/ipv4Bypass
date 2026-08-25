package report

import (
	"sort"
	"strconv"
	"strings"

	"ipv4Bypass/internal/model"
)

// Analyze diffs each host's IPv4/IPv6 port sets and emits findings:
//
//   - new_exposure_ipv6:   open on v6, closed/filtered on v4 (the bypass case)
//   - missing_on_ipv6:     open on v4, closed/filtered on v6
//   - protocol_mismatch:   open on both but fingerprint/banner differs
//   - udp_*:               the same three comparisons for UDP
//   - gua_exposed:         open services reachable via a globally routable v6
//     address (not just link-local), i.e. potentially routable from upstream
//   - ptr_mismatch:        reverse DNS disagrees between families
func Analyze(results []*model.HostResult) []model.Finding {
	var findings []model.Finding
	for _, res := range results {
		h := res.Host

		diffFamily := func(proto model.Protocol, catNew, catMiss model.Category) {
			v4 := serviceMap(res.Open[key(model.V4, proto)])
			v6 := serviceMap(res.Open[key(model.V6, proto)])
			if len(v4) == 0 && len(v6) == 0 {
				return
			}

			// v6-only exposure
			var newPorts []int
			for port := range v6 {
				if _, ok := v4[port]; !ok {
					newPorts = append(newPorts, port)
				}
			}
			sortInts(newPorts)
			for _, p := range newPorts {
				svc := v6[p]
				findings = append(findings, model.Finding{
					Host: h, Category: catNew, Severity: severityFor(catNew, p),
					Protocol: proto, Port: p,
					Detail: describe(svc),
				})
			}

			// v4-only exposure
			var gonePorts []int
			for port := range v4 {
				if _, ok := v6[port]; !ok {
					gonePorts = append(gonePorts, port)
				}
			}
			sortInts(gonePorts)
			for _, p := range gonePorts {
				svc := v4[p]
				findings = append(findings, model.Finding{
					Host: h, Category: catMiss, Severity: severityFor(catMiss, p),
					Protocol: proto, Port: p,
					Detail: describe(svc),
				})
			}

			// same port, different fingerprint => protocol mismatch
			var bothPorts []int
			for port := range v4 {
				if _, ok := v6[port]; ok {
					bothPorts = append(bothPorts, port)
				}
			}
			sortInts(bothPorts)
			for _, p := range bothPorts {
				a, b := v4[p], v6[p]
				if mismatched(a, b) {
					findings = append(findings, model.Finding{
						Host: h, Category: model.CatProtoMismatch,
						Severity: severityFor(model.CatProtoMismatch, p),
						Protocol: proto, Port: p,
						Detail: "v4=" + ident(a) + " vs v6=" + ident(b) +
							" (same port, different service fingerprint)",
					})
				}
			}
		}

		diffFamily(model.TCP, model.CatNewExposure, model.CatMissingOnV6)
		diffFamily(model.UDP, model.CatUDPNewExposure, model.CatUDPMissingOnV6)

		// GUA exposure: any open v6 TCP port on a globally routable address.
		if hasOpen(res.Open[key(model.V6, model.TCP)]) && isGlobal(h.PrimaryIPv6()) {
			openCount := len(res.Open[key(model.V6, model.TCP)])
			findings = append(findings, model.Finding{
				Host: h, Category: model.CatGUAExposed,
				Severity: severityFor(model.CatGUAExposed, 0),
				Detail:   "open TCP services reachable on globally routable IPv6 (" + strconv.Itoa(openCount) + " ports)",
			})
		}

		// PTR discrepancy between stacks.
		if h.HostnameV4 != "" && h.HostnameV6 != "" &&
			!relatedNames(h.HostnameV4, h.HostnameV6) {
			findings = append(findings, model.Finding{
				Host: h, Category: model.CatPTRMismatch, Severity: model.SevInfo,
				Detail: "v4 PTR=" + h.HostnameV4 + " vs v6 PTR=" + h.HostnameV6,
			})
		}
	}
	return findings
}

func key(family model.Family, proto model.Protocol) string {
	return string(family) + ":" + string(proto)
}

func serviceMap(svcs []model.Service) map[int]model.Service {
	m := make(map[int]model.Service, len(svcs))
	for _, s := range svcs {
		m[s.Port] = s
	}
	return m
}

func describe(s model.Service) string {
	parts := []string{}
	if s.Fingerprint != "" {
		parts = append(parts, s.Fingerprint)
	}
	if s.Banner != "" {
		parts = append(parts, "banner: "+s.Banner)
	}
	if len(parts) == 0 {
		return "open"
	}
	return strings.Join(parts, " | ")
}

func ident(s model.Service) string {
	if s.Fingerprint != "" {
		return s.Fingerprint
	}
	return "unknown"
}

// mismatched reports whether two observations of the same port disagree about
// what is listening (fingerprint differs, or banner clearly differs when no
// fingerprint was derived).
func mismatched(a, b model.Service) bool {
	if a.Fingerprint != "" && b.Fingerprint != "" {
		return a.Fingerprint != b.Fingerprint
	}
	if a.Banner != "" && b.Banner != "" {
		return firstLine(a.Banner) != firstLine(b.Banner)
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func hasOpen(svcs []model.Service) bool { return len(svcs) > 0 }

func isGlobal(addr string) bool {
	if addr == "" {
		return false
	}
	return strings.HasPrefix(addr, "2") || strings.HasPrefix(addr, "3") // 2000::/3 GUAs
}

// relatedNames tolerates subdomain relationships (web01.example.com vs
// example.com are not a real mismatch).
func relatedNames(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	if a == b || a == "" || b == "" {
		return true
	}
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func sortInts(a []int) { sort.Ints(a) }

// Package report turns raw scan results into findings (dual-stack diffs,
// severity tags) and renders them as terminal text, JSON, NDJSON or CSV.
package report

import (
	"strconv"

	"ipv4Bypass/internal/model"
)

// highRiskPorts: exposure here is directly dangerous (remote code execution,
// unauthenticated admin surfaces, legacy clear-text protocols).
var highRiskPorts = map[int]bool{
	21: true, 22: true, 23: true, 69: true, 111: true, 135: true, 137: true,
	139: true, 161: true, 445: true, 512: true, 513: true, 514: true,
	873: true, 1099: true, 1433: true, 1521: true, 1883: true, 2049: true,
	2375: true, 3306: true, 3389: true, 4444: true, 5432: true, 5555: true,
	5900: true, 5985: true, 6379: true, 6667: true, 9100: true,
	9200: true, 11211: true, 27017: true, 50000: true,
}

// mediumRiskPorts: common services whose unexpected exposure is noteworthy.
var mediumRiskPorts = map[int]bool{
	25: true, 53: true, 80: true, 110: true, 143: true, 179: true, 389: true,
	443: true, 465: true, 587: true, 631: true, 993: true, 995: true,
	1080: true, 1194: true, 1723: true, 3128: true, 3268: true, 5060: true,
	5683: true, 8000: true, 8008: true, 8080: true, 8443: true, 8888: true,
	9090: true, 10000: true,
}

// baseRate rates the intrinsic risk of a port.
func baseRate(port int) model.Severity {
	switch {
	case highRiskPorts[port]:
		return model.SevHigh
	case mediumRiskPorts[port]:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

// bump escalates one tier — used for the headline "open on IPv6 but firewalled
// on IPv4" direction, which is the actual bypass this tool hunts for.
func bump(s model.Severity) model.Severity {
	switch s {
	case model.SevHigh:
		return model.SevCritical
	case model.SevMedium:
		return model.SevHigh
	case model.SevLow:
		return model.SevMedium
	default:
		return model.SevInfo
	}
}

// drop de-escalates one tier — used when IPv4 is *more* exposed than IPv6
// (interesting for completeness, rarely an attack path).
func drop(s model.Severity) model.Severity {
	switch s {
	case model.SevHigh:
		return model.SevMedium
	case model.SevMedium:
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func severityFor(cat model.Category, port int) model.Severity {
	base := baseRate(port)
	switch cat {
	case model.CatNewExposure, model.CatUDPNewExposure:
		return bump(base)
	case model.CatMissingOnV6, model.CatUDPMissingOnV6:
		return drop(base)
	case model.CatProtoMismatch:
		return model.SevMedium
	case model.CatGUAExposed:
		if base == model.SevHigh {
			return model.SevHigh
		}
		return model.SevMedium
	default:
		return model.SevInfo
	}
}

func portLabel(p model.Protocol, port int) string {
	return string(p) + "/" + strconv.Itoa(port)
}

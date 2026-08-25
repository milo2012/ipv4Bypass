// Package sysutil wraps platform-specific system interactions: interface
// enumeration, privilege detection, external command execution and parsing of
// kernel neighbour tables (ARP / NDP).
package sysutil

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"ipv4Bypass/internal/netutil"
)

// InterfaceInfo bundles everything we need to know about the local interface.
type InterfaceInfo struct {
	Name    string
	HWAddr  string   // local MAC, lowercase colon notation
	IPv4    string   // primary unicast v4
	IPv6All []string // all global/link-local v6 addrs as reported by the OS (unscoped)
	Index   int
}

// GetInterface resolves and inspects the named interface.
func GetInterface(name string) (*InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", name, err)
	}
	info := &InterfaceInfo{
		Name:  iface.Name,
		Index: iface.Index,
	}
	if iface.HardwareAddr != nil {
		info.HWAddr = iface.HardwareAddr.String()
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("cannot read addresses of %s: %w", name, err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if v4 := ip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
			if info.IPv4 == "" || v4.IsPrivate() {
				info.IPv4 = v4.String()
			}
			continue
		}
		if v6 := ip.To16(); v6 != nil && ip.IsGlobalUnicast() {
			info.IPv6All = append(info.IPv6All, v6.String())
		}
	}
	return info, nil
}

// Output runs cmd with args, returning combined stdout/stderr.
func Output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// LookPath resolves a tool name to a full path, probing common sbin dirs when
// PATH lookup fails (arp-scan on Debian/Ubuntu lives in /usr/sbin).
func LookPath(tool string, fallbacks ...string) string {
	if p, err := exec.LookPath(tool); err == nil {
		return p
	}
	candidates := []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/bin", "/usr/bin"}
	for _, dir := range candidates {
		p := dir + "/" + tool
		if fileExists(p) {
			return p
		}
	}
	for _, p := range fallbacks {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// NeighEntry is one row of a neighbour table (ARP or NDP).
type NeighEntry struct {
	IP       string // unscoped address literal
	MAC      string // normalised; empty for failed/incomplete entries
	State    string // REACHABLE, STALE, FAILED ...
	IsRouter bool   // NDP router flag when advertised
}

// ParseNeighLines extracts entries from `ip neigh` style output:
//
//	fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
//	192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
func ParseNeighLines(out string) []NeighEntry {
	var entries []NeighEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		e := NeighEntry{IP: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "lladdr":
				if i+1 < len(fields) {
					if m := Normalize(fields[i+1]); m != "" {
						e.MAC = m
					}
				}
			case "router":
				e.IsRouter = true
			default:
				if isStateWord(fields[i]) {
					e.State = fields[i]
				}
			}
		}
		if e.IP != "" {
			entries = append(entries, e)
		}
	}
	return entries
}

func isStateWord(s string) bool {
	switch strings.ToUpper(s) {
	case "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED",
		"PERMANENT", "NOARP", "NONE", "MULTICAST", "ROUTER":
		return true
	}
	return false
}

func Normalize(mac string) string {
	return netutil.NormalizeMAC(mac)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

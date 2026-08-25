package sysutil

import (
	"fmt"
	"runtime"
	"strings"
)

// ReadARPTable returns the kernel IPv4 neighbour (ARP) table.
//   - Linux:  `ip neigh show` (falls back to `arp -n`)
//   - macOS:  `arp -an`
//   - Windows:`arp -a`
func ReadARPTable() ([]NeighEntry, error) {
	switch runtime.GOOS {
	case "linux":
		if out, err := Output("ip", "neigh", "show"); err == nil && strings.TrimSpace(out) != "" {
			return ParseNeighLines(out), nil
		}
		out, err := Output("arp", "-n")
		if err != nil {
			return nil, fmt.Errorf("reading arp table: %w", err)
		}
		return parseArpPosix(out), nil
	case "darwin", "freebsd", "netbsd", "openbsd":
		out, err := Output("arp", "-an")
		if err != nil {
			return nil, fmt.Errorf("reading ndp/arp table: %w", err)
		}
		return parseArpPosix(out), nil
	default: // windows and others
		out, err := Output("arp", "-a")
		if err != nil {
			return nil, fmt.Errorf("reading arp table: %w", err)
		}
		return parseArpWindows(out), nil
	}
}

// ReadNDPTable returns the kernel IPv6 neighbour discovery table.
//   - Linux:  `ip -6 neigh show`
//   - macOS/BSD: `ndp -an`
//   - Windows:`netsh interface ipv6 show neighbors`
func ReadNDPTable() ([]NeighEntry, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := Output("ip", "-6", "neigh", "show")
		if err != nil {
			return nil, fmt.Errorf("reading ndp table: %w", err)
		}
		return ParseNeighLines(out), nil
	case "darwin", "freebsd", "netbsd", "openbsd":
		out, err := Output("ndp", "-an")
		if err != nil {
			return nil, fmt.Errorf("reading ndp table: %w", err)
		}
		return parseNdpBSD(out), nil
	default: // windows
		out, err := Output("netsh", "interface", "ipv6", "show", "neighbors")
		if err != nil {
			return nil, fmt.Errorf("reading ndp table via netsh: %w", err)
		}
		return parseNetshNeighbors(out), nil
	}
}

// parseArpPosix parses `arp -an` output:
//
//	? (192.168.1.10) at ab:cd:ef:12:34:56 on en0 ifscope [ethernet]
func parseArpPosix(out string) []NeighEntry {
	var entries []NeighEntry
	for _, line := range strings.Split(out, "\n") {
		open := strings.IndexByte(line, '(')
		close_ := strings.IndexByte(line, ')')
		if open < 0 || close_ < open+2 {
			continue
		}
		ip := line[open+1 : close_]
		rest := line[close_:]
		at := strings.Index(rest, " at ")
		if at < 0 {
			continue
		}
		tail := rest[at+4:]
		end := strings.Index(tail, " ")
		mac := tail
		if end > 0 {
			mac = tail[:end]
		}
		if m := Normalize(mac); m != "" {
			entries = append(entries, NeighEntry{IP: ip, MAC: m})
		} else if strings.Contains(mac, "incomplete") {
			entries = append(entries, NeighEntry{IP: ip})
		}
	}
	return entries
}

// parseArpWindows parses Windows `arp -a`:
//
//	192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic
func parseArpWindows(out string) []NeighEntry {
	var entries []NeighEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.Contains(fields[0], ".") {
			continue
		}
		ip := fields[0]
		if !strings.Contains(ip, ":") { // skip ipv6-looking rows in mixed output
			e := NeighEntry{IP: ip}
			if m := Normalize(fields[1]); m != "" {
				e.MAC = m
			}
			if len(fields) >= 3 {
				e.State = fields[len(fields)-1]
			}
			entries = append(entries, e)
		}
	}
	return entries
}

// parseNdpBSD parses macOS/BSD `ndp -an`:
//
//	Neighbor                             Linklayer Address  Netif Expire    S Flags
//	fe80::1%en0                          aa:bb:cc:dd:ee:ff  en0   23s       R
func parseNdpBSD(out string) []NeighEntry {
	var entries []NeighEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr := fields[0]
		if !strings.Contains(addr, ":") { // header / junk
			continue
		}
		e := NeighEntry{IP: StripZoneIfAny(addr)}
		if m := Normalize(fields[1]); m != "" {
			e.MAC = m
		}
		if len(fields) >= 6 {
			e.State = fields[4] // Expire column index varies; S column at 4
			if strings.Contains(fields[len(fields)-1], "R") {
				e.IsRouter = true
			}
		}
		entries = append(entries, e)
	}
	return entries
}

// parseNetshNeighbors parses `netsh interface ipv6 show neighbors` output where
// each row is `<ip> <mac> <state>` with dash-separated MACs.
func parseNetshNeighbors(out string) []NeighEntry {
	var entries []NeighEntry
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		fields := strings.Fields(l)
		if len(fields) < 3 {
			continue
		}
		ip := fields[0]
		if !strings.Contains(ip, ":") && !strings.Contains(ip, ".") {
			continue
		}
		e := NeighEntry{IP: StripZoneIfAny(ip), State: fields[len(fields)-1]}
		if m := Normalize(fields[1]); m != "" {
			e.MAC = m
		} else if up := strings.ToUpper(fields[1]); up == "UNREACHABLE" || up == "INCOMPLETE" {
			e.State = up
		}
		entries = append(entries, e)
	}
	return entries
}

// StripZoneIfAny removes "%iface" scopes from address literals.
func StripZoneIfAny(addr string) string {
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		return addr[:i]
	}
	return addr
}

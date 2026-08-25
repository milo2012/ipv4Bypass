//go:build linux

package discovery

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
)

// solicitRA sends a Router Solicitation to ff02::2 and collects Router
// Advertisements for the given duration, returning discovered prefixes
// (with flags) and default-router link-locals.
func solicitRA(iface *ifaceInfo, wait time.Duration) (prefixes []string, routers []string, err error) {
	conn, rerr := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if rerr != nil {
		return nil, nil, fmt.Errorf("ICMPv6 socket: %w", rerr)
	}
	defer conn.Close()
	pc := conn.IPv6PacketConn()
	if pc == nil {
		return nil, nil, fmt.Errorf("unexpected ICMPv6 connection type")
	}

	all := &net.IPAddr{IP: net.IPv6linklocalallnodes, Zone: iface.Name}
	if jerr := pc.JoinGroup(&net.Interface{Index: iface.Index, Name: iface.Name}, all); jerr != nil {
		return nil, nil, fmt.Errorf("join ff02::1: %w", jerr)
	}

	rs := []byte{133, 0, 0, 0} // type 133, code 0, checksum filled by kernel
	routersGroup := &net.IPAddr{IP: net.IPv6linklocalallrouters, Zone: iface.Name}
	if _, werr := pc.WriteTo(rs, nil, routersGroup); werr != nil {
		return nil, nil, fmt.Errorf("send RS: %w", werr)
	}

	buf := make([]byte, 4096)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		pc.SetReadDeadline(deadline)
		n, _, src, rerr := pc.ReadFrom(buf)
		if rerr != nil {
			break
		}
		if n < 16 || buf[0] != 134 { // Router Advertisement
			continue
		}
		if ia, ok := src.(*net.IPAddr); ok && ia.IP != nil && ia.IP.IsLinkLocalUnicast() {
			zone := ia.Zone
			if zone == "" {
				zone = iface.Name // link-locals need a scope for later use
			}
			routers = append(routers, ia.IP.String()+"%"+zone)
		}
		// options start at byte 16
		opt := buf[16:n]
		for len(opt) >= 8 {
			typ := opt[0]
			length := int(opt[1]) * 8 // in units of 8 octets
			if length == 0 || length > len(opt) {
				break
			}
			if typ == 3 && length >= 32 { // Prefix Information
				plen := int(opt[2])
				flagsA := opt[3]&0x80 != 0
				prefix := net.IP(opt[16:32])
				if plen > 0 && prefix != nil && !prefix.IsUnspecified() {
					flag := ""
					if flagsA {
						flag = " A" // autonomous (SLAAC-capable)
					}
					prefixes = append(prefixes, fmt.Sprintf("%s/%d%s", prefix.String(), plen, flag))
				}
			}
			opt = opt[length:]
		}
	}
	return prefixes, routers, nil
}

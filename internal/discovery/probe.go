package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"ipv4Bypass/internal/netutil"
)

// ping6Multicast sends an ICMPv6 echo request to ff02::1 on the interface and
// collects responder addresses for ~2.5s. Link-locals are returned WITH the
// %zone suffix so they are directly usable in later socket operations.
func ping6Multicast(ctx context.Context, iface *ifaceInfo) ([]string, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("ICMPv6 socket: %w (need root or net.ipv6.ping_group_range)", err)
	}
	defer conn.Close()

	pc := conn.IPv6PacketConn()
	if pc == nil {
		return nil, fmt.Errorf("ICMPv6 socket: unexpected connection type")
	}
	group := &net.IPAddr{IP: net.IPv6linklocalallnodes, Zone: iface.Name}
	if err := pc.JoinGroup(&net.Interface{Index: iface.Index, Name: iface.Name}, group); err != nil {
		return nil, fmt.Errorf("join ff02::1: %w", err)
	}

	self := map[string]bool{}
	for _, a := range iface.IPv6All {
		self[netutil.StripZone(a)] = true
	}

	msg := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("ipv4bypass-disc")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}
	if _, err := pc.WriteTo(wb, nil, group); err != nil {
		return nil, fmt.Errorf("send to ff02::1: %w", err)
	}

	var live []string
	seen := map[string]bool{}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := pc.SetReadDeadline(deadline); err != nil {
			break
		}
		n, _, src, err := pc.ReadFrom(buf)
		if err != nil {
			break // timeout
		}
		rm, err := icmp.ParseMessage(58, buf[:n])
		if err != nil || rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		ipAddr, ok := src.(*net.IPAddr)
		if !ok || ipAddr.IP == nil {
			continue
		}
		base := netutil.StripZone(ipAddr.String())
		if self[base] {
			continue
		}
		addr := base
		if ipAddr.IP.IsLinkLocalUnicast() && ipAddr.Zone == "" {
			addr = base + "%" + iface.Name
		}
		if !seen[addr] {
			seen[addr] = true
			live = append(live, addr)
		}
	}
	return live, nil
}

// ping6Once probes a single (possibly scoped) IPv6 address with one echo.
func ping6Once(ctx context.Context, scopedAddr string) bool {
	host, portless := splitScope(scopedAddr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return false
	}
	defer conn.Close()
	pc := conn.IPv6PacketConn()
	if pc == nil {
		return false
	}
	msg := &icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 7, Data: []byte("eui64-probe")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	dst := &net.IPAddr{IP: ip}
	if !portless { // link-local needs the zone
		dst.Zone = scopeOf(scopedAddr)
	}
	if _, err := pc.WriteTo(wb, nil, dst); err != nil {
		return false
	}
	deadline := time.Now().Add(700 * time.Millisecond)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		pc.SetReadDeadline(deadline)
		n, _, from, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		rm, perr := icmp.ParseMessage(58, buf[:n])
		if perr != nil || rm.Type != ipv6.ICMPTypeEchoReply {
			continue
		}
		if ia, ok := from.(*net.IPAddr); ok && ia.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func splitScope(addr string) (host string, unscoped bool) {
	for i := 0; i < len(addr); i++ {
		if addr[i] == '%' {
			return addr[:i], false
		}
	}
	return addr, true
}

func scopeOf(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == '%' {
			return addr[i+1:]
		}
	}
	return ""
}

// arpScanExternal runs the classic arp-scan binary and parses its output:
//
//	192.168.1.10	a0:b1:c2:d3:e4:f5	Raspberry Pi Foundation
func arpScanExternal(bin, ifaceName, cidr string) (map[string]string, map[string]string, error) {
	out, err := runCmd(bin, "-I", ifaceName, cidr)
	if err != nil && len(out) == 0 {
		return nil, nil, err
	}
	pairs := map[string]string{}
	vendors := map[string]string{}
	for _, line := range splitLines(out) {
		fields := splitFields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		mac := normalizeMAC(fields[1])
		if mac == "" || !isIPv4(ip) {
			continue
		}
		pairs[ip] = mac
		if len(fields) >= 3 && fields[2] != "" && fields[2] != "(Unknown)" &&
			!strings.HasPrefix(line, "Ending") && !strings.HasPrefix(line, "Starting") {
			vendors[ip] = fields[2]
		}
	}
	return pairs, vendors, nil
}

// probeReachable is the fully unprivileged discovery path: TCP connect probes
// against common management ports plus a short wait so the kernel ARP cache
// fills for hosts that answered at L2 even if no TCP port was open.
func probeReachable(ctx context.Context, opts Options) []string {
	var live []string
	targets, err := netutil.ExpandCIDR(opts.CIDR)
	if err != nil {
		return nil
	}
	probePorts := []int{22, 80, 443, 445, 3389}
	sem := make(chan struct{}, 64)
	var mu sync.Mutex
	var wg sync.WaitGroup
	dialer := &net.Dialer{Timeout: 600 * time.Millisecond}
	for _, t := range targets {
		select {
		case <-ctx.Done():
			wg.Wait()
			return live
		default:
		}
		for _, p := range probePorts {
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					return
				}
				c.Close()
				mu.Lock()
				live = append(live, host)
				mu.Unlock()
			}(t, p)
		}
	}
	wg.Wait()
	return dedupe(live)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

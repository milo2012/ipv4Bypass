package discovery

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// mdnsDiscover sends a one-shot DNS-SD service browse to the mDNS multicast
// groups and correlates answer records into an ip -> hostname map.
func mdnsDiscover(iface *ifaceInfo, wait time.Duration) (map[string]string, error) {
	serviceTypes := []string{
		"_services._dns-sd._udp.local",
		"_workstation._tcp.local",
		"_ssh._tcp.local",
		"_smb._tcp.local",
		"_ipp._tcp.local",
		"_airplay._tcp.local",
		"_googlecast._tcp.local",
		"_hap._tcp.local",
		"_device-info._tcp.local",
	}
	query := encodeMDNSQuery(serviceTypes)

	var mu sync.Mutex
	names := map[string]string{} // ip -> first claiming hostname

	record := func(ip, name string) {
		if ip == "" || name == "" {
			return
		}
		mu.Lock()
		if _, ok := names[ip]; !ok {
			names[ip] = name
		}
		mu.Unlock()
	}

	handle := func(buf []byte) { decodeMDNSResponse(buf, record) }

	v4conn, err4 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 5353})
	var v6conn *net.UDPConn
	if iface.Name != "" {
		v6conn, _ = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 5353, Zone: iface.Name})
	}
	if err4 != nil && v6conn == nil {
		// Fall back to ephemeral ports: only unicast replies will be received.
		v4conn, err4 = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err4 != nil {
			return nil, fmt.Errorf("mDNS socket: %w", err4)
		}
	}
	if v4conn != nil {
		defer v4conn.Close()
	}
	if v6conn != nil {
		defer v6conn.Close()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 9000)
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			got := false
			if v4conn != nil {
				v4conn.SetReadDeadline(deadline)
				if n, _, err := v4conn.ReadFromUDP(buf); err == nil && n > 0 {
					handle(buf[:n])
					got = true
				}
			}
			if v6conn != nil {
				v6conn.SetReadDeadline(deadline)
				if n, _, err := v6conn.ReadFromUDP(buf); err == nil && n > 0 {
					handle(buf[:n])
					got = true
				}
			}
			if !got {
				d := time.Until(deadline)
				if d <= 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	mcast4 := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	if v4conn != nil {
		v4conn.WriteToUDP(query, mcast4)
	}
	mcast6 := &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353, Zone: iface.Name}
	if v6conn != nil {
		v6conn.WriteToUDP(query, mcast6)
	}

	select {
	case <-done:
	case <-time.After(wait + 500*time.Millisecond):
	}

	// strip trailing dots
	out := make(map[string]string, len(names))
	for ip, n := range names {
		out[ip] = strings.TrimSuffix(n, ".")
	}
	return out, nil
}

const (
	typeA    = 1
	typePTR  = 12
	typeAAAA = 28
)

// encodeMDNSQuery builds a DNS query with the QU (unicast response) bit set.
func encodeMDNSQuery(names []string) []byte {
	id := rand.Uint32() & 0xffff
	buf := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(buf[0:2], uint16(id))
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(names))) // qdcount
	for _, name := range names {
		for _, label := range strings.Split(name, ".") {
			if label == "" {
				continue
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
		buf = append(buf, 0)
		var tail [4]byte
		binary.BigEndian.PutUint16(tail[0:2], typePTR)
		binary.BigEndian.PutUint16(tail[2:4], 0x8001) // IN + QU bit
		buf = append(buf, tail[:]...)
	}
	return buf
}

// decodeMDNSResponse extracts A/AAAA/PTR records; `record` is called with each
// address-to-name association found.
func decodeMDNSResponse(buf []byte, record func(ip, name string)) {
	if len(buf) < 12 {
		return
	}
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	ns := int(binary.BigEndian.Uint16(buf[8:10]))
	ar := int(binary.BigEndian.Uint16(buf[10:12]))

	pos := 12
	// skip questions
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	for i := 0; i < qd; i++ {
		name, next, ok := readDNSName(buf, pos)
		if !ok || next+4 > len(buf) {
			return
		}
		_ = name
		pos = next + 4
	}

	readAll := func(count int) {
		for i := 0; i < count && pos+10 <= len(buf); i++ {
			name, next, ok := readDNSName(buf, pos)
			if !ok {
				return
			}
			pos = next
			rtype := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
			rdlen := int(binary.BigEndian.Uint16(buf[pos+8 : pos+10]))
			rdata := pos + 10
			if rdata+rdlen > len(buf) {
				return
			}
			switch rtype {
			case typeA:
				if rdlen == 4 {
					ip := net.IP(buf[rdata : rdata+4]).String()
					record(ip, cleanName(name))
				}
			case typeAAAA:
				if rdlen == 16 {
					ip := net.IP(buf[rdata : rdata+16]).String()
					record(ip, cleanName(name))
				}
			case typePTR:
				// PTR targets enumerate service instances; the ip->name mapping
				// we need comes from A/AAAA owner records, so skip here.
				_ = rdlen
			}
			pos = rdata + rdlen
		}
	}
	readAll(an)
	readAll(ns)
	readAll(ar)
}

func cleanName(name string) string {
	return strings.TrimSuffix(name, ".")
}

// readDNSName parses a possibly-compressed domain name starting at off.
func readDNSName(buf []byte, off int) (string, int, bool) {
	var sb strings.Builder
	jumps := 0
	next := -1
	for {
		if off >= len(buf) {
			return "", 0, false
		}
		l := int(buf[off])
		if l&0xc0 == 0xc0 { // compression pointer
			if off+1 >= len(buf) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			off = ptr
			jumps++
			if jumps > 20 {
				return "", 0, false
			}
			continue
		}
		if l == 0 {
			if next < 0 {
				next = off + 1
			}
			return sb.String(), next, true
		}
		if off+1+l > len(buf) {
			return "", 0, false
		}
		sb.Write(buf[off+1 : off+1+l])
		sb.WriteByte('.')
		off += 1 + l
	}
}

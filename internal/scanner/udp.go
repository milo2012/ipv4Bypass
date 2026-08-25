package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ipv4Bypass/internal/model"
	"ipv4Bypass/internal/netutil"
)

// udpProbe is one crafted request payload plus its reply classifier.
type udpProbe struct {
	payload    []byte
	classifier func([]byte) string // returns fingerprint, "" if not this service
}

// probeTable maps UDP ports to service probes. A port without an entry gets a
// single junk byte so closed-port ICMP feedback still classifies it.
var probeTable = map[int]udpProbe{
	53: {payload: dnsQuery("example.com"), classifier: func(b []byte) string {
		if len(b) >= 4 && b[2]&0x80 != 0 {
			return "dns"
		}
		return ""
	}},
	69: {payload: tftpRRQ(), classifier: func(b []byte) string {
		if len(b) >= 2 {
			op := binary.BigEndian.Uint16(b[:2])
			if op == 3 || op == 5 {
				return "tftp"
			}
		}
		return ""
	}},
	123: {payload: ntpClient(), classifier: func(b []byte) string {
		if len(b) >= 48 && b[0]&0x38>>3 <= 4 {
			return "ntp"
		}
		return ""
	}},
	161: {payload: snmpGet(), classifier: func(b []byte) string {
		if len(b) > 2 && b[0] == 0x30 {
			return "snmp"
		}
		return ""
	}},
	137: {payload: nbnsNodeStatus(), classifier: func(b []byte) string {
		if len(b) >= 12 {
			return "netbios-ns"
		}
		return ""
	}},
	1900: {payload: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
		classifier: func(b []byte) string {
			if strings.HasPrefix(string(b), "HTTP/1.") || strings.HasPrefix(string(b), "NOTIFY") {
				return "ssdp"
			}
			return ""
		}},
	5353: {payload: mdnsPTR(), classifier: func(b []byte) string {
		if len(b) >= 4 && b[2]&0x80 != 0 {
			return "mdns"
		}
		return ""
	}},
	5060: {payload: []byte("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK0001\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"),
		classifier: func(b []byte) string {
			if strings.HasPrefix(string(b), "SIP/2.0") {
				return "sip"
			}
			return ""
		}},
	5683: {payload: coapWellKnown(), classifier: func(b []byte) string {
		if len(b) >= 4 && b[0]&0xc0 == 0x40 {
			return "coap"
		}
		return ""
	}},
	500: {payload: isakmpPing(), classifier: func(b []byte) string {
		if len(b) >= 28 && b[16] == 1 { // exchange type SA init echo
			return "isakmp"
		}
		return ""
	}},
	11211: {payload: []byte("version\r\n"), classifier: func(b []byte) string {
		if strings.Contains(string(b), "VERSION") {
			return "memcached"
		}
		return ""
	}},
}

func scanUDP(ctx context.Context, family model.Family, ip string, h *model.Host,
	opts Options, limiter *netutil.RateLimiter, open map[string][]model.Service) {

	var mu sync.Mutex
	var wg sync.WaitGroup
	portCh := make(chan int, len(opts.UDPPorts))
	for _, p := range opts.UDPPorts {
		portCh <- p
	}
	close(portCh)
	workers := 32
	if workers > len(opts.UDPPorts) {
		workers = len(opts.UDPPorts)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				addr := dialAddr(family, ip, port, h)
				limiter.Wait()
				fp := probeUDP(addr, port, opts.ConnectTimeout)
				if fp == "" {
					continue // closed or silent
				}
				mu.Lock()
				open[string(family)+":udp"] = append(open[string(family)+":udp"], model.Service{
					Port:        port,
					Protocol:    model.UDP,
					State:       model.StateOpen,
					Fingerprint: fp,
				})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// probeUDP sends the service payload on a connected socket and distinguishes:
//
//	reply received          -> open (fingerprinted)
//	ICMP port unreachable   -> closed ("")
//	timeout / other         -> "" (filtered or silent open; not reported)
func probeUDP(addr string, port int, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = time.Second
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	payload, ok := probeTable[port]
	if !ok {
		payload = udpProbe{payload: []byte{0x00}}
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload.payload); err != nil {
		return ""
	}

	buf := make([]byte, 2048)
	for attempts := 0; attempts < 3; attempts++ {
		n, err := conn.Read(buf)
		if n > 0 {
			if fp := payload.classifier(buf[:n]); fp != "" {
				return fp
			}
			// Unrecognised but real reply still proves the port is open.
			return "udp/" + strconv.Itoa(port)
		}
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return ""
		}
		var oe *net.OpError
		if errors.As(err, &oe) {
			if errors.Is(oe.Err, syscall.ECONNREFUSED) {
				return "" // definitively closed
			}
		}
		return ""
	}
	return ""
}

// ---- payload builders ------------------------------------------------

func randID() uint16 { return uint16(rand.Intn(0xffff)) }

func dnsQuery(name string) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], randID())
	binary.BigEndian.PutUint16(buf[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	return buf
}

func mdnsPTR() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], randID())
	binary.BigEndian.PutUint16(buf[4:6], 1)
	name := "_services._dns-sd._udp.local"
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0, 0, 12, 0, 1) // QTYPE=PTR
	return buf
}

func tftpRRQ() []byte {
	return append([]byte{0x00, 0x01}, []byte("rfc1350.txt\x00octet\x00")...)
}

func ntpClient() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b // LI=0 VN=3 Mode=3(client)
	return b
}

func snmpGet() []byte {
	// SNMPv1 GET sysDescr.0 with community "public"
	return []byte{
		0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x1c, 0x02, 0x04, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}
}

func nbnsNodeStatus() []byte {
	// NetBIOS NODE STATUS REQUEST for wildcard name "*<00>"
	pkt := []byte{
		randByte(), randByte(),
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 0x00, 0x00, 0x21, 0x00, 0x01,
	}
	return pkt
}

func randByte() byte { return byte(rand.Intn(256)) }

func coapWellKnown() []byte {
	msgid := make([]byte, 2)
	binary.BigEndian.PutUint16(msgid, randID())
	pkt := append([]byte{0x50, 0x01}, msgid...) // NON GET
	pkt = append(pkt, 0xBB)                     // Uri-Path delta=11 len=11
	pkt = append(pkt, "well-known"...)
	pkt = append(pkt, 0x04) // delta=0 len=4
	pkt = append(pkt, "core"...)
	return pkt
}

func isakmpPing() []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:2], randID()) // initiator cookie (partial)
	b[14] = 0x10                                 // version
	b[15] = 0x04                                 // flags
	b[16] = 0x02                                 // exchange type: transactional
	return b
}

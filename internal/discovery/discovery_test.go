package discovery

import (
	"context"
	"encoding/binary"
	"testing"

	"ipv4Bypass/internal/model"
	"ipv4Bypass/internal/sysutil"
)

func testContext() context.Context { return context.Background() }

func TestEncodeMDNSQuery(t *testing.T) {
	buf := encodeMDNSQuery([]string{"_ssh._tcp.local"})
	if len(buf) < 12 {
		t.Fatal("query too short")
	}
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	if qd != 1 {
		t.Fatalf("qdcount = %d", qd)
	}
	name, next, ok := readDNSName(buf, 12)
	if !ok || name != "_ssh._tcp.local." {
		t.Fatalf("round trip failed: %q ok=%v", name, ok)
	}
	// qtype PTR + QU bit
	qtype := binary.BigEndian.Uint16(buf[next : next+2])
	qclass := binary.BigEndian.Uint16(buf[next+2 : next+4])
	if qtype != typePTR || qclass != 0x8001 {
		t.Errorf("qtype=%d qclass=%#x", qtype, qclass)
	}
}

func TestDecodeMDNSResponse(t *testing.T) {
	// Craft a response: answer A record for host.local, plus a compressed name.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400) // response flags
	binary.BigEndian.PutUint16(msg[6:8], 1)      // answers

	body := []byte{}
	for _, l := range []string{"myhost", "local"} { // owner name myhost.local.
		body = append(body, byte(len(l)))
		body = append(body, l...)
	}
	body = append(body, 0)
	body = append(body, 0x00, 0x01)            // type A
	body = append(body, 0x80, 0x01)            // class IN + cache flush
	body = append(body, 0x00, 0x00, 0x00, 120) // ttl
	body = append(body, 0x00, 0x04)            // rdlength
	body = append(body, 192, 168, 1, 55)       // rdata
	msg = append(msg, body...)

	names := map[string]string{}
	decodeMDNSResponse(msg, func(ip, name string) { names[ip] = name })

	wantIP := "192.168.1.55"
	if names[wantIP] != "myhost.local" && names[wantIP] != "myhost.local." {
		t.Fatalf("ip->name map wrong: %+v", names)
	}
}

func TestReadDNSNameCompression(t *testing.T) {
	buf := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		// offset 17: pointer to 0 (full name)
		0xc0, 0x00,
	}
	name, _, ok := readDNSName(buf, 0)
	if !ok || name != "www.example.com." {
		t.Fatalf("plain name: %q %v", name, ok)
	}
	cname, _, ok2 := readDNSName(buf, 17)
	if !ok2 || cname != "www.example.com." {
		t.Fatalf("compressed name: %q %v", cname, ok2)
	}
}

func TestCorrelatorNDPAndARP(t *testing.T) {
	opts := Options{Iface: &sysutil.InterfaceInfo{Name: "eth0", HWAddr: "11:22:33:44:55:66", IPv4: "192.168.1.5"}}
	res := &Result{MDNSNames: map[string]string{}}
	c := newCorrelator(opts, res)

	// ARP finds a v4 host
	c.seedARP(map[string]string{"192.168.1.10": "AA-BB-CC-DD-EE-FF"})
	// NDP has both its link-local and a GUA; plus a privacy-extension orphan
	c.applyNDP([]sysutil.NeighEntry{
		{IP: "fe80::aabb:ccdd:eeff:1", MAC: "aa:bb:cc:dd:ee:ff"},
		{IP: "2620:0:2820:2000::42", MAC: "aa-bb-cc-dd-ee-ff"},
		{IP: "fe80::9999:8888:7777:6666", MAC: ""}, // privacy addr, unknown MAC
	})

	hosts := c.hosts()
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts (correlated + privacy orphan), got %d: %+v", len(hosts), hosts)
	}

	var correlated *model.Host
	var orphan *model.Host
	for _, h := range hosts {
		if h.MAC == "aa:bb:cc:dd:ee:ff" {
			correlated = h
		} else {
			orphan = h
		}
	}
	if correlated == nil {
		t.Fatal("correlated host missing")
	}
	if correlated.IPv4 != "192.168.1.10" {
		t.Errorf("ipv4 not attached: %+v", correlated)
	}
	hasScopedLL, hasGUA := false, false
	for _, a := range correlated.IPv6 {
		switch a {
		case "fe80::aabb:ccdd:eeff:1%eth0":
			hasScopedLL = true
		case "2620:0:2820:2000::42":
			hasGUA = true
		}
	}
	if !hasScopedLL || !hasGUA {
		t.Errorf("v6 addresses wrong (zone must be added to LL): %+v", correlated.IPv6)
	}
	if orphan == nil || len(orphan.IPv6) != 1 {
		t.Errorf("privacy-extension orphan mishandled: %+v", orphan)
	}
}

func TestCorrelatorExcludesSelf(t *testing.T) {
	opts := Options{Iface: &sysutil.InterfaceInfo{Name: "eth0", HWAddr: "11:22:33:44:55:66", IPv4: "192.168.1.5"}}
	res := &Result{MDNSNames: map[string]string{}}
	c := newCorrelator(opts, res)

	c.seedARP(map[string]string{
		"192.168.1.5": "11:22:33:44:55:66", // ourselves
	})
	if got := c.hosts(); len(got) != 0 {
		t.Errorf("self should be excluded, got %+v", got)
	}
}

func TestEUI64FallbackOnlyOnLiveness(t *testing.T) {
	opts := Options{Iface: &sysutil.InterfaceInfo{Name: "eth0", HWAddr: "11:22:33:44:55:66", IPv4: "192.168.1.5"}}
	res := &Result{MDNSNames: map[string]string{}}
	c := newCorrelator(opts, res)
	c.seedARP(map[string]string{"192.168.1.20": "b8:27:eb:aa:bb:cc"})

	// In this sandbox no host answers the unicast probe, so no v6 is attached.
	c.eui64Fallback(testContext())
	for _, h := range c.hosts() {
		if len(h.IPv6) != 0 {
			t.Errorf("EUI-64 attached without liveness proof: %+v", h)
		}
	}
}

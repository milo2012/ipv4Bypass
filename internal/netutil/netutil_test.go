package netutil

import (
	"testing"
	"time"
)

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA-BB-CC-DD-EE-FF":    "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":       "aa:bb:cc:dd:ee:ff",
		" aa : bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"aabbccddeeff":         "aa:bb:cc:dd:ee:ff",
		"":                     "",
		"zz:bb:cc:dd:ee:ff":    "",
		"short":                "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMACToEUI64(t *testing.T) {
	got, err := MACToEUI64("b8:27:eb:12:34:56")
	if err != nil {
		t.Fatal(err)
	}
	want := "fe80::ba27:ebff:fe12:3456"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestIPv6ToMACRoundTrip(t *testing.T) {
	mac := "dc:a6:32:ab:cd:ef"
	v6, err := MACToEUI64(mac)
	if err != nil {
		t.Fatal(err)
	}
	back, err := IPv6ToMAC(v6)
	if err != nil {
		t.Fatalf("reverse of %s failed: %v", v6, err)
	}
	if back != mac {
		t.Errorf("round trip = %s want %s", back, mac)
	}
}

func TestIPv6ToMACRejectsPrivacyAddr(t *testing.T) {
	// RFC 4941 randomised address has no ff:fe marker at bytes 11-12.
	if _, err := IPv6ToMAC("fe80::1234:5678:9abc:def0"); err == nil {
		t.Error("expected error for non-EUI-64 address")
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := ExpandCIDR("192.168.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 || ips[0] != "192.168.0.0" || ips[3] != "192.168.0.3" {
		t.Errorf("unexpected expansion: %v", ips)
	}

	single, err := ExpandCIDR("10.0.0.7/32")
	if err != nil || len(single) != 1 || single[0] != "10.0.0.7" {
		t.Errorf("/32 expansion wrong: %v %v", single, err)
	}

	if _, err := ExpandCIDR("10.0.0.0/8"); err == nil {
		t.Error("expected refusal to expand huge range")
	}
	if _, err := ExpandCIDR("notacidr"); err == nil {
		t.Error("expected error for invalid cidr")
	}
}

func TestPortSpec(t *testing.T) {
	ports, err := PortSpec("22,80,443")
	if err != nil || len(ports) != 3 {
		t.Fatalf("simple list: %v %v", ports, err)
	}
	ports, err = PortSpec("10-12,20")
	if err != nil || len(ports) != 4 || ports[0] != 10 || ports[3] != 20 {
		t.Fatalf("range: %v %v", ports, err)
	}
	dupes, err := PortSpec("80,80,80")
	if err != nil || len(dupes) != 1 {
		t.Fatalf("dupes not deduped: %v", dupes)
	}
	if _, err := PortSpec("99999"); err == nil {
		t.Error("expected error for out-of-range port")
	}
	if _, err := PortSpec("5-3"); err == nil {
		t.Error("expected error for inverted range")
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(1000, 100)
	start := time.Now()
	for i := 0; i < 200; i++ {
		limiter.Wait()
	}
	elapsed := time.Since(start)
	// 200 tokens at burst 100 => ~100ms minimum
	if elapsed < 80*time.Millisecond {
		t.Errorf("rate limiter did not throttle: %v", elapsed)
	}
	unlimited := NewRateLimiter(0, 1)
	start = time.Now()
	for i := 0; i < 1000; i++ {
		unlimited.Wait()
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("unlimited limiter blocked")
	}
}

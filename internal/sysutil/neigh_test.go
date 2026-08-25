package sysutil

import "testing"

func TestParseNeighLines(t *testing.T) {
	out := `
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE
fe80::dead dev eth0  FAILED
::1 dev lo lladdr 00:00:00:00:00:00 PERMANENT
garbage line
`
	entries := ParseNeighLines(out)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.IP != "fe80::1" || e.MAC != "aa:bb:cc:dd:ee:ff" || !e.IsRouter || e.State != "REACHABLE" {
		t.Errorf("entry0 wrong: %+v", e)
	}
	if entries[2].MAC != "" && entries[2].State != "FAILED" && entries[2].State != "" {
		t.Errorf("failed entry wrong: %+v", entries[2])
	}
}

func TestParseArpPosix(t *testing.T) {
	out := `? (192.168.1.10) at ab:cd:ef:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.1) at 0:de:ad:be:ef:0 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]`
	entries := parseArpPosix(out)
	if len(entries) != 3 {
		t.Fatalf("want 3, got %d", len(entries))
	}
	if entries[0].IP != "192.168.1.10" || entries[0].MAC != "ab:cd:ef:12:34:56" {
		t.Errorf("entry0: %+v", entries[0])
	}
	if entries[1].MAC != "00:de:ad:be:ef:00" {
		t.Errorf("normalisation failed: %+v", entries[1])
	}
	if entries[2].MAC != "" {
		t.Errorf("incomplete should have no mac: %+v", entries[2])
	}
}

func TestParseArpWindows(t *testing.T) {
	out := `
Interface: 192.168.1.5 --- 0xd
  Internet Address      Physical Address      Type
  192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic
  192.168.255.255       ff-ff-ff-ff-ff-ff     static`
	entries := parseArpWindows(out)
	if len(entries) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(entries), entries)
	}
	if entries[0].IP != "192.168.1.10" || entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("entry0: %+v", entries[0])
	}
}

func TestParseNdpBSD(t *testing.T) {
	out := `Neighbor                             Linklayer Address  Netif Expire    S Flags
fe80::1%en0                          f0:9f:c2:00:11:22  en0   23s       R R
2620:0:1234::5                       aa:bb:cc:dd:ee:ff  en0   permanent R`
	entries := parseNdpBSD(out)
	if len(entries) != 2 {
		t.Fatalf("want 2, got %d", len(entries))
	}
	if entries[0].IP != "fe80::1" { // zone stripped
		t.Errorf("zone not stripped: %q", entries[0].IP)
	}
	if entries[0].MAC != "f0:9f:c2:00:11:22" || !entries[0].IsRouter {
		t.Errorf("entry0: %+v", entries[0])
	}
	if entries[1].IsRouter {
		t.Errorf("permanent host entry flagged as router: %+v", entries[1])
	}
}

func TestParseNetshNeighbors(t *testing.T) {
	out := `
Internet Address              Physical Address         Type
-------------------------------------------- --------
  fe80::1%12                   aa-bb-cc-dd-ee-ff       Reachable
  fd00::5                      unreachable            Unreachable
`
	entries := parseNetshNeighbors(out)
	if len(entries) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(entries), entries)
	}
	if entries[0].IP != "fe80::1" || entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("entry0: %+v", entries[0])
	}
	if entries[1].MAC != "" {
		t.Errorf("unreachable should have empty mac: %+v", entries[1])
	}
}

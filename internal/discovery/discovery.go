// Package discovery finds dual-stack neighbours and correlates their IPv4 and
// IPv6 identities. Strategy (in order):
//
//  1. ARP sweep of the IPv4 range (native raw-socket ARP on Linux/root,
//     arp-scan binary otherwise)               -> ip4 -> mac
//  2. Kernel NDP table read                    -> ip6 -> mac  (primary source,
//     covers RFC 4941 privacy addresses)
//  3. ICMPv6 all-nodes multicast ping ff02::1  -> live link-locals/GUAs
//  4. EUI-64 derivation from MAC               -> *fallback* candidate, only
//     attached after a successful unicast probe
//
// Optional enrichments: mDNS/DNS-SD name correlation and router-advertisement
// solicitation (prefix inventory).
package discovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"ipv4Bypass/internal/model"
	"ipv4Bypass/internal/netutil"
	"ipv4Bypass/internal/sysutil"
)

// ifaceInfo aliases the sysutil type so platform files need no extra import.
type ifaceInfo = sysutil.InterfaceInfo

var errUnsupportedPlatform = errors.New("unsupported platform")

func isLinux() bool { return runtime.GOOS == "linux" }

// Options configures a discovery run.
type Options struct {
	Iface      *sysutil.InterfaceInfo
	CIDR       string
	Privileged bool
	EnableMDNS bool
	EnableRA   bool
	ArpScanBin string // path to external arp-scan, "" = unavailable
	Logger     *log.Logger
}

// Result carries correlated hosts plus metadata gathered along the way.
type Result struct {
	Hosts      []*model.Host
	Warnings   []string
	RAPrefixes []string
	Routers    []string
	MDNSNames  map[string]string // ip -> mdns hostname

	vendorByIP map[string]string // from external arp-scan output
}

func (r *Result) warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.Warnings = append(r.Warnings, msg)
	if logger != nil {
		logger.Printf("[!] %s", msg)
	}
}

var logger *log.Logger

// Run executes the full discovery pipeline.
func Run(ctx context.Context, opts Options) (*Result, error) {
	logger = opts.Logger
	res := &Result{MDNSNames: map[string]string{}}
	if opts.Logger == nil {
		logger = log.Default()
	}

	// ---- 0. Kernel neighbour table (always, both families) -------------
	// Read whatever the kernel already knows before we start our own sweep.
	// This captures STALE entries from prior traffic that a fresh sweep
	// window might miss — the primary cause of IPv6↔IPv4 correlation gaps.
	kernelNeigh, err := sysutil.ReadCombinedNeighTable(opts.Iface.Name)
	if err != nil {
		res.warnf("cannot read kernel neigh table: %v", err)
	} else {
		logger.Printf("[*] kernel neigh table: %d entries (pre-sweep seed)", len(kernelNeigh))
	}

	// ---- 1. IPv4 ARP sweep --------------------------------------------
	arpPairs := map[string]string{} // ip4 -> mac
	nativeFailed := false
	if opts.Privileged && isLinux() {
		m, err := arpSweepNative(opts.Iface, opts.CIDR)
		if err != nil {
			nativeFailed = true
			res.warnf("native ARP sweep failed (%v); trying fallbacks", err)
		} else {
			arpPairs = m
			logger.Printf("[*] native ARP sweep: %d replies", len(m))
		}
	}
	if len(arpPairs) == 0 && opts.ArpScanBin != "" {
		m, vendors, err := arpScanExternal(opts.ArpScanBin, opts.Iface.Name, opts.CIDR)
		if err != nil {
			res.warnf("external arp-scan failed: %v", err)
		} else {
			arpPairs = m
			res.vendorByIP = vendors
			logger.Printf("[*] arp-scan found %d hosts", len(m))
		}
	}
	if len(arpPairs) == 0 && !nativeFailed && !(opts.Privileged && isLinux()) && opts.ArpScanBin == "" {
		res.warnf("no privileged ARP method available; relying on neighbour tables + active probes")
	}

	// Active fallback: make sure quiet hosts appear in the kernel ARP table.
	if len(arpPairs) == 0 {
		reachable := probeReachable(ctx, opts)
		if len(reachable) > 0 {
			logger.Printf("[*] active probe found %d live IPv4 hosts", len(reachable))
		}
		time.Sleep(200 * time.Millisecond) // let kernel populate cache
		if tab, err := sysutil.ReadARPTable(); err == nil {
			want := map[string]bool{}
			for _, ip := range reachable {
				want[ip] = true
			}
			for _, e := range tab {
				if e.MAC != "" && (want[e.IP] || inRange(opts.CIDR, e.IP)) {
					arpPairs[e.IP] = e.MAC
				}
			}
		} else {
			res.warnf("cannot read ARP table: %v", err)
		}
	}

	// ---- 2. NDP table --------------------------------------------------
	var ndp []sysutil.NeighEntry
	if tab, err := sysutil.ReadNDPTable(); err != nil {
		res.warnf("cannot read NDP table: %v", err)
	} else {
		ndp = tab
		logger.Printf("[*] NDP table: %d entries", len(ndp))
	}

	// ---- 3. ICMPv6 multicast discovery ---------------------------------
	live6, err := ping6Multicast(ctx, opts.Iface)
	if err != nil {
		res.warnf("ICMPv6 multicast discovery failed: %v (NDP/EUI-64 paths still active)", err)
	} else {
		logger.Printf("[*] ff02::1 responders: %d", len(live6))
	}

	// ---- correlate ------------------------------------------------------
	corr := newCorrelator(opts, res)
	// Seed from the kernel table first — this gives us STALE entries and
	// cross-links MACs to IPv4 addresses that the active ARP sweep missed.
	corr.seedKernelNeigh(kernelNeigh)
	corr.seedARP(arpPairs)
	corr.applyNDP(ndp)
	corr.applyMulticast(live6)
	corr.eui64Fallback(ctx)

	res.Hosts = corr.hosts()

	// ---- optional enrichment -------------------------------------------
	if opts.EnableRA && opts.Privileged {
		pfx, routers, err := solicitRA(opts.Iface, 3500*time.Millisecond)
		if err != nil {
			res.warnf("router solicitation failed: %v", err)
		} else {
			res.RAPrefixes, res.Routers = pfx, routers
		}
	} else if opts.EnableRA {
		res.warnf("--ra requires privileges; skipped")
	}

	if opts.EnableMDNS {
		names, err := mdnsDiscover(opts.Iface, 3*time.Second)
		if err != nil {
			res.warnf("mDNS discovery failed: %v", err)
		} else {
			res.MDNSNames = names
			for _, h := range res.Hosts {
				addrs := append([]string{}, h.IPv6...)
				if h.IPv4 != "" {
					addrs = append(addrs, h.IPv4)
				}
				for _, a := range addrs {
					if n, ok := names[netutil.StripZone(a)]; ok && h.MDNSName == "" {
						h.MDNSName = n
					}
				}
			}
			logger.Printf("[*] mDNS names resolved for %d hosts", countMDNSEd(res.Hosts))
		}
	}

	sort.Slice(res.Hosts, func(i, j int) bool { return res.Hosts[i].String() < res.Hosts[j].String() })
	return res, nil
}

func countMDNSEd(hosts []*model.Host) int {
	n := 0
	for _, h := range hosts {
		if h.MDNSName != "" {
			n++
		}
	}
	return n
}

func inRange(cidr, ip string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(net.ParseIP(netutil.StripZone(ip)))
}

// ---------------------------------------------------------------------

// correlator merges evidence from all sources into model.Host records.
type correlator struct {
	opts     Options
	res      *Result
	byMAC    map[string]*model.Host
	orphan   []*model.Host // v6 hosts whose MAC is unknown
	selfMAC  string
	selfIP4  string
	selfIPv6 map[string]bool // all IPv6 addresses belonging to our own interface
}

type vendorCarrier = *Result

func newCorrelator(opts Options, res *Result) *correlator {
	selfV6 := make(map[string]bool)
	for _, a := range opts.Iface.IPv6All {
		selfV6[netutil.StripZone(a)] = true
	}
	// Also derive the link-local from our MAC via EUI-64 so we catch our
	// own fe80:: even when it isn't listed in IPv6All (link-locals are
	// sometimes omitted by the OS address enumerator).
	if ll, err := netutil.MACToEUI64(opts.Iface.HWAddr); err == nil {
		selfV6[ll] = true
	}
	return &correlator{
		opts:     opts,
		res:      res,
		byMAC:    map[string]*model.Host{},
		selfMAC:  netutil.NormalizeMAC(opts.Iface.HWAddr),
		selfIP4:  opts.Iface.IPv4,
		selfIPv6: selfV6,
	}
}

func (c *correlator) hostForMAC(mac string) *model.Host {
	norm := netutil.NormalizeMAC(mac)
	if norm == "" {
		return nil
	}
	if h, ok := c.byMAC[norm]; ok {
		return h
	}
	if norm == c.selfMAC {
		return nil // never report ourselves
	}
	h := &model.Host{MAC: norm}
	if v, ok := ouiVendors[norm[:8]]; ok {
		h.Vendor = v
	}
	c.byMAC[norm] = h
	return h
}

// seedKernelNeigh processes the combined kernel neighbour table (v4 + v6) and
// pre-populates host records so that subsequent seedARP / applyNDP calls can
// link addresses to MACs they would otherwise miss.
//
// For each entry:
//   - IPv4 + MAC  → same as seedARP: creates/finds host by MAC, fills IPv4
//   - IPv6 + MAC  → creates/finds host by MAC, adds scoped IPv6
//   - IPv6 no MAC → orphan (handled by applyNDP later, duplicates skipped)
//
// FAILED/INCOMPLETE entries (no MAC) for IPv4 are skipped — they add noise
// without usable correlation data.
func (c *correlator) seedKernelNeigh(entries []sysutil.NeighEntry) {
	for _, e := range entries {
		if e.MAC == "" {
			continue // incomplete/failed — no MAC to correlate on
		}
		ip := netutil.StripZone(e.IP)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsLoopback() {
			continue
		}
		isV4 := parsed.To4() != nil
		if isV4 {
			// IPv4 entry: same logic as seedARP
			if ip == c.selfIP4 || netutil.NormalizeMAC(e.MAC) == c.selfMAC {
				continue
			}
			if !inRange(c.opts.CIDR, ip) {
				continue // outside target range
			}
			h := c.hostForMAC(e.MAC)
			if h == nil {
				continue
			}
			if h.IPv4 == "" {
				h.IPv4 = ip
			}
		} else {
			// IPv6 entry: add scoped address to host keyed by MAC
			if netutil.NormalizeMAC(e.MAC) == c.selfMAC {
				continue
			}
			scoped := ip
			if parsed.IsLinkLocalUnicast() {
				scoped = netutil.Scoped(ip, c.opts.Iface.Name)
			}
			h := c.hostForMAC(e.MAC)
			if h == nil {
				continue
			}
			h.IPv6 = appendUnique(h.IPv6, scoped)
		}
	}
}

func (c *correlator) seedARP(pairs map[string]string) {
	vendors := c.res.vendorByIP
	for ip, mac := range pairs {
		if ip == c.selfIP4 || netutil.NormalizeMAC(mac) == c.selfMAC {
			continue
		}
		h := c.hostForMAC(mac)
		if h == nil {
			continue
		}
		if h.IPv4 == "" {
			h.IPv4 = ip
		}
		if h.Vendor == "" {
			if v, ok := vendors[ip]; ok && v != "" {
				h.Vendor = v
			}
		}
	}
}

// isSelfIPv6 returns true if addr (with or without zone) belongs to our interface.
func (c *correlator) isSelfIPv6(addr string) bool {
	return c.selfIPv6[netutil.StripZone(addr)]
}

func (c *correlator) applyNDP(entries []sysutil.NeighEntry) {
	for _, e := range entries {
		ip := netutil.StripZone(e.IP)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() != nil || parsed.IsLoopback() {
			continue
		}
		scoped := ip
		if parsed.IsLinkLocalUnicast() {
			scoped = netutil.Scoped(ip, c.opts.Iface.Name)
		}
		// Skip our own interface addresses.
		if c.isSelfIPv6(ip) {
			continue
		}
		var h *model.Host
		if e.MAC != "" {
			h = c.hostForMAC(e.MAC)
			if h == nil {
				continue
			}
		}
		if h == nil {
			// No MAC: maybe an existing host already owns this address, else orphan.
			h = c.hostOwningAddr(scoped)
			if h == nil {
				h = &model.Host{}
				c.orphan = append(c.orphan, h)
			}
		}
		if e.IsRouter {
			c.res.Routers = appendUnique(c.res.Routers, scoped)
		}
		h.IPv6 = appendUnique(h.IPv6, scoped)
	}
}

func (c *correlator) hostOwningAddr(addr string) *model.Host {
	base := netutil.StripZone(addr)
	for _, h := range c.all() {
		for _, a := range h.IPv6 {
			if netutil.StripZone(a) == base {
				return h
			}
		}
	}
	return nil
}

func (c *correlator) applyMulticast(live []string) {
	for _, addr := range live {
		base := netutil.StripZone(addr)
		if ip := net.ParseIP(base); ip == nil || ip.IsLoopback() {
			continue
		}
		// Skip our own interface addresses — we always respond to ff02::1.
		if c.isSelfIPv6(base) {
			continue
		}
		if c.hostOwningAddr(addr) != nil {
			continue
		}
		if mac, err := netutil.IPv6ToMAC(base); err == nil {
			if h := c.hostForMAC(mac); h != nil {
				scoped := netutil.Scoped(addr, c.opts.Iface.Name)
				h.IPv6 = appendUnique(h.IPv6, scoped)
				continue
			}
		}
		// Privacy-extension address with no NDP row: keep as orphan so it is
		// still scanned rather than dropped.
		scoped := netutil.Scoped(addr, c.opts.Iface.Name)
		h := &model.Host{IPv6: []string{scoped}}
		c.orphan = append(c.orphan, h)
	}
}

// eui64Fallback derives fe80::<EUI-64> for hosts lacking any IPv6 address and
// attaches it only after an actual unicast probe answers. It is deliberately
// the LAST strategy because RFC 4941 randomised addresses break the mapping.
func (c *correlator) eui64Fallback(ctx context.Context) {
	for _, h := range c.byMAC {
		if len(h.IPv6) > 0 {
			continue
		}
		cand, err := netutil.MACToEUI64(h.MAC)
		if err != nil {
			continue
		}
		scoped := netutil.Scoped(cand, c.opts.Iface.Name)
		if !ping6Once(ctx, scoped) {
			continue
		}
		h.IPv6 = append(h.IPv6, scoped)
		if logger != nil {
			logger.Printf("[*] EUI-64 fallback confirmed %s for %s", scoped, h.MAC)
		}
	}
}

func (c *correlator) all() []*model.Host {
	out := make([]*model.Host, 0, len(c.byMAC)+len(c.orphan))
	for _, h := range c.byMAC {
		out = append(out, h)
	}
	out = append(out, c.orphan...)
	return out
}

// hosts finalises the list, dropping empty records and self.
func (c *correlator) hosts() []*model.Host {
	var out []*model.Host
	for _, h := range c.all() {
		if h.IPv4 == "" && len(h.IPv6) == 0 {
			continue
		}
		if h.IPv4 == c.selfIP4 {
			continue
		}
		out = append(out, h)
	}
	return out
}

func appendUnique(list []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return list
	}
	for _, x := range list {
		if netutil.StripZone(x) == netutil.StripZone(s) {
			return list
		}
	}
	return append(list, s)
}

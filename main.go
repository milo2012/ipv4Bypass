// ipv4Bypass — find services exposed on IPv6 that are firewalled on IPv4.
//
// The tool discovers dual-stack neighbours on the local network (ARP + NDP +
// ICMPv6 multicast, EUI-64 only as a verified fallback), then scans both
// address families concurrently and reports differences with severity tags.
//
// This is the Go rewrite of bypass.py; see README.md for usage.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"ipv4Bypass/internal/discovery"
	"ipv4Bypass/internal/model"
	"ipv4Bypass/internal/netutil"
	"ipv4Bypass/internal/report"
	"ipv4Bypass/internal/scanner"
	"ipv4Bypass/internal/sysutil"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	iface    string
	cidr     string
	portSpec string
	topPorts int
	timing   int
	conc     int
	rate     float64
	timeout  time.Duration
	udp      bool
	noBanner bool
	mdns     bool
	ra       bool
	jsonPath string
	ndjson   string
	csvPath  string
	strict   bool
	self     bool
	verbose  bool
}

const usageHeader = `Scans dual-stack hosts and reports ports open on IPv6 but blocked on IPv4
(and the inverse), with service fingerprinting and severity ratings.`

func main() {
	log.SetFlags(0)
	cfg := parseFlags()
	if cfg == nil {
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	started := time.Now()
	printBanner()

	// ---- privilege detection (fail early, not mid-run) -----------------
	privileged := sysutil.IsPrivileged()
	var warnings []string
	arpScanBin := ""
	if p := sysutil.LookPath("arp-scan", "/usr/sbin/arp-scan"); p != "" {
		arpScanBin = p
	}
	switch {
	case privileged:
		log.Printf("[*] Privileges: yes (raw ARP/ICMP available)")
	default:
		msg := sysutil.PrivilegeHint()
		if arpScanBin != "" {
			warnings = append(warnings,
				fmt.Sprintf("running unprivileged; ARP discovery via %s only, ICMP probes disabled", arpScanBin))
			warnings = append(warnings, msg+" for best coverage")
			log.Printf("[*] Privileges: no — using arp-scan binary at %s; ICMP disabled", arpScanBin)
		} else {
			warnings = append(warnings,
				"running unprivileged without arp-scan: falling back to TCP-connect host discovery and neighbour tables")
			warnings = append(warnings, msg)
			log.Printf("[*] Privileges: no — reduced-capability mode (TCP-connect discovery)")
			if cfg.strict {
				log.Printf("[-] --strict set: refusing to run degraded scan.")
				os.Exit(2)
			}
		}
	}

	// ---- interface ------------------------------------------------------
	ifaceInfo, err := sysutil.GetInterface(cfg.iface)
	if err != nil {
		log.Printf("[-] %v", err)
		os.Exit(1)
	}
	v6Note := ""
	if len(ifaceInfo.IPv6All) > 0 {
		v6Note = " / " + ifaceInfo.IPv6All[0]
	} else {
		warnings = append(warnings, fmt.Sprintf("interface %s has no global IPv6 address; IPv6 reachability may be limited", cfg.iface))
	}
	log.Printf("[*] Using %s (%s%s)", ifaceInfo.Name, ifaceInfo.IPv4, v6Note)

	// ---- discovery -------------------------------------------------------
	dopts := discovery.Options{
		Iface:      ifaceInfo,
		CIDR:       cfg.cidr,
		Privileged: privileged,
		EnableMDNS: cfg.mdns,
		EnableRA:   cfg.ra,
		ArpScanBin: arpScanBin,
		Logger:     log.Default(),
	}
	if !cfg.verbose {
		// keep discovery chatter minimal unless verbose
		dopts.Logger = quietLogger()
	}
	dres, err := discovery.Run(ctx, dopts)
	if err != nil {
		log.Printf("[-] discovery failed: %v", err)
		os.Exit(1)
	}
	warnings = append(warnings, dres.Warnings...)
	if len(dres.RAPrefixes) > 0 {
		log.Printf("[*] RA prefixes: %s | routers: %s",
			strings.Join(dres.RAPrefixes, ", "), strings.Join(dres.Routers, ", "))
	}
	scannable := 0
	for _, h := range dres.Hosts {
		if h.IPv4 != "" || h.PrimaryIPv6() != "" {
			scannable++
		}
	}
	if cfg.self && ifaceInfo.IPv4 != "" {
		scopedV6 := make([]string, 0, len(ifaceInfo.IPv6All))
		for _, a := range ifaceInfo.IPv6All {
			scopedV6 = append(scopedV6, netutil.Scoped(a, ifaceInfo.Name))
		}
		selfHost := &model.Host{
			MAC:    netutil.NormalizeMAC(ifaceInfo.HWAddr),
			IPv4:   ifaceInfo.IPv4,
			IPv6:   scopedV6,
			Vendor: "this machine",
		}
		dres.Hosts = append(dres.Hosts, selfHost)
		scannable++
	}
	log.Printf("[*] Correlated dual-stack hosts: %d/%d", scannable, len(dres.Hosts))

	// ---- scanning --------------------------------------------------------
	profile := timingProfile(cfg.timing)
	if cfg.rate > 0 {
		profile.rate = cfg.rate
	}
	if cfg.timeout > 0 {
		profile.connectTimeout = cfg.timeout
	}
	tcpPorts, err := selectTCPPorts(cfg)
	if err != nil {
		log.Printf("[-] %v", err)
		os.Exit(1)
	}
	log.Printf("[*] Scanning %d TCP ports per stack (T%d: %.0f pps cap, %v connect timeout), concurrency %d",
		len(tcpPorts), cfg.timing, profile.rate, profile.connectTimeout, cfg.conc)

	var ndjsonFile *os.File
	if cfg.ndjson != "" {
		f, err := openOut(cfg.ndjson)
		if err != nil {
			log.Printf("[-] %v", err)
			os.Exit(1)
		}
		ndjsonFile = f
		defer f.Close()
	}

	sopts := scanner.Options{
		Concurrency:    cfg.conc,
		Ports:          tcpPorts,
		UDPPorts:       scanner.TopUDP,
		EnableUDP:      cfg.udp,
		Banner:         !cfg.noBanner,
		ConnectTimeout: profile.connectTimeout,
		BannerTimeout:  profile.bannerTimeout,
		RatePerSec:     profile.rate,
		OnResult: func(res *model.HostResult) {
			if ndjsonFile != nil {
				report.NDJSON(ndjsonFile, res)
			}
			logHostResult(cfg.verbose, res)
		},
	}
	results := scanner.Run(ctx, dres.Hosts, sopts)

	// ---- report ----------------------------------------------------------
	rep := &model.Report{
		Interface: cfg.iface,
		CIDR:      cfg.cidr,
		Hosts:     results,
		Warnings:  warnings,
		Stats: model.Stats{
			StartedAt:  started,
			HostsFound: len(dres.Hosts),
			Findings:   map[model.Severity]int{},
		},
	}
	for _, r := range results {
		rep.Stats.HostsScanned++
		rep.Stats.OpenV4TCP += len(r.Open["v4:tcp"])
		rep.Stats.OpenV6TCP += len(r.Open["v6:tcp"])
		rep.Stats.OpenV4UDP += len(r.Open["v4:udp"])
		rep.Stats.OpenV6UDP += len(r.Open["v6:udp"])
	}
	rep.Findings = report.Analyze(results)
	for _, f := range rep.Findings {
		rep.Stats.Findings[f.Severity]++
	}
	rep.Stats.DurationSecs = time.Since(started).Seconds()

	out := report.NewText()
	out.Verbose = cfg.verbose
	out.Render(rep)

	if cfg.jsonPath != "" {
		if err := report.WriteJSON(cfg.jsonPath, rep); err != nil {
			log.Printf("[-] json output: %v", err)
		} else {
			log.Printf("[*] JSON report written to %s", cfg.jsonPath)
		}
	}
	if cfg.csvPath != "" {
		if err := report.WriteCSV(cfg.csvPath, rep); err != nil {
			log.Printf("[-] csv output: %v", err)
		} else {
			log.Printf("[*] CSV findings written to %s", cfg.csvPath)
		}
	}
}

// ------------------------------------------------------------------------

type timing struct {
	rate           float64
	connectTimeout time.Duration
	bannerTimeout  time.Duration
}

func timingProfile(t int) timing {
	switch t {
	case 0:
		return timing{rate: 5, connectTimeout: 5 * time.Second, bannerTimeout: 4 * time.Second}
	case 1:
		return timing{rate: 15, connectTimeout: 4 * time.Second, bannerTimeout: 3 * time.Second}
	case 2:
		return timing{rate: 100, connectTimeout: 2 * time.Second, bannerTimeout: 2 * time.Second}
	case 4:
		return timing{rate: 2000, connectTimeout: 600 * time.Millisecond, bannerTimeout: 900 * time.Millisecond}
	case 5:
		return timing{rate: 8000, connectTimeout: 400 * time.Millisecond, bannerTimeout: 700 * time.Millisecond}
	default: // 3 normal
		return timing{rate: 500, connectTimeout: time.Second, bannerTimeout: 1200 * time.Millisecond}
	}
}

func selectTCPPorts(cfg *config) ([]int, error) {
	if cfg.portSpec != "" {
		return netutil.PortSpec(cfg.portSpec)
	}
	switch cfg.topPorts {
	case 100:
		return scanner.TopTCP100, nil
	case 65535:
		all := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			all = append(all, p)
		}
		return all, nil
	default: // 1000
		return scanner.TopTCP1000(), nil
	}
}

func logHostResult(verbose bool, res *model.HostResult) {
	if !verbose || res == nil {
		return
	}
	n4, n6 := len(res.Open["v4:tcp"]), len(res.Open["v6:tcp"])
	log.Printf("[*] scanned %-15s v4:%dtcp v6:%dtcp (%dms)",
		res.Host.IPv4, n4, n6, res.DurationMs)
}

func printBanner() {
	fmt.Fprintf(os.Stderr, "ipv4Bypass/go %s — dual-stack firewall bypass auditor\n", version)
}

func quietLogger() *log.Logger {
	if devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		return log.New(devnull, "", 0)
	}
	return log.New(os.Stderr, "", 0)
}

func openOut(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdout, nil
	}
	return os.Create(path)
}

func parseFlags() *config {
	var cfg config
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ipv4Bypass %s — dual-stack firewall bypass auditor\n\n%s\n\n%s\n",
			version, usageHeader, flagLine())
	}
	flag.StringVar(&cfg.iface, "i", "", "network interface (required, e.g. eth0)")
	flag.StringVar(&cfg.cidr, "r", "", "IPv4 target range CIDR (required, e.g. 192.168.1.0/24)")
	flag.StringVar(&cfg.portSpec, "p", "", "TCP ports spec, e.g. \"22,80,443\" or \"1-1024\" (overrides --top-ports)")
	flag.IntVar(&cfg.topPorts, "top-ports", 1000, "curated TCP port set size: 100, 1000 or 65535 (all)")
	flag.IntVar(&cfg.timing, "T", 3, "timing template 0(paranoid)..5(insane) — sets rate+timeouts")
	flag.IntVar(&cfg.conc, "c", 10, "hosts scanned concurrently")
	flag.Float64Var(&cfg.rate, "rate", 0, "global probe rate cap per second (overrides -T rate)")
	flag.DurationVar(&cfg.timeout, "timeout", 0, "TCP connect timeout override (e.g. 800ms)")
	flag.BoolVar(&cfg.udp, "udp", false, "also probe common UDP services on both stacks")
	flag.BoolVar(&cfg.noBanner, "no-banner", false, "skip banner grabbing / fingerprinting")
	flag.BoolVar(&cfg.mdns, "mdns", true, "correlate mDNS/DNS-SD hostnames")
	flag.BoolVar(&cfg.ra, "ra", false, "send router solicitation to inventory RA prefixes (root/linux)")
	flag.StringVar(&cfg.jsonPath, "json", "", "write full JSON report to file")
	flag.StringVar(&cfg.ndjson, "ndjson", "", "stream one JSON object per scanned host to file ('-' = stdout)")
	flag.StringVar(&cfg.csvPath, "csv", "", "write findings as CSV to file")
	flag.BoolVar(&cfg.strict, "strict", false, "exit instead of running in reduced-capability mode when unprivileged")
	flag.BoolVar(&cfg.self, "self", false, "include this machine itself in the scan (useful to validate)")
	flag.BoolVar(&cfg.verbose, "v", false, "verbose progress logging")
	flag.Parse()

	if cfg.iface == "" || cfg.cidr == "" {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\nerror: both -i <interface> and -r <cidr> are required")
		return nil
	}
	if _, _, err := net.ParseCIDR(strings.TrimSpace(cfg.cidr)); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid CIDR %q: %v\n", cfg.cidr, err)
		return nil
	}
	if cfg.conc < 1 {
		cfg.conc = 1
	}
	if cfg.timing < 0 || cfg.timing > 5 {
		cfg.timing = 3
	}
	if cfg.topPorts != 100 && cfg.topPorts != 1000 && cfg.topPorts != 65535 {
		cfg.topPorts = 1000
	}
	return &cfg
}

func flagLine() string {
	return `Usage: ipv4Bypass -i <iface> -r <cidr> [options]

Options:
  -i string            network interface (required)
  -r string            IPv4 target CIDR (required)
  -p string            TCP port list/ranges ("22,80,443", "1-1024")
  --top-ports int      curated port set: 100 | 1000 | 65535 (default 1000)
  -T int               timing template 0-5 (default 3 normal)
  -c int               concurrent host scans (default 10)
  --rate float         max probes/sec across all workers
  --timeout duration   TCP connect timeout override
  --udp                enable UDP service probing
  --no-banner          disable banner grabbing
  --mdns               mDNS hostname correlation (default true)
  --ra                 router solicitation / prefix inventory (root, linux)
  --json string        write full JSON report
  --ndjson string      stream host results as NDJSON ('-' for stdout)
  --csv string         write findings CSV
  --strict             refuse degraded unprivileged runs
  --self               include this machine in the scan
  -v                   verbose logging`
}

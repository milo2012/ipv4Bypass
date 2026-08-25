// Package scanner performs concurrent dual-stack port scanning with banner
// grabbing, UDP service probes and reverse-DNS resolution. A worker pool
// bounds host-level parallelism and a global token bucket caps packet rate so
// scans can be tuned for IDS-sensitive environments.
package scanner

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipv4Bypass/internal/model"
	"ipv4Bypass/internal/netutil"
)

// Options controls a scan run.
type Options struct {
	Concurrency    int   // hosts scanned in parallel
	Ports          []int // TCP ports to probe
	UDPPorts       []int // UDP ports to probe (when EnableUDP)
	EnableUDP      bool
	Banner         bool                    // grab banners / fingerprints on open TCP ports
	ConnectTimeout time.Duration           // per-probe connect timeout
	BannerTimeout  time.Duration           // per-banner read timeout
	RatePerSec     float64                 // global probe rate cap (<=0 = unlimited)
	OnResult       func(*model.HostResult) // streamed per completed host
	Logger         *log.Logger
}

// Run scans every host concurrently and returns results in input order.
func Run(ctx context.Context, hosts []*model.Host, opts Options) []*model.HostResult {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	limiter := netutil.NewRateLimiter(opts.RatePerSec, int(opts.RatePerSec))
	results := make([]*model.HostResult, len(hosts))

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < opts.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				res := scanHost(ctx, hosts[idx], opts, limiter)
				results[idx] = res
				if opts.OnResult != nil {
					opts.OnResult(res)
				}
			}
		}()
	}
	for i := range hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// scanHost scans both stacks of one host.
func scanHost(ctx context.Context, h *model.Host, opts Options, limiter *netutil.RateLimiter) *model.HostResult {
	start := time.Now()
	res := &model.HostResult{Host: *h, ScannedAt: start, Open: map[string][]model.Service{}}
	open := res.OpenMap()

	var wg sync.WaitGroup
	targets := map[model.Family]string{}
	if h.IPv4 != "" {
		targets[model.V4] = netutil.StripZone(h.IPv4)
	}
	if v6 := h.PrimaryIPv6(); v6 != "" {
		targets[model.V6] = netutil.StripZone(v6) // zone re-added when dialing LLs
	}

	for family, ip := range targets {
		f := family
		address := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanTCP(ctx, f, address, h, opts, limiter, open)
			if opts.EnableUDP && len(opts.UDPPorts) > 0 {
				scanUDP(ctx, f, address, h, opts, limiter, open)
			}
		}()
	}

	// PTR records for both families in parallel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		resolvePTR(h)
	}()

	wg.Wait()
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// dialAddr builds the dial target honouring IPv6 link-local zones.
func dialAddr(family model.Family, ip string, port int, h *model.Host) string {
	host := ip
	if family == model.V6 {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLinkLocalUnicast() {
			if z := zoneForHost(h); z != "" {
				host = ip + "%" + z
			}
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func zoneForHost(h *model.Host) string {
	for _, a := range h.IPv6 {
		if i := strings.IndexByte(a, '%'); i >= 0 {
			return a[i+1:]
		}
	}
	return ""
}

func scanTCP(ctx context.Context, family model.Family, ip string, h *model.Host,
	opts Options, limiter *netutil.RateLimiter, open map[string][]model.Service) {

	portCh := make(chan int, len(opts.Ports))
	for _, p := range opts.Ports {
		portCh <- p
	}
	close(portCh)

	var mu sync.Mutex
	var wg sync.WaitGroup
	workers := 96
	if workers > len(opts.Ports) {
		workers = len(opts.Ports)
	}
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}

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
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					continue // closed or filtered: not reported
				}
				svc := model.Service{Port: port, Protocol: model.TCP, State: model.StateOpen}
				if opts.Banner {
					banner, fp := grabBanner(conn, addr, port, opts.BannerTimeout)
					svc.Banner = truncate(banner, 256)
					svc.Fingerprint = firstNonEmpty(fp, wellKnownName(port))
				} else {
					svc.Fingerprint = wellKnownName(port)
				}
				conn.Close()
				mu.Lock()
				open[key(family, model.TCP)] = append(open[key(family, model.TCP)], svc)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func key(f model.Family, p model.Protocol) string { return string(f) + ":" + string(p) }

func resolvePTR(h *model.Host) {
	var wg sync.WaitGroup
	if h.IPv4 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names, err := net.LookupAddr(netutil.StripZone(h.IPv4))
			if err == nil && len(names) > 0 {
				h.HostnameV4 = strings.TrimSuffix(names[0], ".")
			}
		}()
	}
	if v6 := h.PrimaryIPv6(); v6 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names, err := net.LookupAddr(netutil.StripZone(v6))
			if err == nil && len(names) > 0 {
				h.HostnameV6 = strings.TrimSuffix(names[0], ".")
			}
		}()
	}
	wg.Wait()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", "\\n"))
	s = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"ipv4Bypass/internal/model"
)

// Text renders the human-readable terminal report. Colours degrade
// gracefully when stdout is not a TTY or NO_COLOR is set.
type Text struct {
	Out      io.Writer
	Color    bool // caller decides (TTY + NO_COLOR)
	Verbose  bool // show ALL dual-stack differences, not just IPv6 exposures
	ShowInfo bool // include info-severity findings in the findings section
}

func NewText() *Text {
	return &Text{Out: os.Stdout, Color: useColor(), ShowInfo: true}
}

// headlineCategories are what users of this tool fundamentally care about:
// services reachable via IPv6 that IPv4 policy blocks.
var headlineCategories = map[model.Category]bool{
	model.CatNewExposure:    true,
	model.CatUDPNewExposure: true,
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if fi, err := os.Stdout.Stat(); err == nil {
		return fi.Mode()&os.ModeCharDevice != 0
	}
	return false
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func (t *Text) paint(s model.Severity) string {
	if !t.Color {
		return ""
	}
	switch s {
	case model.SevCritical:
		return ansiBold + ansiRed
	case model.SevHigh:
		return ansiRed
	case model.SevMedium:
		return ansiYellow
	case model.SevLow:
		return ansiCyan
	default:
		return ""
	}
}

func (t *Text) header(msg string) { fmt.Fprintf(t.Out, "\n%s[*]%s %s\n", ansiBold, ansiReset, msg) }
func (t *Text) plain(msg string)  { fmt.Fprintln(t.Out, msg) }

// Render prints hosts, findings and stats.
func (t *Text) Render(rep *model.Report) {
	t.header(fmt.Sprintf("Interface %s (%s)", rep.Interface, rep.CIDR))
	for _, w := range rep.Warnings {
		fmt.Fprintf(t.Out, "%s[-]%s %s\n", ansiYellow, ansiReset, w)
	}

	t.header(fmt.Sprintf("Discovered hosts: %d", len(rep.Hosts)))
	for _, h := range rep.Hosts {
		fmt.Fprintln(t.Out, hostLine(h.Host))
	}

	t.header("Dual-stack port comparison")
	visible := make([]model.Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Severity == model.SevInfo && !t.ShowInfo {
			continue
		}
		if !t.Verbose && !headlineCategories[f.Category] {
			continue // missing-on-v6 / mismatch / PTR noise stays hidden
		}
		visible = append(visible, f)
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].Severity.Less(visible[j].Severity) })
	if len(visible) == 0 {
		t.plain("No IPv6-only exposures found — every open port on IPv6 is also open on IPv4.")
	}
	for _, f := range visible {
		paint := t.paint(f.Severity)
		reset := ansiReset
		if !t.Color {
			reset = ""
		}
		fmt.Fprintf(t.Out, "%s[%s]%s %s\t%s%s%s\n",
			paint, strings.ToUpper(string(f.Severity)), reset,
			hostIdent(f.Host), portLabel(f.Protocol, f.Port),
			categoryLabel(f.Category), f.Detail)
	}

	if !t.Verbose {
		if hidden := len(rep.Findings) - len(visible); hidden > 0 {
			fmt.Fprintf(t.Out, "\n%d additional difference(s) hidden (missing-on-IPv6, protocol mismatches, PTR).\nRun with -v to see the complete comparison.\n", hidden)
		}
	}

	t.header("Summary")
	s := rep.Stats
	fmt.Fprintf(t.Out,
		"Hosts found: %d | scanned: %d | open tcp v4/v6: %d/%d | open udp v4/v6: %d/%d\n",
		s.HostsFound, s.HostsScanned, s.OpenV4TCP, s.OpenV6TCP, s.OpenV4UDP, s.OpenV6UDP)

	shownCounts := map[model.Severity]int{}
	for _, f := range visible {
		shownCounts[f.Severity]++
	}
	for _, sev := range []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo} {
		if n := shownCounts[sev]; n > 0 {
			paint := t.paint(sev)
			reset := ansiReset
			if !t.Color {
				reset = ""
			}
			fmt.Fprintf(t.Out, "%s%s: %d%s  ", paint, sev, n, reset)
		}
	}
	fmt.Fprintln(t.Out)
	fmt.Fprintf(t.Out, "Scan completed in %.1fs\n", s.DurationSecs)
}

func hostIdent(h model.Host) string {
	id := h.IPv4
	if v6 := h.PrimaryIPv6(); v6 != "" {
		if id != "" {
			id += " "
		}
		id += "[" + model.StripZone(v6) + "]"
	}
	if id == "" {
		id = "(v6-only host)"
	}
	if h.MDNSName != "" {
		id += " (" + h.MDNSName + ")"
	} else if h.HostnameV4 != "" {
		id += " (" + h.HostnameV4 + ")"
	}
	return id
}

func hostLine(h model.Host) string {
	fields := []string{h.IPv4}
	v6 := h.PrimaryIPv6()
	if v6 != "" {
		fields = append(fields, "["+model.StripZone(v6)+"]")
	}
	if h.MAC != "" {
		fields = append(fields, strings.ToUpper(h.MAC))
	}
	if h.Vendor != "" {
		fields = append(fields, "("+h.Vendor+")")
	}
	name := firstStr(h.MDNSName, h.HostnameV4, h.HostnameV6)
	if name != "" {
		fields = append(fields, name)
	}
	return joinNonEmpty(fields, "\t")
}

var categoryLabels = map[model.Category]string{
	model.CatNewExposure:    " open on IPv6 but firewalled on IPv4",
	model.CatMissingOnV6:    " missing on IPv6 (open on IPv4 only)",
	model.CatProtoMismatch:  " protocol mismatch",
	model.CatUDPNewExposure: " open on IPv6 but firewalled on IPv4 (udp)",
	model.CatUDPMissingOnV6: " missing on IPv6 (udp)",
	model.CatPTRMismatch:    " ptr mismatch",
	model.CatGUAExposed:     " globally routable exposure",
}

func categoryLabel(c model.Category) string {
	if s, ok := categoryLabels[c]; ok {
		return s + ": "
	}
	return " " + string(c) + ": "
}

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinNonEmpty(fields []string, sep string) string {
	var out []string
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, sep)
}

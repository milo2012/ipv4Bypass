package discovery

import (
	"net"
	"os/exec"
	"strings"

	"ipv4Bypass/internal/netutil"
)

// runCmd executes a tool and returns its combined output.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func splitLines(s string) []string { return strings.Split(s, "\n") }

func splitFields(s string) []string {
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.Fields(s)
}

func normalizeMAC(s string) string { return netutil.NormalizeMAC(s) }

func isIPv4(s string) bool { return net.ParseIP(strings.TrimSpace(s)).To4() != nil }

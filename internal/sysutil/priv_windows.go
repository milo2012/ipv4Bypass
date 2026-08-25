//go:build windows

package sysutil

import (
	"os"
	"os/exec"
	"strings"
)

// IsPrivileged reports whether the process runs elevated (raw sockets,
// ICMP and neighbor-table access require an administrator token).
func IsPrivileged() bool {
	if os.Getenv("POWERSHELL") == "" {
		// `net session` succeeds only for elevated tokens; cheap and reliable.
		if out, err := exec.Command("net", "session").CombinedOutput(); err == nil && len(out) >= 0 {
			return true
		}
	}
	out, err := exec.Command("whoami", "/groups").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), "S-1-16-12288") // high integrity level
}

// PrivilegeHint returns a human hint for gaining privileges on this platform.
func PrivilegeHint() string {
	return "run from an elevated (Administrator) shell for ARP/ICMP features"
}

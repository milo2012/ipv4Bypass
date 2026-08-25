//go:build !windows

package sysutil

import "os"

// IsPrivileged reports whether the process can open raw sockets / send ICMP.
// On UNIX-likes this maps to root (or effective capabilities we do not probe).
func IsPrivileged() bool { return os.Geteuid() == 0 }

// PrivilegeHint returns a human hint for gaining privileges on this platform.
func PrivilegeHint() string {
	return "re-run with sudo (arp-scan, raw ARP/NDP and ICMP require root)"
}

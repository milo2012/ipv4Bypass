//go:build !linux

package discovery

import "time"

// solicitRA is Linux-only (raw ICMPv6 + multicast groups).
func solicitRA(_ *ifaceInfo, _ time.Duration) ([]string, []string, error) {
	return nil, nil, errUnsupportedPlatform
}

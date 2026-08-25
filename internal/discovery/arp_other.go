//go:build !linux

package discovery

// arpSweepNative is unavailable off Linux; callers fall back to external
// arp-scan or neighbour-table reads.
func arpSweepNative(_ *ifaceInfo, _ string) (map[string]string, error) {
	return nil, errUnsupportedPlatform
}

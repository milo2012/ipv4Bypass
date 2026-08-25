//go:build linux

package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"ipv4Bypass/internal/netutil"
)

// arpSweepNative sends raw ARP requests to every host in cidr over iface and
// collects replies. Requires root (AF_PACKET).
func arpSweepNative(iface *ifaceInfo, cidr string) (map[string]string, error) {
	targets, err := netutil.ExpandCIDR(cidr)
	if err != nil {
		return nil, err
	}
	localMAC, err := net.ParseMAC(iface.HWAddr)
	if err != nil || len(localMAC) != 6 {
		return nil, fmt.Errorf("interface %s has no usable MAC", iface.Name)
	}
	localIP := net.ParseIP(iface.IPv4).To4()
	if localIP == nil {
		return nil, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0806)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w (need root?)", err)
	}
	defer syscall.Close(fd)
	addr := &syscall.SockaddrLinklayer{Protocol: htons(0x0806), Ifindex: iface.Index, Halen: 6}
	if err := syscall.Bind(fd, addr); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	replies := struct {
		sync.Mutex
		m map[string]string
	}{m: map[string]string{}}

	stop := make(chan struct{})
	go func() { // reader
		buf := make([]byte, 1500)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				return
			}
			if n < 42 || binary.BigEndian.Uint16(buf[12:14]) != 0x0806 {
				continue
			}
			op := binary.BigEndian.Uint16(buf[20:22])
			if op != 2 { // reply
				continue
			}
			senderMAC := net.HardwareAddr(buf[22:28]).String()
			senderIP := net.IP(buf[28:32]).String()
			replies.Lock()
			replies.m[senderIP] = senderMAC
			replies.Unlock()
		}
	}()

	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	limiter := netutil.NewRateLimiter(2000, 256) // ARP requests/s cap
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], localMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1) // hardware type ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6                               // hw len
	frame[19] = 4                               // proto len
	binary.BigEndian.PutUint16(frame[20:22], 1) // request
	copy(frame[22:28], localMAC)
	copy(frame[28:32], localIP)

	for _, t := range targets {
		tp := net.ParseIP(t).To4()
		if tp == nil {
			continue
		}
		copy(frame[38:42], tp)
		limiter.Wait()
		if err := syscall.Sendto(fd, frame, 0, addr); err != nil {
			continue
		}
	}

	time.Sleep(1200 * time.Millisecond) // collect stragglers
	close(stop)
	return replies.m, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func isTimeout(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

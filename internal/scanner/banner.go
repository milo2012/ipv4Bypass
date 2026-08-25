package scanner

import (
	"bufio"
	"crypto/tls"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// wellKnownName maps ports to conventional service names (fallback only;
// banner-derived fingerprints always win).
func wellKnownName(port int) string {
	if name, ok := portNames[port]; ok {
		return name
	}
	return "tcp/" + strconv.Itoa(port)
}

var portNames = func() map[int]string {
	m := map[int]string{}
	for _, e := range []struct {
		name string
		port int
	}{
		{"ftp", 21}, {"ssh", 22}, {"telnet", 23}, {"smtp", 25}, {"domain", 53},
		{"tftp", 69}, {"http", 80}, {"kerberos", 88}, {"pop3", 110}, {"rpcbind", 111},
		{"ident", 113}, {"nntp", 119}, {"ntp", 123}, {"netbios-ns", 137},
		{"netbios-ssn", 139}, {"imap", 143}, {"bgp", 179}, {"ldap", 389},
		{"https", 443}, {"microsoft-ds", 445}, {"smtps", 465}, {"isakmp", 500},
		{"rtsp", 554}, {"submission", 587}, {"ipp", 631}, {"imaps", 993},
		{"pop3s", 995}, {"socks", 1080}, {"mysql", 3306}, {"ms-sql-s", 1433},
		{"pptp", 1723}, {"mqtt", 1883}, {"nfs", 2049}, {"docker", 2375},
		{"docker-tls", 2376}, {"http-alt", 8080}, {"http-alt-tls", 8443},
		{"postgresql", 5432}, {"vnc", 5900}, {"winrm", 5985}, {"redis", 6379},
		{"kubernetes", 6443}, {"irc", 6667}, {"weblogic", 7001}, {"memcached", 11211},
		{"mongodb", 27017}, {"rdp", 3389}, {"sip", 5060}, {"coap", 5683},
		{"ssdp", 1900}, {"mdns", 5353}, {"netbios-dgm", 138}, {"snmp", 161},
		{"snmptrap", 162}, {"syslog", 514}, {"printer", 9100}, {"elasticsearch", 9200},
	} {
		m[e.port] = e.name
	}
	return m
}()

// fingerprintRules classify captured banners into service names.
var fingerprintRules = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`^SSH-\d`), "ssh"},
	{regexp.MustCompile(`(?i)^HTTP/1\.[01] \d{3}`), "http"},
	{regexp.MustCompile(`(?i)server:\s*(apache|nginx|iis|microsoft-iis|lighttpd|caddy)`), "http"},
	{regexp.MustCompile(`(?i)^220[ -].*(ftp|vsftpd|proftpd|filezilla|pure-ftpd)`), "ftp"},
	{regexp.MustCompile(`^220[- ].*(SMTP|ESMTP|Postfix|Exim|Sendmail)`), "smtp"},
	{regexp.MustCompile(`^\+OK.*(POP3)`), "pop3"},
	{regexp.MustCompile(`^\* OK.*(IMAP)`), "imap"},
	{regexp.MustCompile(`^\xffSMB`), "smb"},
	{regexp.MustCompile(`^RFB \d{3}\.\d{3}`), "vnc"},
	{regexp.MustCompile(`^\xff\xfb|\xff\xfd`), "telnet"}, // IAC negotiation
	{regexp.MustCompile(`^-ERR|^PONG|^\+OK\r?$|redis_version`), "redis"},
	{regexp.MustCompile(`(?i)^RTSP/`), "rtsp"},
	{regexp.MustCompile(`(?i)^SIP/2\.0 \d{3}`), "sip"},
	{regexp.MustCompile(`(?i)bitcoin`), "bitcoin"},
	{regexp.MustCompile(`^\x16\x03[\x00-\x04]`), "tls"},
}

var httpishPorts = map[int]bool{
	80: true, 81: true, 443: true, 591: true, 3000: true, 4443: true,
	7080: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true,
	8443: true, 8888: true, 9000: true, 9090: true, 10000: true,
}

var tlsPorts = map[int]bool{
	443: true, 465: true, 563: true, 636: true, 989: true, 990: true,
	992: true, 993: true, 995: true, 5061: true, 8883: true, 8443: true,
	9443: true, 10000: true,
}

// grabBanner reads a service banner from an open connection. Server-speaks-
// first protocols are handled by plain reads; HTTP-ish ports get a HEAD probe;
// TLS ports are handshaken so certificate subjects enrich the fingerprint.
func grabBanner(conn net.Conn, addr string, port int, timeout time.Duration) (banner, fingerprint string) {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	host, _, _ := net.SplitHostPort(addr)

	// Phase 1: does the server speak first? Short peek window.
	conn.SetReadDeadline(time.Now().Add(peekWindow(timeout)))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		banner = strings.TrimSpace(string(buf[:n]))
		if fp := classifyBanner(banner); fp != "" {
			return banner, fp
		}
		// Got bytes but no match — still useful.
		return banner, ""
	}

	// Phase 2: active probing.
	switch {
	case tlsPorts[port]:
		return tlsProbe(conn, host)
	case httpishPorts[port]:
		return httpProbe(conn, host)
	default:
		// One more short read attempt in case of slow daemons.
		conn.SetReadDeadline(time.Now().Add(timeout))
		if n, err := conn.Read(buf); err == nil && n > 0 {
			banner = strings.TrimSpace(string(buf[:n]))
			return banner, classifyBanner(banner)
		}
	}
	return "", ""
}

func peekWindow(t time.Duration) time.Duration {
	p := t / 4
	if p > 400*time.Millisecond {
		p = 400 * time.Millisecond
	}
	if p < 150*time.Millisecond {
		p = 150 * time.Millisecond
	}
	return p
}

func httpProbe(conn net.Conn, host string) (string, string) {
	req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: ipv4Bypass/1.0\r\n\r\n"
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", ""
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	data := readAll(conn, 1024)
	fp := classifyBanner(data)
	if fp == "" && strings.HasPrefix(data, "HTTP/") {
		fp = "http"
	}
	return data, fp
}

func tlsProbe(conn net.Conn, host string) (string, string) {
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	tlsConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if err := tlsConn.Handshake(); err != nil {
		return "", ""
	}
	cs := tlsConn.ConnectionState()
	var sb strings.Builder
	sb.WriteString("tls")
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		sb.WriteString(" cn=" + cert.Subject.CommonName)
		if len(cert.DNSNames) > 0 {
			sb.WriteString(" san=" + strings.Join(cert.DNSNames[:minInt(3, len(cert.DNSNames))], ","))
		}
		if cert.Issuer.CommonName != "" {
			sb.WriteString(" issuer=" + cert.Issuer.CommonName)
		}
	}
	return sb.String(), "tls"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func readAll(conn net.Conn, limit int) string {
	br := bufio.NewReader(conn)
	var sb strings.Builder
	for sb.Len() < limit {
		chunk, err := br.ReadString('\n')
		sb.WriteString(chunk)
		if err != nil || chunk == "\r\n" {
			break
		}
	}
	return sb.String()
}

// classifyBanner applies the regex table; empty when unrecognised.
func classifyBanner(banner string) string {
	if banner == "" {
		return ""
	}
	head := banner
	if i := strings.IndexAny(banner, "\r\n"); i >= 0 {
		head = banner[:i]
	}
	for _, r := range fingerprintRules {
		if r.re.MatchString(head) || r.re.MatchString(banner) {
			return r.label
		}
	}
	return ""
}

package report

import (
	"testing"

	"ipv4Bypass/internal/model"
)

func mkHost() model.Host {
	return model.Host{
		MAC:        "aa:bb:cc:dd:ee:ff",
		IPv4:       "192.168.1.10",
		IPv6:       []string{"fe80::aabb:ccdd:eeff:1%eth0"},
		HostnameV4: "host.lan",
	}
}

func mkResult(h model.Host, v4tcp, v6tcp []model.Service) *model.HostResult {
	r := &model.HostResult{Host: h, Open: map[string][]model.Service{}}
	if v4tcp != nil {
		r.Open["v4:tcp"] = v4tcp
	}
	if v6tcp != nil {
		r.Open["v6:tcp"] = v6tcp
	}
	return r
}

func tcp(port int, fp string) model.Service {
	return model.Service{Port: port, Protocol: model.TCP, State: model.StateOpen, Fingerprint: fp}
}

func TestAnalyzeNewExposure(t *testing.T) {
	res := mkResult(mkHost(),
		[]model.Service{tcp(80, "http")},
		[]model.Service{tcp(80, "http"), tcp(22, "ssh")})
	findings := Analyze([]*model.HostResult{res})

	var found bool
	for _, f := range findings {
		if f.Category == model.CatNewExposure && f.Port == 22 {
			found = true
			// ssh is high-risk; bypass direction escalates to critical
			if f.Severity != model.SevCritical {
				t.Errorf("ssh new exposure should be critical, got %s", f.Severity)
			}
			if f.Detail == "" || f.Protocol != model.TCP {
				t.Errorf("detail/protocol wrong: %+v", f)
			}
		}
		if f.Category == model.CatMissingOnV6 && f.Port == 80 {
			t.Errorf("port open on both must not be missing_on_ipv6")
		}
	}
	if !found {
		t.Fatalf("new_exposure for port 22 not found: %+v", findings)
	}
}

func TestAnalyzeMissingOnV6(t *testing.T) {
	res := mkResult(mkHost(),
		[]model.Service{tcp(445, "microsoft-ds"), tcp(3389, "rdp")},
		nil)
	findings := Analyze([]*model.HostResult{res})
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Category != model.CatMissingOnV6 {
			t.Fatalf("wrong category %s", f.Category)
		}
		// inverse direction de-escalates: rdp high->medium
		if f.Port == 3389 && f.Severity != model.SevMedium {
			t.Errorf("missing-on-v6 rdp should drop to medium, got %s", f.Severity)
		}
	}
}

func TestAnalyzeProtocolMismatch(t *testing.T) {
	res := mkResult(mkHost(),
		[]model.Service{tcp(8080, "http")},
		[]model.Service{tcp(8080, "redis")})
	findings := Analyze([]*model.HostResult{res})
	if len(findings) != 1 {
		t.Fatalf("want exactly the mismatch finding, got %+v", findings)
	}
	f := findings[0]
	if f.Category != model.CatProtoMismatch || f.Severity != model.SevMedium ||
		f.Port != 8080 || f.Protocol != model.TCP {
		t.Errorf("mismatch finding wrong: %+v", f)
	}
}

func TestAnalyzeNoFalseMismatchWhenSame(t *testing.T) {
	res := mkResult(mkHost(), []model.Service{tcp(22, "ssh")}, []model.Service{tcp(22, "ssh")})
	if got := Analyze([]*model.HostResult{res}); len(got) != 0 {
		t.Errorf("identical services should produce no findings, got %+v", got)
	}
}

func TestAnalyzeGUAExposed(t *testing.T) {
	h := mkHost()
	h.IPv6 = []string{"2620:0:2820:2000::42"} // globally routable
	res := mkResult(h, nil, []model.Service{tcp(443, "https")})
	findings := Analyze([]*model.HostResult{res})
	var gua bool
	for _, f := range findings {
		if f.Category == model.CatGUAExposed {
			gua = true
		}
	}
	if !gua {
		t.Fatalf("gua_exposed not reported: %+v", findings)
	}
}

func TestAnalyzePTRMismatch(t *testing.T) {
	h := mkHost()
	h.HostnameV6 = "different.example.com"
	h.IPv6 = []string{"2620:0:2820:2000::42"}
	res := mkResult(h, nil, []model.Service{tcp(443, "https")})
	findings := Analyze([]*model.HostResult{res})
	var ptr bool
	for _, f := range findings {
		if f.Category == model.CatPTRMismatch {
			ptr = true
			if f.Severity != model.SevInfo {
				t.Error("ptr mismatch should be info")
			}
		}
	}
	if !ptr {
		t.Fatal("ptr mismatch not detected")
	}
}

func TestSeverityDirection(t *testing.T) {
	cases := []struct {
		cat  model.Category
		port int
		want model.Severity
	}{
		{model.CatNewExposure, 3389, model.SevCritical}, // high + bypass bump
		{model.CatNewExposure, 8080, model.SevHigh},     // high-risk port bumped
		{model.CatMissingOnV6, 3389, model.SevMedium},
		{model.CatUDPNewExposure, 161, model.SevCritical},
		{model.CatUDPMissingOnV6, 53, model.SevLow},
	}
	for _, c := range cases {
		if got := severityFor(c.cat, c.port); got != c.want {
			t.Errorf("severityFor(%s, %d) = %s, want %s", c.cat, c.port, got, c.want)
		}
	}
}

func TestRelatedNames(t *testing.T) {
	if !relatedNames("web01.example.com.", "example.com") {
		t.Error("subdomain should relate to parent")
	}
	if relatedNames("foo.example.com", "bar.example.org") {
		t.Error("unrelated hosts flagged as related")
	}
	if !relatedNames("", "") {
		t.Error("empty names are trivially related")
	}
}

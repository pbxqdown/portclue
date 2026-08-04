package analyze

import (
	"net/netip"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestPortNoListener(t *testing.T) {
	report := Port(8080, model.Facts{})
	if report.Verdict != model.NotLocal {
		t.Fatalf("verdict = %s, want %s", report.Verdict, model.NotLocal)
	}
	if len(report.Paths) != 0 {
		t.Fatalf("paths = %d, want 0", len(report.Paths))
	}
}

func TestLoopbackListenerIsNotExternallyExposed(t *testing.T) {
	report := Port(8080, model.Facts{
		Listeners: []model.Listener{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 8080},
			Inode:    42,
		}},
	})
	if report.Verdict != model.NotLocal {
		t.Fatalf("verdict = %s, want %s", report.Verdict, model.NotLocal)
	}
}

func TestWildcardAcceptedIsPotential(t *testing.T) {
	report := Port(8080, model.Facts{
		Listeners: []model.Listener{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 8080},
			Inode:    43,
		}},
		Firewall: []model.FirewallObservation{{
			Backend: "nftables", Chain: "input", Verdict: model.FirewallAccept,
		}},
	})
	if report.Verdict != model.Potential {
		t.Fatalf("verdict = %s, want %s", report.Verdict, model.Potential)
	}
	if len(report.Unknowns) == 0 {
		t.Fatal("expected external unknowns")
	}
}

func TestWildcardUnknownFirewallIsUnknown(t *testing.T) {
	report := Port(8080, model.Facts{
		Listeners: []model.Listener{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 8080},
		}},
		Firewall: []model.FirewallObservation{{
			Backend: "nftables", Chain: "input", Verdict: model.FirewallUnknown,
		}},
	})
	if report.Verdict != model.Unknown {
		t.Fatalf("verdict = %s, want %s", report.Verdict, model.Unknown)
	}
}

func TestDockerPublishedPortUsesForwardChain(t *testing.T) {
	report := Port(8080, model.Facts{
		Mappings: []model.NATMapping{{
			Protocol: "tcp", HostAddress: netip.IPv4Unspecified(), HostPort: 8080,
			ContainerPort: 80, ContainerName: "web",
		}},
		Firewall: []model.FirewallObservation{
			{Backend: "nftables", Chain: "input", Verdict: model.FirewallDrop},
			{Backend: "nftables", Chain: "forward", Verdict: model.FirewallAccept},
		},
	})
	if report.Verdict != model.Potential {
		t.Fatalf("verdict = %s, want %s", report.Verdict, model.Potential)
	}
	if got := report.Paths[0].Owner.Container; got != "web" {
		t.Fatalf("container = %q, want web", got)
	}
	if got := report.Paths[0].Steps[1].Decision; got != "FORWARD" {
		t.Fatalf("packet path = %q, want FORWARD", got)
	}
}

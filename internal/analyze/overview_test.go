package analyze

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestOverviewGroupsAndPrioritizesPorts(t *testing.T) {
	facts := model.Facts{
		Listeners: []model.Listener{
			{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 8080},
				Owner:    &model.Owner{Process: "nginx"},
			},
			{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("::"), Port: 8080},
				Owner:    &model.Owner{Process: "nginx"},
			},
			{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 9000},
				Owner:    &model.Owner{Process: "local-api"},
			},
		},
	}
	report := Overview(facts)
	if len(report.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(report.Entries))
	}
	external := report.Entries[0]
	if external.Port != 8080 || external.BindScope != model.AllInterfaces {
		t.Fatalf("first entry = %+v, want all-interface port 8080", external)
	}
	if external.Identity.Name != "NGINX web server" || external.Identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", external.Identity)
	}
	if !reflect.DeepEqual(external.Owners, []string{"nginx"}) {
		t.Fatalf("owners = %#v", external.Owners)
	}
	if !reflect.DeepEqual(external.Sources, []string{"host"}) {
		t.Fatalf("sources = %#v", external.Sources)
	}
	if !reflect.DeepEqual(external.Binds, []string{"0.0.0.0", "::"}) {
		t.Fatalf("binds = %#v", external.Binds)
	}
	if report.Entries[1].BindScope != model.LoopbackOnly {
		t.Fatalf("second bind scope = %s, want %s", report.Entries[1].BindScope, model.LoopbackOnly)
	}
}

func TestOverviewUsesUnknownOwner(t *testing.T) {
	report := Overview(model.Facts{
		Listeners: []model.Listener{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 1234},
		}},
	})
	if got := report.Entries[0].Owners; !reflect.DeepEqual(got, []string{"unknown"}) {
		t.Fatalf("owners = %#v, want unknown", got)
	}
}

func TestOverviewSeparatesServicesSharingPort(t *testing.T) {
	report := Overview(model.Facts{Listeners: []model.Listener{
		{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.53"), Port: 53},
			Owner: &model.Owner{Process: "systemd-resolve", Executable: "/usr/lib/systemd/systemd-resolved",
				Service: "systemd-resolved.service"},
		},
		{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("192.0.2.10"), Port: 53},
			Owner: &model.Owner{Process: "dnsmasq", Executable: "/usr/sbin/dnsmasq",
				Service: "libvirtd.service", ServiceDescription: "libvirt legacy monolithic daemon"},
		},
	}})
	if len(report.Entries) != 2 {
		t.Fatalf("entries = %d, want 2: %+v", len(report.Entries), report.Entries)
	}
	if got := report.Entries[0]; got.Identity.Name != "dnsmasq DNS/DHCP service" ||
		got.BindScope != model.SpecificInterface || !reflect.DeepEqual(got.Binds, []string{"192.0.2.10"}) {
		t.Fatalf("specific-interface entry = %+v", got)
	}
	if got := report.Entries[1]; got.Identity.Name != "systemd DNS resolver" ||
		got.BindScope != model.LoopbackOnly || !reflect.DeepEqual(got.Binds, []string{"127.0.0.53"}) {
		t.Fatalf("loopback entry = %+v", got)
	}
}

func TestOverviewSpecificInterfaceSortsBetweenWildcardAndLoopback(t *testing.T) {
	report := Overview(model.Facts{Listeners: []model.Listener{
		{Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 3}},
		{Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("198.51.100.20"), Port: 2}},
		{Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 1}},
	}})
	want := []model.BindScope{model.AllInterfaces, model.SpecificInterface, model.LoopbackOnly}
	for index, scope := range want {
		if report.Entries[index].BindScope != scope {
			t.Fatalf("entry %d scope = %s, want %s", index, report.Entries[index].BindScope, scope)
		}
	}
}

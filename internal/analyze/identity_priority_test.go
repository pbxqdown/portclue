package analyze

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestDockerMappingSuppressesProxyListener(t *testing.T) {
	report := Overview(model.Facts{
		Listeners: []model.Listener{
			{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 18080},
				Owner: &model.Owner{
					Process: "docker-proxy", Executable: "/usr/bin/docker-proxy",
					Service: "docker.service", ServiceDescription: "Docker Application Container Engine",
				},
			},
			{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv6Unspecified(), Port: 18080},
				Owner:    &model.Owner{Process: "docker-proxy", Executable: "/usr/bin/docker-proxy"},
			},
		},
		Mappings: []model.NATMapping{
			{
				Protocol: "tcp", HostAddress: netip.IPv4Unspecified(), HostPort: 18080,
				ContainerPort: 18080, ContainerName: "demo-api",
				ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
			},
			{
				Protocol: "tcp", HostAddress: netip.IPv6Unspecified(), HostPort: 18080,
				ContainerPort: 18080, ContainerName: "demo-api",
				ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
			},
		},
	})
	if len(report.Entries) != 1 {
		t.Fatalf("entries = %d, want 1: %+v", len(report.Entries), report.Entries)
	}
	entry := report.Entries[0]
	if entry.Identity.Name != "api service" {
		t.Fatalf("service = %q, want api service", entry.Identity.Name)
	}
	if !reflect.DeepEqual(entry.Owners, []string{"demo-api"}) ||
		!reflect.DeepEqual(entry.Sources, []string{"docker"}) {
		t.Fatalf("entry retained proxy evidence: %+v", entry)
	}
	if !reflect.DeepEqual(entry.Binds, []string{"0.0.0.0", "::"}) {
		t.Fatalf("binds = %#v, want dual-stack Docker publication", entry.Binds)
	}
}

func TestDockerMappingSuppressesAnonymousListenerWithoutRoot(t *testing.T) {
	report := Overview(model.Facts{
		Listeners: []model.Listener{
			{Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 18080}},
			{Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv6Unspecified(), Port: 18080}},
		},
		Mappings: []model.NATMapping{
			{
				Protocol: "tcp", HostAddress: netip.IPv4Unspecified(), HostPort: 18080,
				ContainerPort: 18080, ContainerName: "demo-api",
				ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
			},
			{
				Protocol: "tcp", HostAddress: netip.IPv6Unspecified(), HostPort: 18080,
				ContainerPort: 18080, ContainerName: "demo-api",
				ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
			},
		},
	})
	if len(report.Entries) != 1 {
		t.Fatalf("entries = %d, want only Docker mapping: %+v", len(report.Entries), report.Entries)
	}
	entry := report.Entries[0]
	if entry.Identity.Name != "api service" ||
		!reflect.DeepEqual(entry.Owners, []string{"demo-api"}) ||
		!reflect.DeepEqual(entry.Sources, []string{"docker"}) {
		t.Fatalf("entry = %+v, want only identified Docker service", entry)
	}
}

func TestDockerMappingKeepsKnownNonProxyListener(t *testing.T) {
	report := Overview(model.Facts{
		Listeners: []model.Listener{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 18080},
			Owner:    &model.Owner{Process: "custom-gateway", Executable: "/usr/bin/custom-gateway"},
		}},
		Mappings: []model.NATMapping{{
			Protocol: "tcp", HostAddress: netip.IPv4Unspecified(), HostPort: 18080,
			ContainerPort: 18080, ContainerName: "demo-api",
			ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
		}},
	})
	if len(report.Entries) != 2 {
		t.Fatalf("entries = %d, want known host listener and Docker mapping: %+v", len(report.Entries), report.Entries)
	}
	sources := []string{report.Entries[0].Sources[0], report.Entries[1].Sources[0]}
	if !reflect.DeepEqual(sources, []string{"host", "docker"}) &&
		!reflect.DeepEqual(sources, []string{"docker", "host"}) {
		t.Fatalf("sources = %#v, want host and docker", sources)
	}
}

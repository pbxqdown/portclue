package identify

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestObservedOpenSSHOwnerIsHighConfidence(t *testing.T) {
	identity := Default().Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 22},
		Owner: &model.Owner{
			Process: "sshd", Executable: "/usr/sbin/sshd", Service: "ssh.service",
		},
	})
	if identity.Name != "OpenSSH server" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
	if len(identity.Evidence) < 2 {
		t.Fatalf("expected executable and systemd evidence: %+v", identity.Evidence)
	}
}

func TestObservedProcessOverridesPortConvention(t *testing.T) {
	resolver := &Resolver{services: map[string]string{"tcp/22": "ssh"}}
	identity := resolver.Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 22},
		Owner: &model.Owner{
			Process: "python3", Executable: "/usr/bin/python3",
			Command: "python3 -m http.server 22",
		},
	})
	if identity.Name != "python3 process" || identity.Confidence != "MEDIUM" {
		t.Fatalf("identity = %+v", identity)
	}
	if identity.PortHint != "ssh" {
		t.Fatalf("port hint = %q, want ssh", identity.PortHint)
	}
}

func TestPortConventionAloneIsLowConfidence(t *testing.T) {
	resolver := &Resolver{services: map[string]string{"tcp/22": "ssh"}}
	identity := resolver.Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 22},
	})
	if identity.Name != "SSH service" || identity.Confidence != "LOW" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestKindMappingUsesImageAndContainerPort(t *testing.T) {
	identity := Default().Mapping(model.NATMapping{
		Protocol: "tcp", HostPort: 18443, ContainerPort: 6443,
		ContainerName: "example-control-plane", ContainerImage: "kindest/node:v1.36.1",
	})
	if identity.Name != "Kubernetes API server" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestCommandSignatureIdentifiesPythonHTTPServer(t *testing.T) {
	identity := Default().Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 43123},
		Owner: &model.Owner{
			Process: "python3", Executable: "/usr/bin/python3",
			Command: "python3 -m http.server 43123",
		},
	})
	if identity.Name != "Python HTTP server" || identity.Confidence != "MEDIUM" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestLoadServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services")
	data := "ssh 22/tcp\nhttp 80/tcp www # comment\nignored invalid\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	services := loadServices(path)
	if services["tcp/22"] != "ssh" || services["tcp/80"] != "http" {
		t.Fatalf("services = %#v", services)
	}
}

func TestComposeLabelFallback(t *testing.T) {
	identity := (&Resolver{}).Mapping(model.NATMapping{
		Protocol: "tcp", ContainerName: "project-api-1",
		ContainerLabels: map[string]string{"com.docker.compose.service": "api"},
	})
	if identity.Name != "api service" || identity.Confidence != "MEDIUM" {
		t.Fatalf("identity = %+v", identity)
	}
	if !strings.Contains(identity.Evidence[0], "Compose") {
		t.Fatalf("evidence = %#v", identity.Evidence)
	}
}

func TestDnsmasqExecutableOverridesLibvirtUnitDescription(t *testing.T) {
	identity := Default().Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("192.0.2.10"), Port: 53},
		Owner: &model.Owner{
			Process: "dnsmasq", Executable: "/usr/sbin/dnsmasq",
			Service: "libvirtd.service", ServiceDescription: "libvirt legacy monolithic daemon",
		},
	})
	if identity.Name != "dnsmasq DNS/DHCP service" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestDockerProxyIsInfrastructureNotDockerEngine(t *testing.T) {
	identity := Default().Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 18080},
		Owner: &model.Owner{
			Process: "docker-proxy", Executable: "/usr/bin/docker-proxy",
			Service: "docker.service", ServiceDescription: "Docker Application Container Engine",
		},
	})
	if identity.Name != "Docker port forwarding proxy" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
}

package identify

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestSocketActivatedSSHUsesTriggerService(t *testing.T) {
	identity := Default().Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 22},
		Owner:    &model.Owner{PID: 1, Process: "systemd", Service: "init.scope"},
		Activation: &model.SocketActivation{
			Address: netip.IPv4Unspecified(), Port: 22,
			SocketUnit: "ssh.socket", TriggerService: "ssh.service",
			Description: "OpenBSD Secure Shell server socket",
		},
	})
	if identity.Name != "OpenSSH server" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
	if len(identity.Evidence) == 0 || !strings.Contains(identity.Evidence[0], "ssh.socket") {
		t.Fatalf("evidence = %#v", identity.Evidence)
	}
}

func TestUnknownSocketUsesSystemdDescription(t *testing.T) {
	resolver := &Resolver{}
	identity := resolver.Listener(model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 12345},
		Activation: &model.SocketActivation{
			Address: netip.IPv4Unspecified(), Port: 12345,
			SocketUnit: "example.socket", Description: "Example server socket",
		},
	})
	if identity.Name != "Example server" || identity.Confidence != "HIGH" {
		t.Fatalf("identity = %+v", identity)
	}
}

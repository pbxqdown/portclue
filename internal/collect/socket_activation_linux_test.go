//go:build linux

package collect

import (
	"net/netip"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestParseSystemdSocketProperties(t *testing.T) {
	input := `Listen=0.0.0.0:22 (Stream)
Listen=[::]:22 (Stream)
Id=ssh.socket
Triggers=ssh.service
Description=OpenBSD Secure Shell server socket
ActiveState=active
SubState=running

Listen=/run/docker.sock (Stream)
Id=docker.socket
Triggers=docker.service
Description=Docker API socket
ActiveState=active
SubState=running
`
	got := parseSystemdSocketProperties(input)
	if len(got) != 2 {
		t.Fatalf("activations = %d, want 2: %+v", len(got), got)
	}
	if got[0].Address != netip.IPv4Unspecified() || got[0].Port != 22 {
		t.Fatalf("first activation = %+v", got[0])
	}
	if got[1].Address != netip.IPv6Unspecified() || got[1].TriggerService != "ssh.service" {
		t.Fatalf("second activation = %+v", got[1])
	}
}

func TestAttachSocketActivationByAddressAndPort(t *testing.T) {
	listener := model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 22},
	}
	activation := model.SocketActivation{
		Address: netip.IPv4Unspecified(), Port: 22, SocketUnit: "ssh.socket",
	}
	if listener.Endpoint.Address != activation.Address || listener.Endpoint.Port != activation.Port {
		t.Fatal("fixture should match")
	}
}

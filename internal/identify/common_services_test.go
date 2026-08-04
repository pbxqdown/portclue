package identify

import (
	"net/netip"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestCommonInfrastructureServices(t *testing.T) {
	tests := []struct {
		name     string
		listener model.Listener
		want     string
	}{
		{
			name: "rpcbind",
			listener: model.Listener{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 111},
				Owner:    &model.Owner{Process: "rpcbind", Executable: "/usr/sbin/rpcbind", Service: "rpcbind.service"},
			},
			want: "rpcbind RPC service",
		},
		{
			name: "Samba",
			listener: model.Listener{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 445},
				Owner:    &model.Owner{Process: "smbd", Executable: "/usr/sbin/smbd", Service: "smbd.service"},
			},
			want: "Samba SMB service",
		},
		{
			name: "QEMU",
			listener: model.Listener{
				Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.MustParseAddr("127.0.0.1"), Port: 43210},
				Owner: &model.Owner{
					Process: "qemu-system-x86", Executable: "/usr/bin/qemu-system-x86_64",
				},
			},
			want: "QEMU virtual machine",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := Default().Listener(test.listener)
			if identity.Name != test.want || identity.Confidence != "HIGH" {
				t.Fatalf("identity = %+v, want %q HIGH", identity, test.want)
			}
		})
	}
}

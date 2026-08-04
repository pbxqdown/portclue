//go:build linux

package collect

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseInetDiagMessage(t *testing.T) {
	tests := []struct {
		name    string
		family  byte
		address netip.Addr
	}{
		{name: "IPv4", family: unix.AF_INET, address: netip.MustParseAddr("192.0.2.10")},
		{name: "IPv6", family: unix.AF_INET6, address: netip.MustParseAddr("2001:db8::10")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, inetDiagMsgLen)
			payload[0] = test.family
			binary.BigEndian.PutUint16(payload[4:6], 8443)
			if test.address.Is4() {
				raw := test.address.As4()
				copy(payload[8:12], raw[:])
			} else {
				raw := test.address.As16()
				copy(payload[8:24], raw[:])
			}
			binary.NativeEndian.PutUint32(payload[64:68], 1000)
			binary.NativeEndian.PutUint32(payload[68:72], 424242)

			listener, err := parseInetDiagMessage(payload)
			if err != nil {
				t.Fatal(err)
			}
			if listener.Endpoint.Address != test.address || listener.Endpoint.Port != 8443 ||
				listener.Endpoint.Protocol != "tcp" || listener.UID != 1000 || listener.Inode != 424242 {
				t.Fatalf("listener = %+v", listener)
			}
		})
	}
}

func TestParseInetDiagMessageRejectsMalformedInput(t *testing.T) {
	if _, err := parseInetDiagMessage(make([]byte, inetDiagMsgLen-1)); err == nil {
		t.Fatal("expected short-message error")
	}
	payload := make([]byte, inetDiagMsgLen)
	payload[0] = 255
	if _, err := parseInetDiagMessage(payload); err == nil {
		t.Fatal("expected unsupported-family error")
	}
}

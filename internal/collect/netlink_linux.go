//go:build linux

package collect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/pbxqdown/portclue/internal/model"
	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily = 20
	inetDiagReqLen   = 56
	inetDiagMsgLen   = 72
	tcpListenState   = 10
)

func ListTCPListeners() ([]model.Listener, []string, error) {
	var listeners []model.Listener
	var warnings []string
	var successful int
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		items, err := listTCPListenersFamily(family)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("socket diagnostics for family %d: %v", family, err))
			continue
		}
		successful++
		listeners = append(listeners, items...)
	}
	if successful == 0 {
		return nil, warnings, errors.New("could not query TCP listeners through NETLINK_INET_DIAG")
	}
	return listeners, warnings, nil
}

func listTCPListenersFamily(family uint8) ([]model.Listener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	seq := uint32(1)
	req := make([]byte, unix.NLMSG_HDRLEN+inetDiagReqLen)
	order := binary.NativeEndian
	order.PutUint32(req[0:4], uint32(len(req)))
	order.PutUint16(req[4:6], sockDiagByFamily)
	order.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	order.PutUint32(req[8:12], seq)
	req[unix.NLMSG_HDRLEN] = family
	req[unix.NLMSG_HDRLEN+1] = unix.IPPROTO_TCP
	order.PutUint32(req[unix.NLMSG_HDRLEN+4:unix.NLMSG_HDRLEN+8], 1<<tcpListenState)

	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	var result []model.Listener
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		for offset := 0; offset+unix.NLMSG_HDRLEN <= n; {
			msgLen := int(order.Uint32(buf[offset : offset+4]))
			if msgLen < unix.NLMSG_HDRLEN || offset+msgLen > n {
				return nil, fmt.Errorf("malformed netlink message length %d", msgLen)
			}
			msgType := order.Uint16(buf[offset+4 : offset+6])
			payload := buf[offset+unix.NLMSG_HDRLEN : offset+msgLen]
			switch msgType {
			case unix.NLMSG_DONE:
				return result, nil
			case unix.NLMSG_ERROR:
				if len(payload) < 4 {
					return nil, errors.New("short netlink error response")
				}
				code := int32(order.Uint32(payload[:4]))
				if code != 0 {
					return nil, unix.Errno(-code)
				}
			default:
				listener, err := parseInetDiagMessage(payload)
				if err != nil {
					return nil, err
				}
				result = append(result, listener)
			}
			offset += nlmsgAlign(msgLen)
		}
	}
}

func parseInetDiagMessage(payload []byte) (model.Listener, error) {
	if len(payload) < inetDiagMsgLen {
		return model.Listener{}, fmt.Errorf("short inet_diag message: %d bytes", len(payload))
	}
	family := payload[0]
	port := binary.BigEndian.Uint16(payload[4:6])
	var address netip.Addr
	switch family {
	case unix.AF_INET:
		var raw [4]byte
		copy(raw[:], payload[8:12])
		address = netip.AddrFrom4(raw)
	case unix.AF_INET6:
		var raw [16]byte
		copy(raw[:], payload[8:24])
		address = netip.AddrFrom16(raw)
	default:
		return model.Listener{}, fmt.Errorf("unsupported address family %d", family)
	}
	return model.Listener{
		Endpoint: model.Endpoint{Protocol: "tcp", Address: address.Unmap(), Port: port},
		Inode:    uint64(binary.NativeEndian.Uint32(payload[68:72])),
		UID:      binary.NativeEndian.Uint32(payload[64:68]),
	}, nil
}

func nlmsgAlign(length int) int {
	return (length + unix.NLMSG_ALIGNTO - 1) & ^(unix.NLMSG_ALIGNTO - 1)
}

//go:build linux

package collect

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pbxqdown/portclue/internal/model"
)

func AttachSystemdSocketActivations(parent context.Context, listeners []model.Listener) ([]model.Listener, []string) {
	activations, err := activeSystemdSocketActivations(parent)
	if err != nil {
		return listeners, []string{"systemd socket activation evidence unavailable: " + err.Error()}
	}
	for i := range listeners {
		for _, activation := range activations {
			if activation.Port != listeners[i].Endpoint.Port ||
				activation.Address != listeners[i].Endpoint.Address {
				continue
			}
			copy := activation
			listeners[i].Activation = &copy
			break
		}
	}
	return listeners, nil
}

func activeSystemdSocketActivations(parent context.Context) ([]model.SocketActivation, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(
		ctx,
		"systemctl", "show",
		"--type=socket",
		"--state=active",
		"--property=Id,Description,Listen,Triggers,ActiveState,SubState",
		"--no-pager",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show active sockets: %w", err)
	}
	return parseSystemdSocketProperties(string(output)), nil
}

func parseSystemdSocketProperties(output string) []model.SocketActivation {
	var result []model.SocketActivation
	for _, block := range strings.Split(strings.TrimSpace(output), "\n\n") {
		properties := make(map[string][]string)
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			properties[key] = append(properties[key], value)
		}
		socketUnit := first(properties["Id"])
		if socketUnit == "" || first(properties["ActiveState"]) != "active" {
			continue
		}
		trigger := firstService(properties["Triggers"])
		description := first(properties["Description"])
		for _, listen := range properties["Listen"] {
			address, port, ok := parseStreamListen(listen)
			if !ok {
				continue
			}
			result = append(result, model.SocketActivation{
				Address: address, Port: port, SocketUnit: socketUnit,
				TriggerService: trigger, Description: description,
			})
		}
	}
	return result
}

func parseStreamListen(value string) (netip.Addr, uint16, bool) {
	const suffix = " (Stream)"
	if !strings.HasSuffix(value, suffix) {
		return netip.Addr{}, 0, false
	}
	endpoint := strings.TrimSpace(strings.TrimSuffix(value, suffix))
	if addressPort, err := netip.ParseAddrPort(endpoint); err == nil {
		return addressPort.Addr().Unmap(), addressPort.Port(), true
	}
	if numeric, err := strconv.ParseUint(endpoint, 10, 16); err == nil && numeric > 0 {
		return netip.IPv4Unspecified(), uint16(numeric), true
	}
	return netip.Addr{}, 0, false
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func firstService(values []string) string {
	for _, value := range values {
		for _, field := range strings.Fields(value) {
			if strings.HasSuffix(field, ".service") {
				return field
			}
		}
	}
	return ""
}

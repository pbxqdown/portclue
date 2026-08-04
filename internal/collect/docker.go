package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/pbxqdown/portclue/internal/model"
)

type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		IP          string `json:"IP"`
		PrivatePort uint16 `json:"PrivatePort"`
		PublicPort  uint16 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

func DockerMappings(ctx context.Context, socketPath string) ([]model.NATMapping, error) {
	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker Engine returned %s", response.Status)
	}
	var containers []dockerContainer
	if err := json.NewDecoder(response.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode Docker response: %w", err)
	}
	var mappings []model.NATMapping
	for _, container := range containers {
		name := shortContainerName(container.Names, container.ID)
		for _, port := range container.Ports {
			if port.PublicPort == 0 {
				continue
			}
			address := netip.IPv4Unspecified()
			if port.IP != "" {
				if parsed, err := netip.ParseAddr(port.IP); err == nil {
					address = parsed.Unmap()
				}
			}
			mappings = append(mappings, model.NATMapping{
				Protocol:        strings.ToLower(port.Type),
				HostAddress:     address,
				HostPort:        port.PublicPort,
				ContainerPort:   port.PrivatePort,
				ContainerName:   name,
				ContainerID:     shortID(container.ID),
				ContainerImage:  container.Image,
				ContainerLabels: container.Labels,
			})
		}
	}
	return mappings, nil
}

func shortContainerName(names []string, id string) string {
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	return shortID(id)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

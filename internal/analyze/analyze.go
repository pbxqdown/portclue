package analyze

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/pbxqdown/portclue/internal/identify"
	"github.com/pbxqdown/portclue/internal/model"
)

func Port(port uint16, facts model.Facts) model.Report {
	report := model.Report{
		SchemaVersion: 1,
		Query:         model.Query{Protocol: "tcp", Port: port},
		Warnings:      append([]string(nil), facts.Warnings...),
	}

	for _, listener := range facts.Listeners {
		if listener.Endpoint.Protocol != "tcp" || listener.Endpoint.Port != port {
			continue
		}
		report.Paths = append(report.Paths, listenerPath(listener, firewallFor(facts.Firewall, "input")))
	}
	for _, mapping := range facts.Mappings {
		if mapping.Protocol != "tcp" || mapping.HostPort != port {
			continue
		}
		report.Paths = append(report.Paths, mappingPath(mapping, firewallFor(facts.Firewall, "forward")))
	}
	report.Paths = deduplicate(report.Paths)
	sort.Slice(report.Paths, func(i, j int) bool {
		return report.Paths[i].Endpoint.Address.String() < report.Paths[j].Endpoint.Address.String()
	})
	report.Verdict = aggregate(report.Paths)
	if report.Verdict == model.Potential || report.Verdict == model.Unknown {
		report.Unknowns = []string{
			"router port forwarding",
			"cloud firewall or security group",
			"upstream NAT, including carrier-grade NAT",
		}
	}
	return report
}

func listenerPath(listener model.Listener, firewall model.FirewallObservation) model.Path {
	path := model.Path{Endpoint: listener.Endpoint, Owner: listener.Owner, Identity: identify.Default().Listener(listener)}
	path.Steps = append(path.Steps, model.PathStep{
		Kind: "listener", Decision: "LISTEN",
		Evidence: fmt.Sprintf("NETLINK_INET_DIAG reports socket inode %d bound to %s", listener.Inode, displayEndpoint(listener.Endpoint)),
	})
	if listener.Activation != nil {
		detail := "active " + listener.Activation.SocketUnit
		if listener.Activation.TriggerService != "" {
			detail += " triggers " + listener.Activation.TriggerService
		}
		path.Steps = append(path.Steps, model.PathStep{Kind: "socket-activation", Decision: "TRIGGERS", Evidence: detail})
	}
	if listener.Owner != nil {
		detail := fmt.Sprintf("PID %d (%s)", listener.Owner.PID, fallback(listener.Owner.Process, "unknown process"))
		if listener.Owner.Service != "" {
			detail += ", systemd unit " + listener.Owner.Service
		}
		path.Steps = append(path.Steps, model.PathStep{Kind: "owner", Decision: "OWNED", Evidence: detail})
	} else {
		path.Steps = append(path.Steps, model.PathStep{Kind: "owner", Decision: "UNKNOWN", Evidence: "no readable /proc file descriptor referenced the socket inode"})
	}
	return applyReachability(path, listener.Endpoint.Address, firewall)
}

func mappingPath(mapping model.NATMapping, firewall model.FirewallObservation) model.Path {
	owner := &model.Owner{Container: mapping.ContainerName}
	path := model.Path{
		Endpoint: model.Endpoint{Protocol: mapping.Protocol, Address: mapping.HostAddress, Port: mapping.HostPort},
		Owner:    owner,
		Identity: identify.Default().Mapping(mapping),
	}
	path.Steps = append(path.Steps,
		model.PathStep{
			Kind: "docker-publish", Decision: "DNAT",
			Evidence: fmt.Sprintf("Docker Engine publishes %s to container %s port %d/tcp", displayEndpoint(path.Endpoint), mapping.ContainerName, mapping.ContainerPort),
		},
		model.PathStep{
			Kind: "packet-path", Decision: "FORWARD",
			Evidence: "published bridge-network traffic is evaluated on the forwarding path after destination NAT",
		},
	)
	return applyReachability(path, mapping.HostAddress, firewall)
}

func applyReachability(path model.Path, address netip.Addr, firewall model.FirewallObservation) model.Path {
	if address.IsLoopback() {
		path.Verdict = model.NotLocal
		path.Steps = append(path.Steps, model.PathStep{Kind: "bind-address", Decision: "LOOPBACK_ONLY", Evidence: address.String() + " is reachable only from this network namespace"})
		return path
	}
	if address.Is6() {
		path.Verdict = model.Unknown
		path.Steps = append(path.Steps, model.PathStep{Kind: "firewall", Decision: "UNKNOWN", Evidence: "IPv6 firewall path evaluation is not implemented in v0.1"})
		return path
	}
	if address.IsUnspecified() {
		path.Steps = append(path.Steps, model.PathStep{Kind: "bind-address", Decision: "ALL_INTERFACES", Evidence: address.String() + " accepts traffic addressed to any local interface"})
	} else {
		path.Steps = append(path.Steps, model.PathStep{Kind: "bind-address", Decision: "SPECIFIC_INTERFACE", Evidence: "socket is bound to local address " + address.String()})
	}
	path.Steps = append(path.Steps, model.PathStep{
		Kind: "firewall", Decision: string(firewall.Verdict), Evidence: firewallEvidence(firewall),
	})
	switch firewall.Verdict {
	case model.FirewallAccept, model.FirewallNotConfigured:
		path.Verdict = model.Potential
	case model.FirewallDrop:
		path.Verdict = model.NotLocal
	default:
		path.Verdict = model.Unknown
	}
	return path
}

func firewallFor(observations []model.FirewallObservation, chain string) model.FirewallObservation {
	for _, observation := range observations {
		if strings.EqualFold(observation.Chain, chain) {
			return observation
		}
	}
	return model.FirewallObservation{Backend: "unavailable", Chain: chain, Verdict: model.FirewallUnknown, Error: "no firewall observation was collected"}
}

func firewallEvidence(observation model.FirewallObservation) string {
	detail := observation.Backend
	if observation.Evidence != "" {
		detail += ": " + observation.Evidence
	}
	if observation.Error != "" {
		detail += ": " + observation.Error
	}
	return detail
}

func aggregate(paths []model.Path) model.Verdict {
	if len(paths) == 0 {
		return model.NotLocal
	}
	verdict := model.NotLocal
	for _, path := range paths {
		if path.Verdict == model.Potential || path.Verdict == model.Confirmed {
			return path.Verdict
		}
		if path.Verdict == model.Unknown {
			verdict = model.Unknown
		}
	}
	return verdict
}

func deduplicate(paths []model.Path) []model.Path {
	seenDocker := make(map[string]bool)
	for _, path := range paths {
		if path.Owner != nil && path.Owner.Container != "" {
			seenDocker[path.Endpoint.Address.String()+fmt.Sprintf(":%d", path.Endpoint.Port)] = true
		}
	}
	result := make([]model.Path, 0, len(paths))
	for _, path := range paths {
		key := path.Endpoint.Address.String() + fmt.Sprintf(":%d", path.Endpoint.Port)
		if seenDocker[key] && (path.Owner == nil || (path.Owner.Container == "" && (path.Owner.Process == "docker-proxy" || path.Owner.Process == "rootlesskit"))) {
			continue
		}
		result = append(result, path)
	}
	return result
}

func displayEndpoint(endpoint model.Endpoint) string {
	return netip.AddrPortFrom(endpoint.Address, endpoint.Port).String() + "/" + endpoint.Protocol
}

func fallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

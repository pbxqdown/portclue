package analyze

import (
	"sort"
	"strconv"
	"strings"

	"github.com/pbxqdown/portclue/internal/identify"
	"github.com/pbxqdown/portclue/internal/model"
)

type overviewBuilder struct {
	entry     model.OverviewEntry
	binds     map[string]struct{}
	owners    map[string]struct{}
	sources   map[string]struct{}
	bindScope model.BindScope
}

type overviewKey struct {
	port     uint16
	service  string
	category string
	owner    string
	source   string
}

func Overview(facts model.Facts) model.OverviewReport {
	builders := make(map[overviewKey]*overviewBuilder)
	dockerEndpoints := make(map[string]struct{})
	for _, mapping := range facts.Mappings {
		if mapping.Protocol == "tcp" {
			dockerEndpoints[overviewEndpointKey(mapping.Protocol, mapping.HostAddress.String(), mapping.HostPort)] = struct{}{}
		}
	}

	for _, listener := range facts.Listeners {
		if listener.Endpoint.Protocol != "tcp" {
			continue
		}
		if _, published := dockerEndpoints[overviewEndpointKey(listener.Endpoint.Protocol, listener.Endpoint.Address.String(), listener.Endpoint.Port)]; published && isDockerProxyOrUnknown(listener) {
			continue
		}
		identity := identify.Default().Listener(listener)
		owner := listenerOwner(listener)
		key := overviewKey{port: listener.Endpoint.Port, service: identity.Name, category: identity.Category, owner: owner, source: "host"}
		builder := overviewFor(builders, key, identity)
		builder.binds[listener.Endpoint.Address.String()] = struct{}{}
		builder.sources["host"] = struct{}{}
		builder.considerBind(listener.Endpoint.Address.IsUnspecified(), listener.Endpoint.Address.IsLoopback())
		if owner != "" {
			builder.owners[owner] = struct{}{}
		}
	}
	for _, mapping := range facts.Mappings {
		if mapping.Protocol != "tcp" {
			continue
		}
		identity := identify.Default().Mapping(mapping)
		owner := mapping.ContainerName
		key := overviewKey{port: mapping.HostPort, service: identity.Name, category: identity.Category, owner: owner, source: "docker"}
		builder := overviewFor(builders, key, identity)
		builder.binds[mapping.HostAddress.String()] = struct{}{}
		builder.sources["docker"] = struct{}{}
		builder.considerBind(mapping.HostAddress.IsUnspecified(), mapping.HostAddress.IsLoopback())
		if owner != "" {
			builder.owners[owner] = struct{}{}
		}
	}

	report := model.OverviewReport{
		SchemaVersion: 2,
		Mode:          "overview",
		Entries:       make([]model.OverviewEntry, 0),
		Warnings:      append([]string(nil), facts.Warnings...),
	}
	for _, builder := range builders {
		builder.entry.Binds = sortedKeys(builder.binds)
		builder.entry.Owners = sortedKeys(builder.owners)
		if len(builder.entry.Owners) == 0 {
			builder.entry.Owners = []string{"unknown"}
		}
		builder.entry.Sources = sortedKeys(builder.sources)
		builder.entry.BindScope = builder.bindScope
		report.Entries = append(report.Entries, builder.entry)
	}
	sort.Slice(report.Entries, func(i, j int) bool {
		left, right := report.Entries[i], report.Entries[j]
		if bindScopeRank(left.BindScope) != bindScopeRank(right.BindScope) {
			return bindScopeRank(left.BindScope) > bindScopeRank(right.BindScope)
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Identity.Name != right.Identity.Name {
			return left.Identity.Name < right.Identity.Name
		}
		return strings.Join(left.Binds, ",") < strings.Join(right.Binds, ",")
	})
	return report
}

func overviewFor(builders map[overviewKey]*overviewBuilder, key overviewKey, identity model.ServiceIdentity) *overviewBuilder {
	if existing := builders[key]; existing != nil {
		existing.considerIdentity(identity)
		return existing
	}
	builder := &overviewBuilder{
		entry:   model.OverviewEntry{Protocol: "tcp", Port: key.port, Identity: identity},
		binds:   make(map[string]struct{}),
		owners:  make(map[string]struct{}),
		sources: make(map[string]struct{}),
	}
	builders[key] = builder
	return builder
}

func (builder *overviewBuilder) considerBind(unspecified, loopback bool) {
	candidate := model.SpecificInterface
	if unspecified {
		candidate = model.AllInterfaces
	} else if loopback {
		candidate = model.LoopbackOnly
	}
	if bindScopeRank(candidate) > bindScopeRank(builder.bindScope) {
		builder.bindScope = candidate
	}
}

func bindScopeRank(scope model.BindScope) int {
	switch scope {
	case model.AllInterfaces:
		return 3
	case model.SpecificInterface:
		return 2
	case model.LoopbackOnly:
		return 1
	default:
		return 0
	}
}

func listenerOwner(listener model.Listener) string {
	if listener.Activation != nil {
		owner := listener.Activation.SocketUnit
		if listener.Activation.TriggerService != "" {
			owner += " -> " + listener.Activation.TriggerService
		}
		return owner
	}
	if listener.Owner == nil {
		return ""
	}
	if listener.Owner.Process != "" {
		return listener.Owner.Process
	}
	return listener.Owner.Service
}

func isDockerProxyOrUnknown(listener model.Listener) bool {
	if listener.Owner == nil {
		return true
	}
	process := strings.ToLower(listener.Owner.Process)
	executable := strings.ToLower(listener.Owner.Executable)
	return process == "docker-proxy" || process == "rootlesskit" ||
		strings.HasSuffix(executable, "/docker-proxy") || strings.HasSuffix(executable, "/rootlesskit")
}

func overviewEndpointKey(protocol, address string, port uint16) string {
	return strings.ToLower(protocol) + "|" + address + "|" + strconv.Itoa(int(port))
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

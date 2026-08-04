package identify

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/pbxqdown/portclue/internal/model"
)

//go:embed catalog.json
var catalogData []byte

type signature struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Executables    []string `json:"executables"`
	Units          []string `json:"units"`
	Images         []string `json:"images"`
	Commands       []string `json:"commands"`
	Ports          []uint16 `json:"ports"`
	ContainerPorts []uint16 `json:"container_ports"`
}

type Resolver struct {
	signatures []signature
	services   map[string]string
}

var (
	defaultOnce  sync.Once
	defaultValue *Resolver
)

func Default() *Resolver {
	defaultOnce.Do(func() {
		var signatures []signature
		if err := json.Unmarshal(catalogData, &signatures); err != nil {
			panic("invalid embedded service catalog: " + err.Error())
		}
		defaultValue = &Resolver{
			signatures: signatures,
			services:   loadServices("/etc/services"),
		}
	})
	return defaultValue
}

func (resolver *Resolver) Listener(listener model.Listener) model.ServiceIdentity {
	portHint := resolver.portHint(listener.Endpoint.Protocol, listener.Endpoint.Port)
	if listener.Activation != nil {
		return resolver.socketActivation(*listener.Activation, portHint)
	}
	if listener.Owner == nil {
		return fallbackIdentity(nil, "", nil, portHint)
	}
	owner := listener.Owner
	best, score, evidence := resolver.matchOwner(*owner)
	if score > 0 {
		return identity(best, confidence(score), evidence, portHint)
	}
	return fallbackIdentity(owner, "", nil, portHint)
}

func (resolver *Resolver) Mapping(mapping model.NATMapping) model.ServiceIdentity {
	portHint := resolver.portHint(mapping.Protocol, mapping.ContainerPort)
	best, score, evidence := resolver.matchMapping(mapping)
	if score > 0 {
		return identity(best, confidence(score), evidence, portHint)
	}
	if compose := mapping.ContainerLabels["com.docker.compose.service"]; compose != "" {
		return model.ServiceIdentity{
			Name:       compose + " service",
			Category:   "containerized-application",
			Confidence: "MEDIUM",
			Evidence:   []string{"Docker Compose service label is " + strconv.Quote(compose)},
			PortHint:   portHint,
		}
	}
	if mapping.ContainerImage != "" {
		return model.ServiceIdentity{
			Name:       imageRepository(mapping.ContainerImage) + " container",
			Category:   "containerized-application",
			Confidence: "MEDIUM",
			Evidence:   []string{"Docker image is " + strconv.Quote(mapping.ContainerImage)},
			PortHint:   portHint,
		}
	}
	return fallbackIdentity(nil, mapping.ContainerName, []string{"Docker container name is " + strconv.Quote(mapping.ContainerName)}, portHint)
}

func (resolver *Resolver) matchOwner(owner model.Owner) (signature, int, []string) {
	executable := strings.ToLower(filepath.Base(owner.Executable))
	process := strings.ToLower(owner.Process)
	unit := strings.ToLower(owner.Service)
	command := strings.ToLower(owner.Command)
	var best signature
	bestScore := 0
	var bestEvidence []string
	for _, candidate := range resolver.signatures {
		score := 0
		var evidence []string
		if executable != "" && containsFold(candidate.Executables, executable) {
			score += 100
			evidence = append(evidence, "executable basename matched "+strconv.Quote(executable))
		} else if process != "" && containsFold(candidate.Executables, process) {
			score += 90
			evidence = append(evidence, "process name matched "+strconv.Quote(process))
		}
		for _, expected := range candidate.Units {
			if unitMatches(unit, expected) {
				score += 100
				evidence = append(evidence, "systemd unit matched "+strconv.Quote(owner.Service))
				break
			}
		}
		for _, fragment := range candidate.Commands {
			if command != "" && strings.Contains(command, strings.ToLower(fragment)) {
				score += 60
				evidence = append(evidence, "command line matched "+strconv.Quote(fragment))
				break
			}
		}
		if score > bestScore {
			best, bestScore, bestEvidence = candidate, score, evidence
		}
	}
	return best, bestScore, bestEvidence
}

func (resolver *Resolver) matchMapping(mapping model.NATMapping) (signature, int, []string) {
	image := imageRepository(mapping.ContainerImage)
	var best signature
	bestScore := 0
	var bestEvidence []string
	for _, candidate := range resolver.signatures {
		if len(candidate.Images) == 0 || !imageMatches(image, candidate.Images) {
			continue
		}
		if len(candidate.ContainerPorts) > 0 && !containsPort(candidate.ContainerPorts, mapping.ContainerPort) {
			continue
		}
		score := 90
		evidence := []string{"Docker image matched " + strconv.Quote(mapping.ContainerImage)}
		if containsPort(candidate.ContainerPorts, mapping.ContainerPort) {
			score += 20
			evidence = append(evidence, fmt.Sprintf("container port %d matched the service signature", mapping.ContainerPort))
		}
		if score > bestScore {
			best, bestScore, bestEvidence = candidate, score, evidence
		}
	}
	return best, bestScore, bestEvidence
}

func identity(match signature, confidence string, evidence []string, portHint string) model.ServiceIdentity {
	return model.ServiceIdentity{
		Name: match.Name, Category: match.Category, Confidence: confidence,
		Evidence: evidence, PortHint: portHint,
	}
}

func fallbackIdentity(owner *model.Owner, container string, evidence []string, portHint string) model.ServiceIdentity {
	if owner != nil {
		if owner.ServiceDescription != "" {
			return model.ServiceIdentity{
				Name: owner.ServiceDescription, Category: "system-service", Confidence: "HIGH",
				Evidence: append(evidence, "systemd unit description for "+strconv.Quote(owner.Service)),
				PortHint: portHint,
			}
		}
		if owner.Process != "" {
			return model.ServiceIdentity{
				Name: owner.Process + " process", Category: "application", Confidence: "MEDIUM",
				Evidence: append(evidence, "observed process name is "+strconv.Quote(owner.Process)),
				PortHint: portHint,
			}
		}
	}
	if container != "" {
		return model.ServiceIdentity{
			Name: container + " container", Category: "containerized-application", Confidence: "MEDIUM",
			Evidence: evidence, PortHint: portHint,
		}
	}
	if portHint != "" {
		return model.ServiceIdentity{
			Name: friendlyPortService(portHint), Category: "port-convention", Confidence: "LOW",
			Evidence: []string{"only the conventional TCP port assignment is known"},
			PortHint: portHint,
		}
	}
	return model.ServiceIdentity{Name: "Unknown service", Category: "unknown", Confidence: "UNKNOWN", Evidence: evidence}
}

func (resolver *Resolver) portHint(protocol string, port uint16) string {
	return resolver.services[strings.ToLower(protocol)+"/"+strconv.Itoa(int(port))]
}

func confidence(score int) string {
	if score >= 90 {
		return "HIGH"
	}
	if score >= 60 {
		return "MEDIUM"
	}
	return "LOW"
}

func unitMatches(actual, expected string) bool {
	actual, expected = strings.ToLower(actual), strings.ToLower(expected)
	if actual == expected {
		return true
	}
	if strings.HasSuffix(expected, ".service") {
		prefix := strings.TrimSuffix(expected, ".service") + "@"
		return strings.HasPrefix(actual, prefix) && strings.HasSuffix(actual, ".service")
	}
	return false
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func containsPort(values []uint16, wanted uint16) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func imageMatches(actual string, expected []string) bool {
	for _, value := range expected {
		normalized := imageRepository(value)
		if actual == normalized || strings.HasSuffix(actual, "/"+normalized) {
			return true
		}
	}
	return false
}

func imageRepository(value string) string {
	value = strings.TrimSpace(value)
	if at := strings.IndexByte(value, '@'); at >= 0 {
		value = value[:at]
	}
	lastSlash := strings.LastIndexByte(value, '/')
	if colon := strings.LastIndexByte(value, ':'); colon > lastSlash {
		value = value[:colon]
	}
	return strings.ToLower(path.Clean(value))
}

func friendlyPortService(name string) string {
	switch strings.ToLower(name) {
	case "ssh":
		return "SSH service"
	case "http", "www":
		return "HTTP web service"
	case "https":
		return "HTTPS web service"
	case "domain":
		return "DNS service"
	case "ipp":
		return "IPP printing service"
	case "postgresql":
		return "PostgreSQL service"
	case "mysql":
		return "MySQL service"
	default:
		return strings.ToUpper(name) + " service"
	}
}

func endpointKey(protocol string, port uint16) string {
	return strings.ToLower(protocol) + "/" + strconv.Itoa(int(port))
}

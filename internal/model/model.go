package model

import "net/netip"

type Verdict string

const (
	Confirmed Verdict = "CONFIRMED"
	Potential Verdict = "POTENTIAL"
	NotLocal  Verdict = "NOT_EXPOSED_LOCALLY"
	Unknown   Verdict = "UNKNOWN"
)

type Endpoint struct {
	Protocol string     `json:"protocol"`
	Address  netip.Addr `json:"address"`
	Port     uint16     `json:"port"`
}

type Owner struct {
	PID                int    `json:"pid,omitempty"`
	Process            string `json:"process,omitempty"`
	Executable         string `json:"executable,omitempty"`
	Command            string `json:"command,omitempty"`
	Service            string `json:"service,omitempty"`
	ServiceDescription string `json:"service_description,omitempty"`
	Container          string `json:"container,omitempty"`
	Cgroup             string `json:"cgroup,omitempty"`
	NetNS              uint64 `json:"network_namespace,omitempty"`
}

type Listener struct {
	Endpoint   Endpoint          `json:"endpoint"`
	Inode      uint64            `json:"inode"`
	UID        uint32            `json:"uid"`
	NetNS      uint64            `json:"network_namespace,omitempty"`
	Owner      *Owner            `json:"owner,omitempty"`
	Activation *SocketActivation `json:"socket_activation,omitempty"`
}

type NATMapping struct {
	Protocol        string            `json:"protocol"`
	HostAddress     netip.Addr        `json:"host_address"`
	HostPort        uint16            `json:"host_port"`
	ContainerIP     netip.Addr        `json:"container_ip,omitempty"`
	ContainerPort   uint16            `json:"container_port"`
	ContainerName   string            `json:"container_name"`
	ContainerID     string            `json:"container_id,omitempty"`
	ContainerImage  string            `json:"container_image,omitempty"`
	ContainerLabels map[string]string `json:"container_labels,omitempty"`
}

type FirewallVerdict string

const (
	FirewallAccept        FirewallVerdict = "ACCEPT"
	FirewallDrop          FirewallVerdict = "DROP"
	FirewallUnknown       FirewallVerdict = "UNKNOWN"
	FirewallNotConfigured FirewallVerdict = "NOT_CONFIGURED"
)

type FirewallObservation struct {
	Backend  string          `json:"backend"`
	Chain    string          `json:"chain"`
	Verdict  FirewallVerdict `json:"verdict"`
	Evidence string          `json:"evidence,omitempty"`
	Error    string          `json:"error,omitempty"`
}

type Facts struct {
	Listeners []Listener            `json:"listeners"`
	Mappings  []NATMapping          `json:"nat_mappings"`
	Firewall  []FirewallObservation `json:"firewall"`
	Warnings  []string              `json:"warnings,omitempty"`
}

type PathStep struct {
	Kind     string `json:"kind"`
	Decision string `json:"decision"`
	Evidence string `json:"evidence"`
}

type Path struct {
	Endpoint Endpoint        `json:"endpoint"`
	Owner    *Owner          `json:"owner,omitempty"`
	Identity ServiceIdentity `json:"service_identity"`
	Verdict  Verdict         `json:"verdict"`
	Steps    []PathStep      `json:"steps"`
}

type Query struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

type Report struct {
	SchemaVersion int      `json:"schema_version"`
	Query         Query    `json:"query"`
	Verdict       Verdict  `json:"verdict"`
	Paths         []Path   `json:"paths"`
	Unknowns      []string `json:"unknowns,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

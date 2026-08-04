package model

type BindScope string

const (
	AllInterfaces     BindScope = "ALL_INTERFACES"
	SpecificInterface BindScope = "SPECIFIC_INTERFACE"
	LoopbackOnly      BindScope = "LOOPBACK_ONLY"
)

type OverviewEntry struct {
	Protocol  string          `json:"protocol"`
	Port      uint16          `json:"port"`
	Identity  ServiceIdentity `json:"service_identity"`
	Binds     []string        `json:"binds"`
	Owners    []string        `json:"owners"`
	Sources   []string        `json:"sources"`
	BindScope BindScope       `json:"bind_scope"`
}

type OverviewReport struct {
	SchemaVersion int             `json:"schema_version"`
	Mode          string          `json:"mode"`
	Entries       []OverviewEntry `json:"entries"`
	Warnings      []string        `json:"warnings,omitempty"`
}

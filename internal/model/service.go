package model

type ServiceIdentity struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
	PortHint   string   `json:"port_hint,omitempty"`
}

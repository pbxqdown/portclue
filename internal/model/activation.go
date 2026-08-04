package model

import "net/netip"

type SocketActivation struct {
	Address        netip.Addr `json:"address"`
	Port           uint16     `json:"port"`
	SocketUnit     string     `json:"socket_unit"`
	TriggerService string     `json:"trigger_service,omitempty"`
	Description    string     `json:"description,omitempty"`
}

package identify

import (
	"strconv"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

func (resolver *Resolver) socketActivation(activation model.SocketActivation, portHint string) model.ServiceIdentity {
	owner := model.Owner{
		Service:            activation.TriggerService,
		ServiceDescription: trimSocketSuffix(activation.Description),
	}
	best, score, evidence := resolver.matchOwner(owner)
	activationEvidence := "active systemd socket unit " + strconv.Quote(activation.SocketUnit)
	if activation.TriggerService != "" {
		activationEvidence += " triggers " + strconv.Quote(activation.TriggerService)
	}
	evidence = append([]string{activationEvidence}, evidence...)
	if score > 0 {
		return identity(best, confidence(score), evidence, portHint)
	}
	if activation.Description != "" {
		return model.ServiceIdentity{
			Name:       trimSocketSuffix(activation.Description),
			Category:   "system-service",
			Confidence: "HIGH",
			Evidence:   evidence,
			PortHint:   portHint,
		}
	}
	return fallbackIdentity(&owner, "", evidence, portHint)
}

func trimSocketSuffix(value string) string {
	value = strings.TrimSpace(value)
	for _, suffix := range []string{" activation socket", " socket", " Socket"} {
		if strings.HasSuffix(value, suffix) {
			return strings.TrimSpace(strings.TrimSuffix(value, suffix))
		}
	}
	return value
}

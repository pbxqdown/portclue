package analyze

import "github.com/pbxqdown/portclue/internal/model"

func (builder *overviewBuilder) considerIdentity(candidate model.ServiceIdentity) {
	if confidenceRank(candidate.Confidence) >= confidenceRank(builder.entry.Identity.Confidence) {
		builder.entry.Identity = candidate
	}
}

func confidenceRank(value string) int {
	switch value {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

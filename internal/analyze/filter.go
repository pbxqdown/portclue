package analyze

import (
	"fmt"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

// OverviewFilter narrows overview entries after collection and identification.
// Empty fields mean "no constraint".
type OverviewFilter struct {
	BindScopes    map[model.BindScope]struct{}
	Sources       map[string]struct{}
	MinConfidence string
}

func (filter OverviewFilter) Active() bool {
	return len(filter.BindScopes) > 0 || len(filter.Sources) > 0 || filter.MinConfidence != ""
}

// ParseOverviewFilter validates overview-only CLI filter values.
func ParseOverviewFilter(bindScope, source, minConfidence string) (OverviewFilter, error) {
	filter := OverviewFilter{}
	if bindScope != "" {
		parts := splitCSV(bindScope)
		if len(parts) == 0 {
			return OverviewFilter{}, fmt.Errorf("invalid bind-scope %q (expected ALL_INTERFACES, SPECIFIC_INTERFACE, LOOPBACK_ONLY)", bindScope)
		}
		filter.BindScopes = make(map[model.BindScope]struct{}, len(parts))
		for _, part := range parts {
			scope := model.BindScope(part)
			switch scope {
			case model.AllInterfaces, model.SpecificInterface, model.LoopbackOnly:
				filter.BindScopes[scope] = struct{}{}
			default:
				return OverviewFilter{}, fmt.Errorf("invalid bind-scope %q (expected ALL_INTERFACES, SPECIFIC_INTERFACE, LOOPBACK_ONLY)", part)
			}
		}
	}
	if source != "" {
		parts := splitCSV(source)
		if len(parts) == 0 {
			return OverviewFilter{}, fmt.Errorf("invalid source %q (expected host or docker)", source)
		}
		filter.Sources = make(map[string]struct{}, len(parts))
		for _, part := range parts {
			switch part {
			case "host", "docker":
				filter.Sources[part] = struct{}{}
			default:
				return OverviewFilter{}, fmt.Errorf("invalid source %q (expected host or docker)", part)
			}
		}
	}
	if minConfidence != "" {
		switch minConfidence {
		case "HIGH", "MEDIUM", "LOW", "UNKNOWN":
			filter.MinConfidence = minConfidence
		default:
			return OverviewFilter{}, fmt.Errorf("invalid min-confidence %q (expected HIGH, MEDIUM, LOW, or UNKNOWN)", minConfidence)
		}
	}
	return filter, nil
}

// FilterOverview returns a copy of report with entries matching filter.
func FilterOverview(report model.OverviewReport, filter OverviewFilter) model.OverviewReport {
	if !filter.Active() {
		return report
	}
	filtered := model.OverviewReport{
		SchemaVersion: report.SchemaVersion,
		Mode:          report.Mode,
		Entries:       make([]model.OverviewEntry, 0, len(report.Entries)),
		Warnings:      append([]string(nil), report.Warnings...),
	}
	for _, entry := range report.Entries {
		if matchesOverviewFilter(entry, filter) {
			filtered.Entries = append(filtered.Entries, entry)
		}
	}
	return filtered
}

func matchesOverviewFilter(entry model.OverviewEntry, filter OverviewFilter) bool {
	if len(filter.BindScopes) > 0 {
		if _, ok := filter.BindScopes[entry.BindScope]; !ok {
			return false
		}
	}
	if len(filter.Sources) > 0 {
		matched := false
		for _, source := range entry.Sources {
			if _, ok := filter.Sources[source]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if filter.MinConfidence != "" && confidenceRank(entry.Identity.Confidence) < confidenceRank(filter.MinConfidence) {
		return false
	}
	return true
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

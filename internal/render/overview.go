package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

func OverviewJSON(writer io.Writer, report model.OverviewReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

func OverviewText(writer io.Writer, report model.OverviewReport) error {
	var output strings.Builder
	output.WriteString("LOCAL TCP LISTENERS\n\n")
	if len(report.Entries) == 0 {
		output.WriteString("No TCP listeners or Docker published ports were found.\n")
	} else {
		serviceWidth, bindWidth, ownerWidth, sourceWidth := len("SERVICE"), len("BIND"), len("OWNER"), len("SOURCE")
		for _, entry := range report.Entries {
			serviceWidth = max(serviceWidth, len(entry.Identity.Name))
			bindWidth = max(bindWidth, len(strings.Join(entry.Binds, ",")))
			ownerWidth = max(ownerWidth, len(strings.Join(entry.Owners, ",")))
			sourceWidth = max(sourceWidth, len(strings.Join(entry.Sources, ",")))
		}
		fmt.Fprintf(&output, "%-7s %-*s %-10s %-*s %-*s %-*s %s\n",
			"PORT", serviceWidth, "SERVICE", "CONFIDENCE", bindWidth, "BIND", ownerWidth, "OWNER", sourceWidth, "SOURCE", "BIND SCOPE")
		for _, entry := range report.Entries {
			fmt.Fprintf(&output, "%-7d %-*s %-10s %-*s %-*s %-*s %s\n",
				entry.Port,
				serviceWidth, entry.Identity.Name,
				entry.Identity.Confidence,
				bindWidth, strings.Join(entry.Binds, ","),
				ownerWidth, strings.Join(entry.Owners, ","),
				sourceWidth, strings.Join(entry.Sources, ","),
				entry.BindScope,
			)
		}
		output.WriteString("\nBIND SCOPE describes socket binding, not firewall reachability.\n")
		output.WriteString("Run `portclue PORT` for the complete evidence chain and local exposure verdict.\n")
	}
	if len(report.Warnings) > 0 {
		output.WriteString("\nIncomplete evidence:\n")
		for _, warning := range report.Warnings {
			fmt.Fprintf(&output, "  - %s\n", warning)
		}
	}
	_, err := io.WriteString(writer, output.String())
	return err
}

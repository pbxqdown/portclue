package render

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

func JSON(writer io.Writer, report model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

func Text(writer io.Writer, report model.Report) error {
	var output strings.Builder
	output.WriteString(title(report.Verdict))
	output.WriteString("\n\n")
	fmt.Fprintf(&output, "TCP port %d\n", report.Query.Port)
	if len(report.Paths) == 0 {
		output.WriteString("  No listening socket or Docker published-port mapping was found.\n")
	}
	for _, path := range report.Paths {
		fmt.Fprintf(&output, "\n  %s  [%s]\n", endpoint(path.Endpoint), path.Verdict)
		writeIdentity(&output, path.Identity)
		for _, step := range path.Steps {
			fmt.Fprintf(&output, "    -> %-18s %s\n", step.Decision, step.Evidence)
		}
	}
	if len(report.Unknowns) > 0 {
		output.WriteString("\nUnknown outside this machine:\n")
		for _, item := range report.Unknowns {
			fmt.Fprintf(&output, "  - %s\n", item)
		}
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

func title(verdict model.Verdict) string {
	switch verdict {
	case model.Potential:
		return "POTENTIAL EXTERNAL EXPOSURE"
	case model.NotLocal:
		return "NOT EXPOSED LOCALLY"
	case model.Confirmed:
		return "CONFIRMED EXTERNAL EXPOSURE"
	default:
		return "LOCAL EXPOSURE UNKNOWN"
	}
}

func endpoint(value model.Endpoint) string {
	address := value.Address
	if !address.IsValid() {
		address = netip.IPv4Unspecified()
	}
	return netip.AddrPortFrom(address, value.Port).String() + "/" + value.Protocol
}

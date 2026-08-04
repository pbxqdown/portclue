package render

import (
	"fmt"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

func writeIdentity(output *strings.Builder, identity model.ServiceIdentity) {
	fmt.Fprintf(output, "    Service            %s\n", identity.Name)
	fmt.Fprintf(output, "    Category           %s\n", identity.Category)
	fmt.Fprintf(output, "    Confidence         %s\n", identity.Confidence)
	if identity.PortHint != "" {
		fmt.Fprintf(output, "    Port convention    %s\n", identity.PortHint)
	}
	for _, evidence := range identity.Evidence {
		fmt.Fprintf(output, "    Identity evidence  %s\n", evidence)
	}
}

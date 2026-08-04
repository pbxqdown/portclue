package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestEmptyReportText(t *testing.T) {
	var output bytes.Buffer
	report := model.Report{Query: model.Query{Protocol: "tcp", Port: 65534}, Verdict: model.NotLocal}
	if err := Text(&output, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "No listening socket") {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestOverviewText(t *testing.T) {
	report := model.OverviewReport{
		Entries: []model.OverviewEntry{{
			Protocol:  "tcp",
			Port:      8080,
			Identity:  model.ServiceIdentity{Name: "NGINX web server", Confidence: "HIGH"},
			Binds:     []string{"0.0.0.0"},
			Owners:    []string{"web"},
			Sources:   []string{"docker"},
			BindScope: model.AllInterfaces,
		}},
	}
	var output bytes.Buffer
	if err := OverviewText(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"LOCAL TCP LISTENERS", "NGINX web server", "8080", "web", "ALL_INTERFACES", "not firewall reachability", "portclue PORT"} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("output does not contain %q: %s", wanted, output.String())
		}
	}
}

func TestOverviewJSONMode(t *testing.T) {
	report := model.OverviewReport{
		SchemaVersion: 2,
		Mode:          "overview",
		Entries: []model.OverviewEntry{{
			Protocol: "tcp", Port: 8080, BindScope: model.AllInterfaces,
		}},
	}
	var output bytes.Buffer
	if err := OverviewJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{`"mode": "overview"`, `"schema_version": 2`, `"bind_scope": "ALL_INTERFACES"`} {
		if !strings.Contains(output.String(), wanted) {
			t.Fatalf("output does not contain %q: %s", wanted, output.String())
		}
	}
}

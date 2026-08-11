package analyze

import (
	"reflect"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestParseOverviewFilter(t *testing.T) {
	filter, err := ParseOverviewFilter("ALL_INTERFACES, LOOPBACK_ONLY", "host,docker", "MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := filter.BindScopes[model.AllInterfaces]; !ok {
		t.Fatalf("missing ALL_INTERFACES: %#v", filter.BindScopes)
	}
	if _, ok := filter.BindScopes[model.LoopbackOnly]; !ok {
		t.Fatalf("missing LOOPBACK_ONLY: %#v", filter.BindScopes)
	}
	if _, ok := filter.Sources["host"]; !ok {
		t.Fatalf("missing host: %#v", filter.Sources)
	}
	if filter.MinConfidence != "MEDIUM" {
		t.Fatalf("min confidence = %q", filter.MinConfidence)
	}
}

func TestParseOverviewFilterRejectsUnknown(t *testing.T) {
	if _, err := ParseOverviewFilter("PUBLIC", "", ""); err == nil {
		t.Fatal("expected bind-scope error")
	}
	if _, err := ParseOverviewFilter("", "podman", ""); err == nil {
		t.Fatal("expected source error")
	}
	if _, err := ParseOverviewFilter("", "", "LIKELY"); err == nil {
		t.Fatal("expected min-confidence error")
	}
}

func TestFilterOverview(t *testing.T) {
	report := model.OverviewReport{
		SchemaVersion: 2,
		Mode:          "overview",
		Entries: []model.OverviewEntry{
			{
				Port: 22, BindScope: model.AllInterfaces, Sources: []string{"host"},
				Identity: model.ServiceIdentity{Name: "ssh", Confidence: "HIGH"},
			},
			{
				Port: 8080, BindScope: model.AllInterfaces, Sources: []string{"docker"},
				Identity: model.ServiceIdentity{Name: "api", Confidence: "MEDIUM"},
			},
			{
				Port: 53, BindScope: model.LoopbackOnly, Sources: []string{"host"},
				Identity: model.ServiceIdentity{Name: "dns", Confidence: "LOW"},
			},
			{
				Port: 9, BindScope: model.SpecificInterface, Sources: []string{"host"},
				Identity: model.ServiceIdentity{Name: "mystery", Confidence: "UNKNOWN"},
			},
		},
		Warnings: []string{"note"},
	}

	filter, err := ParseOverviewFilter("ALL_INTERFACES", "host", "MEDIUM")
	if err != nil {
		t.Fatal(err)
	}
	got := FilterOverview(report, filter)
	if got.SchemaVersion != 2 || got.Mode != "overview" {
		t.Fatalf("metadata = %+v", got)
	}
	if !reflect.DeepEqual(got.Warnings, []string{"note"}) {
		t.Fatalf("warnings = %#v", got.Warnings)
	}
	if len(got.Entries) != 1 || got.Entries[0].Port != 22 {
		t.Fatalf("entries = %+v, want only port 22", got.Entries)
	}
}

func TestFilterOverviewInactivePassthrough(t *testing.T) {
	report := model.OverviewReport{Entries: []model.OverviewEntry{{Port: 1}}}
	got := FilterOverview(report, OverviewFilter{})
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want passthrough", len(got.Entries))
	}
}

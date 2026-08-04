package render

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestDetailedJSONContractV1(t *testing.T) {
	report := model.Report{
		SchemaVersion: 1,
		Query:         model.Query{Protocol: "tcp", Port: 8080},
		Verdict:       model.Unknown,
		Paths: []model.Path{{
			Endpoint: model.Endpoint{Protocol: "tcp", Address: netip.IPv4Unspecified(), Port: 8080},
			Owner:    &model.Owner{PID: 42, Process: "nginx", Service: "nginx.service"},
			Identity: model.ServiceIdentity{
				Name: "NGINX web server", Category: "web", Confidence: "HIGH",
				Evidence: []string{"executable matched nginx"}, PortHint: "http",
			},
			Verdict: model.Unknown,
			Steps: []model.PathStep{{
				Kind: "listener", Decision: "LISTEN", Evidence: "socket is listening",
			}},
		}},
		Unknowns: []string{"router port forwarding"},
		Warnings: []string{"firewall evidence incomplete"},
	}
	var output bytes.Buffer
	if err := JSON(&output, report); err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, output.Bytes(), []byte(`{
		"schema_version": 1,
		"query": {"protocol": "tcp", "port": 8080},
		"verdict": "UNKNOWN",
		"paths": [{
			"endpoint": {"protocol": "tcp", "address": "0.0.0.0", "port": 8080},
			"owner": {"pid": 42, "process": "nginx", "service": "nginx.service"},
			"service_identity": {
				"name": "NGINX web server",
				"category": "web",
				"confidence": "HIGH",
				"evidence": ["executable matched nginx"],
				"port_hint": "http"
			},
			"verdict": "UNKNOWN",
			"steps": [{"kind": "listener", "decision": "LISTEN", "evidence": "socket is listening"}]
		}],
		"unknowns": ["router port forwarding"],
		"warnings": ["firewall evidence incomplete"]
	}`))
}

func TestOverviewJSONContractV2(t *testing.T) {
	report := model.OverviewReport{
		SchemaVersion: 2,
		Mode:          "overview",
		Entries: []model.OverviewEntry{{
			Protocol: "tcp",
			Port:     8080,
			Identity: model.ServiceIdentity{
				Name: "api service", Category: "containerized-application", Confidence: "MEDIUM",
				Evidence: []string{"Compose label is api"},
			},
			Binds:     []string{"0.0.0.0", "::"},
			Owners:    []string{"demo-api"},
			Sources:   []string{"docker"},
			BindScope: model.AllInterfaces,
		}},
		Warnings: []string{"process ownership incomplete"},
	}
	var output bytes.Buffer
	if err := OverviewJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, output.Bytes(), []byte(`{
		"schema_version": 2,
		"mode": "overview",
		"entries": [{
			"protocol": "tcp",
			"port": 8080,
			"service_identity": {
				"name": "api service",
				"category": "containerized-application",
				"confidence": "MEDIUM",
				"evidence": ["Compose label is api"]
			},
			"binds": ["0.0.0.0", "::"],
			"owners": ["demo-api"],
			"sources": ["docker"],
			"bind_scope": "ALL_INTERFACES"
		}],
		"warnings": ["process ownership incomplete"]
	}`))
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("invalid actual JSON: %v\n%s", err, got)
	}
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("invalid expected JSON: %v\n%s", err, want)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON contract mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

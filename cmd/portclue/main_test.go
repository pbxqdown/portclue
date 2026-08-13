package main

import "testing"

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name          string
		fallback      string
		moduleVersion string
		want          string
	}{
		{name: "ldflags release", fallback: "0.1.0", moduleVersion: "v0.1.0", want: "0.1.0"},
		{name: "go install module tag", fallback: "0.1.0-dev", moduleVersion: "v0.1.0", want: "0.1.0"},
		{name: "local devel", fallback: "0.1.0-dev", moduleVersion: "(devel)", want: "0.1.0-dev"},
		{name: "empty module", fallback: "0.1.0-dev", moduleVersion: "", want: "0.1.0-dev"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveVersion(test.fallback, test.moduleVersion); got != test.want {
				t.Fatalf("resolveVersion(%q, %q) = %q, want %q", test.fallback, test.moduleVersion, got, test.want)
			}
		})
	}
}

func TestArgumentExitCodes(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      int
	}{
		{name: "long help", arguments: []string{"--help"}, want: 0},
		{name: "short help", arguments: []string{"-h"}, want: 0},
		{name: "version", arguments: []string{"--version"}, want: 0},
		{name: "unknown flag", arguments: []string{"--not-a-real-flag"}, want: 2},
		{name: "zero port", arguments: []string{"0"}, want: 2},
		{name: "overflow port", arguments: []string{"65536"}, want: 2},
		{name: "non-numeric port", arguments: []string{"abc"}, want: 2},
		{name: "too many ports", arguments: []string{"22", "23"}, want: 2},
		{name: "bad bind-scope", arguments: []string{"--bind-scope", "PUBLIC"}, want: 2},
		{name: "bad source", arguments: []string{"--source", "podman"}, want: 2},
		{name: "bad min-confidence", arguments: []string{"--min-confidence", "LIKELY"}, want: 2},
		{name: "filter with port", arguments: []string{"--bind-scope", "ALL_INTERFACES", "8080"}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := run(test.arguments); got != test.want {
				t.Fatalf("exit code = %d, want %d", got, test.want)
			}
		})
	}
}

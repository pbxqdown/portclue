package main

import "testing"

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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := run(test.arguments); got != test.want {
				t.Fatalf("exit code = %d, want %d", got, test.want)
			}
		})
	}
}

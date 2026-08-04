//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnitDescription(t *testing.T) {
	root := t.TempDir()
	oldRoots := systemdUnitRoots
	systemdUnitRoots = []string{root}
	defer func() { systemdUnitRoots = oldRoots }()

	content := "[Unit]\nDescription=Example database service\n[Service]\nExecStart=/usr/bin/example\n"
	if err := os.WriteFile(filepath.Join(root, "example.service"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := unitDescription("example.service"); got != "Example database service" {
		t.Fatalf("description = %q", got)
	}
}

func TestTemplateUnitDescription(t *testing.T) {
	root := t.TempDir()
	oldRoots := systemdUnitRoots
	systemdUnitRoots = []string{root}
	defer func() { systemdUnitRoots = oldRoots }()

	if err := os.WriteFile(filepath.Join(root, "worker@.service"), []byte("[Unit]\nDescription=Worker instance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := unitDescription("worker@blue.service"); got != "Worker instance" {
		t.Fatalf("description = %q", got)
	}
}

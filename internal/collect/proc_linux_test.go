//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketInode(t *testing.T) {
	inode, ok := socketInode("socket:[123456]")
	if !ok || inode != 123456 {
		t.Fatalf("got (%d, %v)", inode, ok)
	}
	if _, ok := socketInode("pipe:[123456]"); ok {
		t.Fatal("pipe was accepted as a socket")
	}
}

func TestCgroupAndUnit(t *testing.T) {
	path := cgroupPath("0::/system.slice/ssh.service\n")
	if path != "/system.slice/ssh.service" {
		t.Fatalf("path = %q", path)
	}
	if unit := systemdUnit(path); unit != "ssh.service" {
		t.Fatalf("unit = %q", unit)
	}
}

func TestReadOwnerFromProcFixture(t *testing.T) {
	root := t.TempDir()
	pidRoot := filepath.Join(root, "42")
	if err := os.MkdirAll(filepath.Join(pidRoot, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(pidRoot, "comm"), "example-daemon\n")
	writeFixture(t, filepath.Join(pidRoot, "cmdline"), "example-daemon\x00--serve\x00")
	writeFixture(t, filepath.Join(pidRoot, "cgroup"), "0::/system.slice/example-worker.service\n")
	if err := os.Symlink("/usr/bin/example-daemon", filepath.Join(pidRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531993]", filepath.Join(pidRoot, "ns", "net")); err != nil {
		t.Fatal(err)
	}

	owner := readOwner(root, 42)
	if owner.PID != 42 || owner.Process != "example-daemon" ||
		owner.Executable != "/usr/bin/example-daemon" ||
		owner.Command != "example-daemon --serve" ||
		owner.Service != "example-worker.service" ||
		owner.NetNS != 4026531993 {
		t.Fatalf("owner = %+v", owner)
	}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pbxqdown/portclue/internal/model"
)

func AttachProcessOwners(listeners []model.Listener) ([]model.Listener, []string) {
	wanted := make(map[uint64]struct{}, len(listeners))
	for _, listener := range listeners {
		wanted[listener.Inode] = struct{}{}
	}
	owners, warnings := findSocketOwners("/proc", wanted)
	for i := range listeners {
		if owner, ok := owners[listeners[i].Inode]; ok {
			copy := owner
			listeners[i].Owner = &copy
			listeners[i].NetNS = owner.NetNS
		}
	}
	return listeners, warnings
}

func findSocketOwners(procRoot string, wanted map[uint64]struct{}) (map[uint64]model.Owner, []string) {
	result := make(map[uint64]model.Owner)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result, []string{fmt.Sprintf("read %s: %v", procRoot, err)}
	}
	permissionDenied := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if os.IsPermission(err) {
				permissionDenied++
			}
			continue
		}
		var owner *model.Owner
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			if _, ok := wanted[inode]; !ok {
				continue
			}
			if _, exists := result[inode]; exists {
				continue
			}
			if owner == nil {
				value := readOwner(procRoot, pid)
				owner = &value
			}
			result[inode] = *owner
		}
	}
	var warnings []string
	if permissionDenied > 0 {
		warnings = append(warnings, fmt.Sprintf("process ownership may be incomplete: permission denied for %d /proc PID directories (try sudo)", permissionDenied))
	}
	return result, warnings
}

func socketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
	return inode, err == nil
}

func readOwner(procRoot string, pid int) model.Owner {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	owner := model.Owner{PID: pid}
	if data, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		owner.Process = strings.TrimSpace(string(data))
	}
	if target, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		owner.Executable = target
	}
	if data, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		owner.Command = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}
	if data, err := os.ReadFile(filepath.Join(base, "cgroup")); err == nil {
		owner.Cgroup = cgroupPath(string(data))
		owner.Service = systemdUnit(owner.Cgroup)
		owner.ServiceDescription = unitDescription(owner.Service)
	}
	if target, err := os.Readlink(filepath.Join(base, "ns", "net")); err == nil {
		owner.NetNS, _ = bracketedID(target)
	}
	return owner
}

func cgroupPath(content string) string {
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && (parts[0] == "0" || parts[1] == "") {
			return parts[2]
		}
	}
	return ""
}

func systemdUnit(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".service") || strings.HasSuffix(parts[i], ".scope") {
			return parts[i]
		}
	}
	return ""
}

func bracketedID(value string) (uint64, error) {
	start := strings.LastIndexByte(value, '[')
	end := strings.LastIndexByte(value, ']')
	if start < 0 || end <= start {
		return 0, fmt.Errorf("invalid namespace link %q", value)
	}
	return strconv.ParseUint(value[start+1:end], 10, 64)
}

//go:build linux

package collect

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

var systemdUnitRoots = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

func unitDescription(unit string) string {
	if unit == "" {
		return ""
	}
	candidates := []string{unit}
	if at := strings.IndexByte(unit, '@'); at >= 0 {
		if suffix := strings.LastIndexByte(unit, '.'); suffix > at {
			candidates = append(candidates, unit[:at+1]+unit[suffix:])
		}
	}
	for _, candidate := range candidates {
		for _, root := range systemdUnitRoots {
			if description := descriptionFromUnitFile(filepath.Join(root, candidate)); description != "" {
				return description
			}
		}
	}
	return ""
}

func descriptionFromUnitFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	inUnit := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inUnit = line == "[Unit]"
			continue
		}
		if inUnit && strings.HasPrefix(line, "Description=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Description="))
		}
	}
	return ""
}

package identify

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func loadServices(path string) map[string]string {
	result := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		portProtocol := strings.SplitN(fields[1], "/", 2)
		if len(portProtocol) != 2 {
			continue
		}
		port, err := strconv.ParseUint(portProtocol[0], 10, 16)
		if err != nil || port == 0 {
			continue
		}
		key := endpointKey(portProtocol[1], uint16(port))
		if _, exists := result[key]; !exists {
			result[key] = fields[0]
		}
	}
	return result
}

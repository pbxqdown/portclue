package collect

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestDockerMappingsFromUnixSocket(t *testing.T) {
	socket := serveDockerAPI(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/containers/json" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `[{
			"Id":"1234567890abcdef",
			"Names":["/demo-api"],
			"Image":"example/demo-api:1.0",
			"Labels":{"com.docker.compose.service":"api"},
			"Ports":[
				{"IP":"0.0.0.0","PrivatePort":18080,"PublicPort":18080,"Type":"tcp"},
				{"IP":"::","PrivatePort":18080,"PublicPort":18080,"Type":"tcp"},
				{"PrivatePort":9000,"PublicPort":0,"Type":"tcp"}
			]
		}]`)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	mappings, err := DockerMappings(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mappings = %d, want 2: %+v", len(mappings), mappings)
	}
	if got := mappings[0]; got.HostAddress != netip.IPv4Unspecified() ||
		got.HostPort != 18080 || got.ContainerPort != 18080 ||
		got.ContainerName != "demo-api" || got.ContainerID != "1234567890ab" ||
		got.ContainerImage != "example/demo-api:1.0" ||
		got.ContainerLabels["com.docker.compose.service"] != "api" {
		t.Fatalf("IPv4 mapping = %+v", got)
	}
	if got := mappings[1].HostAddress; got != netip.IPv6Unspecified() {
		t.Fatalf("IPv6 host address = %s, want ::", got)
	}
}

func TestDockerMappingsRejectsBadResponse(t *testing.T) {
	socket := serveDockerAPI(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	_, err := DockerMappings(context.Background(), socket)
	if err == nil {
		t.Fatal("expected Docker status error")
	}
}

func serveDockerAPI(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	return socket
}

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pbxqdown/portclue/internal/model"
)

func TestParseNFTDirectAccept(t *testing.T) {
	data := fixture(t, "../../testdata/nft/input_accept_8080.json")
	observation, err := parseNFT(data, 8080, "input")
	if err != nil {
		t.Fatal(err)
	}
	if observation.Verdict != model.FirewallAccept {
		t.Fatalf("verdict = %s, want %s", observation.Verdict, model.FirewallAccept)
	}
}

func TestParseNFTUnsupportedExpressionIsUnknown(t *testing.T) {
	data := fixture(t, "../../testdata/nft/input_unsupported.json")
	observation, err := parseNFT(data, 8080, "input")
	if err != nil {
		t.Fatal(err)
	}
	if observation.Verdict != model.FirewallUnknown {
		t.Fatalf("verdict = %s, want %s", observation.Verdict, model.FirewallUnknown)
	}
}

func TestParseIPTablesDrop(t *testing.T) {
	data := string(fixture(t, "../../testdata/iptables/input_drop.txt"))
	observation := parseIPTables(data, 8080, "INPUT")
	if observation.Verdict != model.FirewallDrop {
		t.Fatalf("verdict = %s, want %s", observation.Verdict, model.FirewallDrop)
	}
}

func fixture(t *testing.T, relative string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(relative))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

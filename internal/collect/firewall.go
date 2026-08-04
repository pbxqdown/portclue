package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pbxqdown/portclue/internal/model"
)

func Firewall(ctx context.Context, port uint16, chain string) model.FirewallObservation {
	if observation, ok := nftFirewall(ctx, port, chain); ok {
		return observation
	}
	if observation, ok := iptablesFirewall(ctx, port, chain); ok {
		return observation
	}
	return model.FirewallObservation{
		Backend: "unavailable", Chain: chain, Verdict: model.FirewallUnknown,
		Error: "neither nftables nor iptables rules could be read",
	}
}

func nftFirewall(parent context.Context, port uint16, wantedHook string) (model.FirewallObservation, bool) {
	if _, err := exec.LookPath("nft"); err != nil {
		return model.FirewallObservation{}, false
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "nft", "--json", "list", "ruleset").Output()
	if err != nil {
		return model.FirewallObservation{}, false
	}
	observation, err := parseNFT(output, port, wantedHook)
	if err != nil {
		return model.FirewallObservation{
			Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallUnknown, Error: err.Error(),
		}, true
	}
	return observation, true
}

type nftDocument struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

func parseNFT(data []byte, port uint16, wantedHook string) (model.FirewallObservation, error) {
	var document nftDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return model.FirewallObservation{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	var bases []nftChain
	var rules []nftRule
	for _, object := range document.Nftables {
		if raw, ok := object["chain"]; ok {
			var chain nftChain
			if err := json.Unmarshal(raw, &chain); err == nil && strings.EqualFold(chain.Hook, wantedHook) {
				bases = append(bases, chain)
			}
		}
		if raw, ok := object["rule"]; ok {
			var rule nftRule
			if err := json.Unmarshal(raw, &rule); err == nil {
				rules = append(rules, rule)
			}
		}
	}
	if len(bases) == 0 {
		return model.FirewallObservation{
			Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallNotConfigured,
			Evidence: "no nftables base chain is attached to the " + wantedHook + " hook",
		}, nil
	}
	if len(bases) > 1 {
		return model.FirewallObservation{
			Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallUnknown,
			Evidence: fmt.Sprintf("%d base chains are attached to the %s hook; cross-chain priority evaluation is not implemented", len(bases), wantedHook),
		}, nil
	}
	base := bases[0]
	for _, rule := range rules {
		if rule.Family != base.Family || rule.Table != base.Table || rule.Chain != base.Name {
			continue
		}
		applies, verdict, evidence, conclusive := evaluateNFTRule(rule.Expr, port)
		if !applies {
			continue
		}
		if !conclusive {
			return model.FirewallObservation{
				Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallUnknown,
				Evidence: evidence,
			}, nil
		}
		return model.FirewallObservation{
			Backend: "nftables", Chain: wantedHook, Verdict: verdict, Evidence: evidence,
		}, nil
	}
	policy := strings.ToUpper(base.Policy)
	switch policy {
	case "ACCEPT":
		return model.FirewallObservation{Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallAccept, Evidence: "base chain policy is accept and no supported earlier rule matched"}, nil
	case "DROP":
		return model.FirewallObservation{Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallDrop, Evidence: "base chain policy is drop and no supported earlier rule matched"}, nil
	default:
		return model.FirewallObservation{Backend: "nftables", Chain: wantedHook, Verdict: model.FirewallUnknown, Evidence: "base chain has no supported conclusive rule or policy"}, nil
	}
}

func evaluateNFTRule(expressions []json.RawMessage, port uint16) (bool, model.FirewallVerdict, string, bool) {
	portConstraint := false
	unknownCondition := false
	verdict := model.FirewallUnknown
	for _, raw := range expressions {
		var expression map[string]json.RawMessage
		if json.Unmarshal(raw, &expression) != nil {
			unknownCondition = true
			continue
		}
		if _, ok := expression["counter"]; ok {
			continue
		}
		if rawMatch, ok := expression["match"]; ok {
			kind, value, supported := nftMatch(rawMatch)
			if !supported {
				unknownCondition = true
				continue
			}
			switch kind {
			case "dport":
				portConstraint = true
				if value != strconv.Itoa(int(port)) {
					return false, model.FirewallUnknown, "", true
				}
			case "protocol":
				if !strings.EqualFold(value, "tcp") {
					return false, model.FirewallUnknown, "", true
				}
			}
			continue
		}
		if _, ok := expression["accept"]; ok {
			verdict = model.FirewallAccept
			continue
		}
		if _, ok := expression["drop"]; ok {
			verdict = model.FirewallDrop
			continue
		}
		if _, ok := expression["reject"]; ok {
			verdict = model.FirewallDrop
			continue
		}
		unknownCondition = true
	}
	if verdict == model.FirewallUnknown {
		return false, verdict, "", true
	}
	if unknownCondition {
		return true, model.FirewallUnknown, "a potentially matching nftables rule contains an unsupported expression", false
	}
	what := "all TCP traffic"
	if portConstraint {
		what = fmt.Sprintf("TCP destination port %d", port)
	}
	return true, verdict, fmt.Sprintf("a direct nftables rule matches %s and returns %s", what, strings.ToLower(string(verdict))), true
}

func nftMatch(raw json.RawMessage) (kind, value string, supported bool) {
	var match struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if json.Unmarshal(raw, &match) != nil || match.Op != "==" {
		return "", "", false
	}
	var left map[string]json.RawMessage
	if json.Unmarshal(match.Left, &left) != nil {
		return "", "", false
	}
	if payloadRaw, ok := left["payload"]; ok {
		var payload struct{ Protocol, Field string }
		if json.Unmarshal(payloadRaw, &payload) == nil && payload.Protocol == "tcp" && payload.Field == "dport" {
			var number uint16
			if json.Unmarshal(match.Right, &number) == nil {
				return "dport", strconv.Itoa(int(number)), true
			}
		}
	}
	if metaRaw, ok := left["meta"]; ok {
		var meta struct {
			Key string `json:"key"`
		}
		var protocol string
		if json.Unmarshal(metaRaw, &meta) == nil && meta.Key == "l4proto" && json.Unmarshal(match.Right, &protocol) == nil {
			return "protocol", protocol, true
		}
	}
	return "", "", false
}

func iptablesFirewall(parent context.Context, port uint16, wantedChain string) (model.FirewallObservation, bool) {
	if _, err := exec.LookPath("iptables-save"); err != nil {
		return model.FirewallObservation{}, false
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "iptables-save", "-t", "filter").Output()
	if err != nil {
		return model.FirewallObservation{}, false
	}
	return parseIPTables(string(output), port, strings.ToUpper(wantedChain)), true
}

func parseIPTables(data string, port uint16, chain string) model.FirewallObservation {
	observation := model.FirewallObservation{Backend: "iptables", Chain: chain, Verdict: model.FirewallUnknown}
	policy := ""
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":"+chain+" ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				policy = fields[1]
			}
			continue
		}
		if !strings.HasPrefix(line, "-A "+chain+" ") {
			continue
		}
		applies, verdict, conclusive := evaluateIPTablesRule(strings.Fields(line), port)
		if !applies {
			continue
		}
		if !conclusive {
			observation.Evidence = "a potentially matching iptables rule uses unsupported conditions or jumps"
			return observation
		}
		observation.Verdict = verdict
		observation.Evidence = fmt.Sprintf("a direct iptables rule matches TCP destination port %d and returns %s", port, strings.ToLower(string(verdict)))
		return observation
	}
	switch policy {
	case "ACCEPT":
		observation.Verdict = model.FirewallAccept
		observation.Evidence = "base chain policy is ACCEPT and no supported earlier rule matched"
	case "DROP":
		observation.Verdict = model.FirewallDrop
		observation.Evidence = "base chain policy is DROP and no supported earlier rule matched"
	case "":
		observation.Verdict = model.FirewallNotConfigured
		observation.Evidence = "iptables has no " + chain + " base chain"
	default:
		observation.Evidence = "unsupported iptables base chain policy " + policy
	}
	return observation
}

func evaluateIPTablesRule(fields []string, port uint16) (bool, model.FirewallVerdict, bool) {
	wantedPort := ""
	protocol := ""
	target := ""
	unsupported := false
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-A":
			i++
		case "-p", "--protocol":
			i++
			if i < len(fields) {
				protocol = fields[i]
			}
		case "--dport":
			i++
			if i < len(fields) {
				wantedPort = fields[i]
			}
		case "-j":
			i++
			if i < len(fields) {
				target = fields[i]
			}
		case "-s", "-d":
			i++
			if i < len(fields) && fields[i] != "0.0.0.0/0" {
				unsupported = true
			}
		case "-m":
			i++
			if i < len(fields) && fields[i] != "tcp" {
				unsupported = true
			}
		case "-c":
			i += 2
		default:
			unsupported = true
		}
	}
	if protocol != "" && protocol != "tcp" {
		return false, model.FirewallUnknown, true
	}
	if wantedPort != "" && wantedPort != strconv.Itoa(int(port)) {
		return false, model.FirewallUnknown, true
	}
	var verdict model.FirewallVerdict
	switch target {
	case "ACCEPT":
		verdict = model.FirewallAccept
	case "DROP", "REJECT":
		verdict = model.FirewallDrop
	case "":
		return false, model.FirewallUnknown, true
	default:
		return true, model.FirewallUnknown, false
	}
	if unsupported {
		return true, model.FirewallUnknown, false
	}
	return true, verdict, true
}

var errUnsupported = errors.New("unsupported")

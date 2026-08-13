package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/pbxqdown/portclue/internal/analyze"
	"github.com/pbxqdown/portclue/internal/collect"
	"github.com/pbxqdown/portclue/internal/model"
	"github.com/pbxqdown/portclue/internal/render"
)

var version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func displayVersion() string {
	moduleVersion := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		moduleVersion = info.Main.Version
	}
	return resolveVersion(version, moduleVersion)
}

func resolveVersion(fallback, moduleVersion string) string {
	if fallback != "" && fallback != "0.1.0-dev" {
		return fallback
	}
	if moduleVersion != "" && moduleVersion != "(devel)" {
		return strings.TrimPrefix(moduleVersion, "v")
	}
	return fallback
}

func run(arguments []string) int {
	flags := flag.NewFlagSet("portclue", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "emit the versioned JSON report")
	dockerSocket := flags.String("docker-socket", "/var/run/docker.sock", "Docker Engine Unix socket")
	bindScope := flags.String("bind-scope", "", "overview only: comma-separated ALL_INTERFACES,SPECIFIC_INTERFACE,LOOPBACK_ONLY")
	source := flags.String("source", "", "overview only: comma-separated host,docker")
	minConfidence := flags.String("min-confidence", "", "overview only: HIGH, MEDIUM, LOW, or UNKNOWN")
	showVersion := flags.Bool("version", false, "print version and exit")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: portclue [--json] [--bind-scope SCOPE] [--source SOURCE] [--min-confidence LEVEL] [PORT]")
		fmt.Fprintln(flags.Output(), "List local TCP exposure, or explain one port in detail.")
		fmt.Fprintln(flags.Output(), "Overview filters apply only when PORT is omitted.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, displayVersion())
		return 0
	}
	filter, err := analyze.ParseOverviewFilter(*bindScope, *source, *minConfidence)
	if err != nil {
		fmt.Fprintln(os.Stderr, "portclue:", err)
		return 2
	}
	if flags.NArg() > 1 {
		flags.Usage()
		return 2
	}
	if flags.NArg() == 0 {
		return runOverview(*jsonOutput, *dockerSocket, filter)
	}
	if filter.Active() {
		fmt.Fprintln(os.Stderr, "portclue: --bind-scope, --source, and --min-confidence apply only to overview mode")
		return 2
	}
	parsed, err := strconv.ParseUint(flags.Arg(0), 10, 16)
	if err != nil || parsed == 0 {
		fmt.Fprintf(os.Stderr, "portclue: invalid TCP port %q (expected 1-65535)\n", flags.Arg(0))
		return 2
	}
	port := uint16(parsed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listeners, warnings, err := collect.ListTCPListeners()
	if err != nil {
		fmt.Fprintln(os.Stderr, "portclue:", err)
		return 1
	}
	listeners, procWarnings := collect.AttachProcessOwners(listeners)
	warnings = append(warnings, procWarnings...)
	listeners, socketWarnings := collect.AttachSystemdSocketActivations(ctx, listeners)
	warnings = append(warnings, socketWarnings...)
	mappings, err := collect.DockerMappings(ctx, *dockerSocket)
	if err != nil {
		warnings = append(warnings, "Docker evidence unavailable: "+err.Error())
	}
	facts := model.Facts{
		Listeners: listeners,
		Mappings:  mappings,
		Firewall: []model.FirewallObservation{
			collect.Firewall(ctx, port, "input"),
			collect.Firewall(ctx, port, "forward"),
		},
		Warnings: warnings,
	}
	report := analyze.Port(port, facts)
	if *jsonOutput {
		err = render.JSON(os.Stdout, report)
	} else {
		err = render.Text(os.Stdout, report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "portclue: write report:", err)
		return 1
	}
	return 0
}

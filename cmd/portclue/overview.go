package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/pbxqdown/portclue/internal/analyze"
	"github.com/pbxqdown/portclue/internal/collect"
	"github.com/pbxqdown/portclue/internal/model"
	"github.com/pbxqdown/portclue/internal/render"
)

func runOverview(jsonOutput bool, dockerSocket string) int {
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
	mappings, err := collect.DockerMappings(ctx, dockerSocket)
	if err != nil {
		warnings = append(warnings, "Docker evidence unavailable: "+err.Error())
	}
	report := analyze.Overview(model.Facts{
		Listeners: listeners,
		Mappings:  mappings,
		Warnings:  warnings,
	})
	if jsonOutput {
		err = render.OverviewJSON(os.Stdout, report)
	} else {
		err = render.OverviewText(os.Stdout, report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "portclue: write overview:", err)
		return 1
	}
	return 0
}

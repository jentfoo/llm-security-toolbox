// Command secagent runs the autonomous security exploration controller
// against an OpenAI-compatible endpoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-appsec/secagent/config"
	"github.com/go-appsec/secagent/orchestrator"
)

func main() {
	cfg, err := config.Parse(flag.CommandLine, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	if orchestrator.IsTerminal(os.Stderr) && os.Getenv("NO_COLOR") == "" {
		orchestrator.EnableColors()
	}

	log, err := orchestrator.NewLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log open: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	if err := orchestrator.Run(ctx, cfg, log); err != nil {
		log.Log("controller", "fatal", map[string]any{"err": err.Error()})
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

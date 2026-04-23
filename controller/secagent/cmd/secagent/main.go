// Command secagent runs the autonomous security exploration controller
// against an OpenAI-compatible endpoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

	var repoRoot string
	if !cfg.External {
		r, err := detectRepoRoot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot resolve repo root: %v\n", err)
			os.Exit(1)
		}
		repoRoot = r
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

	if err := orchestrator.Run(ctx, cfg, repoRoot, log); err != nil {
		log.Log("controller", "fatal", map[string]any{"err": err.Error()})
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// detectRepoRoot walks up from the binary's working directory looking for the
// toolbox Makefile. Falls back to cwd.
func detectRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "sectool")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return cwd, nil
}

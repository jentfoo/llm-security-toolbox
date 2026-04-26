package orchestrator

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// SectoolServer represents the sectool MCP endpoint secagent talks to.
// When secagent attached to an already-running server, Cmd is nil and
// Terminate is a no-op.
type SectoolServer struct {
	Cmd     *exec.Cmd
	LogFile *os.File
	URL     string
}

// readinessProbeTimeout caps each MCP readiness probe so a hung
// connection can't stall startup.
const readinessProbeTimeout = 500 * time.Millisecond

// StartSectool returns a SectoolServer for the configured MCP port. If a
// server is already responding on that port it attaches without starting
// a child process; otherwise it launches `sectool mcp` from $PATH and
// waits for HTTP readiness.
func StartSectool(proxyPort, mcpPort int, workflow string, log *Logger) (*SectoolServer, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort)

	if mcpReachable(url) {
		if log != nil {
			log.Log("server", "attaching to running sectool", map[string]any{
				"mcp_port": mcpPort, "url": url,
			})
		}
		return &SectoolServer{URL: url}, nil
	}

	binary, err := exec.LookPath("sectool")
	if err != nil {
		return nil, fmt.Errorf("sectool not found in $PATH: %w", err)
	}

	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	logPath := filepath.Join(cwd, "sectool-mcp.log")
	f, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("create log file: %w", err)
	}
	cmd := exec.Command(binary, "mcp",
		fmt.Sprintf("--proxy-port=%d", proxyPort),
		fmt.Sprintf("--port=%d", mcpPort),
		"--workflow="+workflow,
	)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("start sectool: %w", err)
	}
	if log != nil {
		log.Log("server", "started sectool", map[string]any{
			"mcp_port": mcpPort, "proxy_port": proxyPort,
			"log": logPath, "binary": binary,
		})
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			_ = f.Close()
			return nil, fmt.Errorf("sectool exited early (code %d)", cmd.ProcessState.ExitCode())
		}
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("sectool died during startup: %w", err)
			}
		}
		if mcpReachable(url) {
			if log != nil {
				log.Log("server", "ready", map[string]any{"url": url})
			}
			return &SectoolServer{Cmd: cmd, LogFile: f, URL: url}, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = f.Close()
	return nil, errors.New("sectool MCP server did not become ready within 10s")
}

// mcpReachable reports whether the MCP endpoint accepts an HTTP request
// within readinessProbeTimeout.
func mcpReachable(url string) bool {
	client := &http.Client{Timeout: readinessProbeTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// Terminate tears down the child server. No-op when attached to a server
// secagent didn't start.
func (s *SectoolServer) Terminate() {
	if s == nil || s.Cmd == nil || s.Cmd.Process == nil {
		return
	}
	_ = s.Cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_, _ = s.Cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.Cmd.Process.Kill()
		<-done
	}
	if s.LogFile != nil {
		_ = s.LogFile.Close()
	}
}

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

// SectoolServer manages a child sectool MCP server process.
type SectoolServer struct {
	Cmd     *exec.Cmd
	LogFile *os.File
	URL     string
}

// StartSectool runs `make build-sectool` (unless skipBuild) then
// `bin/sectool mcp ...` and waits for HTTP readiness.
func StartSectool(
	repoRoot string, proxyPort, mcpPort int, workflow string,
	skipBuild bool, log *Logger,
) (*SectoolServer, error) {
	if !skipBuild {
		if log != nil {
			log.Log("server", "building sectool", nil)
		}
		build := exec.Command("make", "build-sectool")
		build.Dir = repoRoot
		if out, err := build.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("make build-sectool failed: %w\n%s", err, string(out))
		}
	}

	binary := filepath.Join(repoRoot, "bin", "sectool")
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
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
		log.Log("server", "started sectool", map[string]any{"mcp_port": mcpPort, "proxy_port": proxyPort, "log": logPath})
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Early death check.
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
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
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

// Terminate tears down the child server.
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

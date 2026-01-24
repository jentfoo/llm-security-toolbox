package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

const shutdownTimeout = 10 * time.Second

// Server is the sectool MCP server.
type Server struct {
	cfg            *config.Config
	flagBurpMCPURL string
	flagConfigPath string
	flagMCPPort    int // CLI override, 0 means use config

	// MCP server settings
	mcpPort         int
	mcpWorkflowMode string

	// Runtime state
	mcpServer *mcpServer
	started   chan struct{}
	startedAt time.Time

	// Health metrics providers
	mu             sync.RWMutex
	metricProvider map[string]HealthMetricProvider

	// Backend implementations
	httpBackend    HttpBackend
	oastBackend    OastBackend
	crawlerBackend CrawlerBackend

	// Flow ID mapping (ephemeral)
	flowStore      *store.FlowStore
	crawlFlowStore *store.CrawlFlowStore

	// Request/response results store (ephemeral)
	requestStore *store.RequestStore

	// proxyLastOffset tracks the highest offset seen across all proxy list queries.
	// Enables "since=last" to show only new traffic since the last query.
	proxyLastOffset atomic.Uint32

	// Shutdown coordination
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewServer creates a new MCP server instance with optional backends.
// If a backend is nil, Run initializes the default implementation.
func NewServer(flags MCPServerFlags, hb HttpBackend, ob OastBackend, cb CrawlerBackend) (*Server, error) {
	s := &Server{
		flagBurpMCPURL:  flags.BurpMCPURL,
		flagConfigPath:  flags.ConfigPath,
		flagMCPPort:     flags.MCPPort,
		mcpWorkflowMode: flags.WorkflowMode,
		metricProvider:  make(map[string]HealthMetricProvider),
		started:         make(chan struct{}),
		shutdownCh:      make(chan struct{}),
		flowStore:       store.NewFlowStore(),
		crawlFlowStore:  store.NewCrawlFlowStore(),
		requestStore:    store.NewRequestStore(),
		httpBackend:     hb,
		oastBackend:     ob,
		crawlerBackend:  cb,
	}

	// Register health metrics for store counts
	s.RegisterHealthMetric("flows", func() string { return strconv.Itoa(s.flowStore.Count()) })
	s.RegisterHealthMetric("crawl_flows", func() string { return strconv.Itoa(s.crawlFlowStore.Count()) })
	s.RegisterHealthMetric("requests", func() string { return strconv.Itoa(s.requestStore.Count()) })

	return s, nil
}

// WaitTillStarted blocks until the server has started.
func (s *Server) WaitTillStarted() {
	<-s.started
}

// Run starts the MCP server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	log.Printf("sectool MCP server starting (version=%s)", config.Version)

	markStarted := sync.OnceFunc(func() {
		s.startedAt = time.Now()
		close(s.started)
	})
	defer markStarted()

	// Load or create config from ~/.sectool/config.json
	if err := s.loadOrCreateConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Connect to Burp MCP
	if s.httpBackend == nil {
		if err := s.connectBurpMCP(ctx); err != nil {
			return fmt.Errorf("failed to connect to Burp MCP: %w", err)
		}
	}

	// Setup OAST backend
	if s.oastBackend == nil {
		s.oastBackend = NewInteractshBackend()
	}

	// Setup Crawler backend
	if s.crawlerBackend == nil {
		s.crawlerBackend = NewCollyBackend(s.cfg.Crawler, s.crawlFlowStore, s.flowStore, s.httpBackend)
	}

	// Start MCP server
	s.mcpServer = newMCPServer(s, s.mcpWorkflowMode)
	if err := s.mcpServer.Start(s.mcpPort); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	markStarted()
	log.Printf("MCP server listening on http://%s/mcp", s.mcpServer.Addr())
	s.printMCPConfig()

	select {
	case <-ctx.Done():
		log.Printf("context cancelled, initiating shutdown")
	case sig := <-sigCh:
		log.Printf("received signal %v, initiating shutdown", sig)
	case <-s.shutdownCh:
		log.Printf("shutdown requested")
	}

	signal.Stop(sigCh)

	return s.shutdown()
}

// shutdown performs graceful shutdown.
func (s *Server) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Close MCP server
	if s.mcpServer != nil {
		if err := s.mcpServer.Close(ctx); err != nil {
			log.Printf("MCP server shutdown error: %v", err)
		}
	}

	// Wait for any ongoing operations
	s.wg.Wait()

	// Close backends
	if s.httpBackend != nil {
		if err := s.httpBackend.Close(); err != nil {
			log.Printf("warning: failed to close HttpBackend: %v", err)
		}
	}
	if s.oastBackend != nil {
		if err := s.oastBackend.Close(); err != nil {
			log.Printf("warning: failed to close OastBackend: %v", err)
		}
	}
	if s.crawlerBackend != nil {
		if err := s.crawlerBackend.Close(); err != nil {
			log.Printf("warning: failed to close CrawlerBackend: %v", err)
		}
	}

	log.Printf("sectool MCP server stopped")
	return nil
}

// RegisterHealthMetric registers a health metric provider for the given key.
func (s *Server) RegisterHealthMetric(key string, provider HealthMetricProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metricProvider[key] = provider
}

// RequestShutdown initiates server shutdown.
func (s *Server) RequestShutdown() {
	select {
	case <-s.shutdownCh:
		// Already shutting down
	default:
		close(s.shutdownCh)
	}
}

// loadOrCreateConfig loads config and applies CLI flag overrides.
// Precedence: CLI flags > config file > defaults
func (s *Server) loadOrCreateConfig() error {
	// Determine config path
	configPath := s.flagConfigPath
	if configPath == "" {
		configPath = config.DefaultPath()
	}

	cfg, err := config.LoadOrCreatePath(configPath)
	if err != nil {
		return err
	}

	// Apply CLI flag overrides (non-zero values override config)
	if s.flagMCPPort != 0 {
		s.mcpPort = s.flagMCPPort
	} else {
		s.mcpPort = cfg.MCPPort
	}

	s.cfg = cfg
	return nil
}

// connectBurpMCP establishes the connection to Burp MCP.
func (s *Server) connectBurpMCP(ctx context.Context) error {
	burpURL := s.flagBurpMCPURL
	if burpURL == "" {
		burpURL = config.DefaultBurpMCPURL
	}

	burpBackend := NewBurpBackend(burpURL)
	if err := burpBackend.Connect(ctx); err != nil {
		return err
	}
	s.httpBackend = burpBackend
	return nil
}

// printMCPConfig outputs MCP configuration instructions to stderr.
func (s *Server) printMCPConfig() {
	addr := s.mcpServer.Addr()
	mcpURL := fmt.Sprintf("http://%s/mcp", addr)
	sseURL := fmt.Sprintf("http://%s/sse", addr)

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "================================================================================")
	_, _ = fmt.Fprintf(os.Stderr, "MCP Endpoint: %s\n", mcpURL)
	_, _ = fmt.Fprintf(os.Stderr, "SSE Endpoint: %s (legacy)\n", sseURL)
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Claude Code:")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintf(os.Stderr, "  claude mcp add --transport http sectool %s\n", mcpURL)
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Codex (~/.codex/config.toml):")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "  [mcp_servers.sectool]")
	_, _ = fmt.Fprintf(os.Stderr, "  url = \"%s\"\n", mcpURL)
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "================================================================================")
	_, _ = fmt.Fprintln(os.Stderr, "")
}

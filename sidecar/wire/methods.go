package wire

// Contract version advertised at registration. Major mismatch is a fast fail;
// within a shared major the session runs at min(local, remote) minor.
const (
	VersionMajor = 1
	VersionMinor = 0
)

// JSON-RPC method names exchanged over the connection.
const (
	MethodRegister      = "register"
	MethodPing          = "ping"
	MethodPong          = "pong"
	MethodShutdown      = "shutdown"
	MethodPushFlow      = "push_flow"
	MethodLog           = "log"
	MethodReportMetrics = "report_metrics"
	MethodCoreQuery     = "core_query"
)

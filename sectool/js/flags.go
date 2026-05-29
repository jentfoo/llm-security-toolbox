package js

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// Parse handles the "sectool js" command.
func Parse(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("js", pflag.ContinueOnError)
	origin := fs.String("origin", "same-origin",
		`endpoint scope: "same-origin", "summary", "full", or a comma-separated host set`)
	includeAssets := fs.Bool("include-assets", false,
		"include static-asset references (.js/.css/fonts/images) dropped by default")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool js [--origin MODE] <flow_id>

Extract the API surface from a JavaScript or HTML response flow.

Returns deduplicated endpoints, routes, WebSocket URLs, URL literals, and
external <script src=...> URLs. Inline <script> blocks in HTML responses are
parsed independently. Endpoints include a last_flow reference to the most
recent matching proxy flow when one exists.

Arguments:
  <flow_id>    Flow ID (from proxy, replay, or crawl)

Flags:
  --origin           Endpoint scope (default "same-origin"): "same-origin",
                     "summary", "full", or a comma-separated host set
  --include-assets   Include static-asset references (.js/.css/fonts/images)
                     that are dropped by default

Examples:
  sectool js f7k2x
  sectool js --origin summary f7k2x
  sectool js --include-assets f7k2x
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fs.Usage()
		return errors.New("flow_id required: sectool js <flow_id>")
	}

	return run(mcpURL, posArgs[0], *origin, *includeAssets)
}

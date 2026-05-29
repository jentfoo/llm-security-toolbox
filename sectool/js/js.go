package js

import (
	"context"
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
)

func run(mcpURL, flowID, origin string, includeAssets bool) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.JSAnalyze(ctx, flowID, origin, includeAssets)
	if err != nil {
		return fmt.Errorf("js_analyze failed: %w", err)
	}

	_, _ = fmt.Printf("%s\n\n", cliutil.Bold("JS Analyze"))
	_, _ = fmt.Printf("Flow %s, source=%s\n", cliutil.ID(flowID), resp.Source)
	_, _ = fmt.Printf("Bytes=%d, script_blocks=%d\n\n", resp.Stats.InputBytes, resp.Stats.ScriptBlocks)

	for _, w := range resp.Warnings {
		_, _ = fmt.Printf("  %s %s\n", cliutil.Warning("!"), w)
	}
	if len(resp.Warnings) > 0 {
		_, _ = fmt.Println()
	}

	if len(resp.OriginSummary) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Origins"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Origin", "Endpoints"})
		for _, o := range resp.OriginSummary {
			t.AppendRow(table.Row{o.Origin, o.Count})
		}
		t.Render()
		_, _ = fmt.Println()
	}

	if len(resp.Endpoints) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Endpoints"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Method", "URL", "Lib", "Last Flow"})
		for _, e := range resp.Endpoints {
			t.AppendRow(table.Row{e.Method, e.URL, e.Library, e.LastFlow})
		}
		t.Render()
		_, _ = fmt.Println()
	}

	if len(resp.Routes) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Routes"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Path", "Framework"})
		for _, r := range resp.Routes {
			t.AppendRow(table.Row{r.Path, r.Framework})
		}
		t.Render()
		_, _ = fmt.Println()
	}

	if len(resp.Secrets) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Secrets"))
		t := cliutil.NewTable(nil)
		t.AppendHeader(table.Row{"Kind", "Value"})
		for _, s := range resp.Secrets {
			t.AppendRow(table.Row{s.Kind, s.Value})
		}
		t.Render()
		_, _ = fmt.Println()
	}

	if len(resp.ScriptSrc) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Script Src"))
		for _, s := range resp.ScriptSrc {
			_, _ = fmt.Printf("  %s\n", s)
		}
		_, _ = fmt.Println()
	}

	if len(resp.SourceMaps) > 0 {
		_, _ = fmt.Println(cliutil.Bold("Source Maps"))
		for _, s := range resp.SourceMaps {
			_, _ = fmt.Printf("  %s\n", s)
		}
		_, _ = fmt.Println()
	}

	if len(resp.Endpoints)+len(resp.Routes)+len(resp.Secrets)+len(resp.ScriptSrc)+len(resp.OriginSummary) == 0 {
		_, _ = fmt.Println("No API surface extracted.")
	}

	return nil
}

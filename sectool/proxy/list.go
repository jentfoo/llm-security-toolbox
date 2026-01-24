package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/cliutil"
	"github.com/go-harden/llm-security-toolbox/sectool/mcpclient"
)

func summary(mcpURL string, timeout time.Duration, host, path, method, status, contains, containsBody, excludeHost, excludePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxySummary(ctx, mcpclient.ProxySummaryOpts{
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
	})
	if err != nil {
		return fmt.Errorf("proxy summary failed: %w", err)
	}

	if len(resp.Summary) > 0 {
		printAggregateTable(resp.Summary)
	} else {
		fmt.Println("No matching entries found.")
	}

	return nil
}

func list(mcpURL string, timeout time.Duration, host, path, method, status, contains, containsBody, since, excludeHost, excludePath string, limit, offset int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ProxyList(ctx, mcpclient.ProxyListOpts{
		Host:         host,
		Path:         path,
		Method:       method,
		Status:       status,
		Contains:     contains,
		ContainsBody: containsBody,
		Since:        since,
		ExcludeHost:  excludeHost,
		ExcludePath:  excludePath,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return fmt.Errorf("proxy list failed: %w", err)
	}

	if len(resp.Flows) > 0 {
		printFlowTable(resp.Flows)
	} else {
		fmt.Println("No matching entries found.")
	}

	return nil
}

func printAggregateTable(agg []mcpclient.SummaryEntry) {
	fmt.Println("| host | path | method | status | count |")
	fmt.Println("|------|------|--------|--------|-------|")
	for _, e := range agg {
		fmt.Printf("| %s | %s | %s | %d | %d |\n",
			cliutil.EscapeMarkdown(e.Host), cliutil.EscapeMarkdown(e.Path),
			e.Method, e.Status, e.Count)
	}
	fmt.Printf("\n*%d unique request patterns*\n", len(agg))
}

func printFlowTable(flows []mcpclient.FlowEntry) {
	fmt.Println("| flow_id | method | host | path | status | size |")
	fmt.Println("|---------|--------|------|------|--------|------|")
	for _, f := range flows {
		fmt.Printf("| %s | %s | %s | %s | %d | %d |\n",
			f.FlowID, f.Method,
			cliutil.EscapeMarkdown(f.Host),
			cliutil.EscapeMarkdown(f.Path),
			f.Status, f.RespSize)
	}
	fmt.Printf("\n*%d flows*\n", len(flows))

	if len(flows) > 0 {
		lastFlow := flows[len(flows)-1]
		fmt.Printf("\nTo list flows after this: `sectool proxy list --since %s`\n", lastFlow.FlowID)
	}
}

package service

import (
	"context"
	"encoding/base64"
	"html"
	"net/url"

	"github.com/mark3labs/mcp-go/mcp"
)

func (m *mcpServer) encodeURLTool() mcp.Tool {
	return mcp.NewTool("encode_url",
		mcp.WithDescription("URL encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeBase64Tool() mcp.Tool {
	return mcp.NewTool("encode_base64",
		mcp.WithDescription("Base64 encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeHTMLTool() mcp.Tool {
	return mcp.NewTool("encode_html",
		mcp.WithDescription("HTML entity encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}
func (m *mcpServer) handleEncodeURL(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			return errorResult("URL decode error: " + err.Error()), nil
		}
		result = decoded
	} else {
		result = url.QueryEscape(input)
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeBase64(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return errorResult("base64 decode error: " + err.Error()), nil
		}
		result = string(decoded)
	} else {
		result = base64.StdEncoding.EncodeToString([]byte(input))
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeHTML(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		result = html.UnescapeString(input)
	} else {
		result = html.EscapeString(input)
	}

	return mcp.NewToolResultText(result), nil
}

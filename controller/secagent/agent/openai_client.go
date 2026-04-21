package agent

import (
	"context"
	"net/http"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

// ChatMessage mirrors the subset of OpenAI chat-completion fields we need.
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	Name       string     `json:"name,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall mirrors assistant.tool_calls entries.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction holds the tool name and raw JSON argument string.
type ToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatTool is the OpenAI function-tool schema wrapper.
type ChatTool struct {
	Type     string         `json:"type"`
	Function ChatToolSchema `json:"function"`
}

// ChatToolSchema is the inner tool schema.
type ChatToolSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ChatRequest is what we send per round.
type ChatRequest struct {
	Model     string
	Messages  []ChatMessage
	Tools     []ChatTool
	MaxTokens int
}

// ChatResponse captures the assistant reply.
type ChatResponse struct {
	Content   string
	ToolCalls []ToolCall
	Usage     Usage
	Model     string
}

// Usage reports token counts.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// ChatClient is the low-level boundary that can be faked in tests.
type ChatClient interface {
	CreateChatCompletion(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

// OpenAIChatClient wraps go-openai for OpenAI-compatible endpoints.
type OpenAIChatClient struct {
	client *openai.Client
}

// NewOpenAIChatClient builds a client pointed at baseURL with the given apiKey.
// Pass an empty apiKey for most local endpoints.
func NewOpenAIChatClient(baseURL, apiKey string) *OpenAIChatClient {
	cfg := openai.DefaultConfig(apiKey)
	if baseURL != "" {
		cfg.BaseURL = baseURL
	}
	cfg.HTTPClient = &http.Client{Timeout: 25 * time.Minute}
	return &OpenAIChatClient{client: openai.NewClientWithConfig(cfg)}
}

// CreateChatCompletion sends one chat-completion request.
func (c *OpenAIChatClient) CreateChatCompletion(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	msgs := make([]openai.ChatCompletionMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		om := openai.ChatCompletionMessage{
			Role:       m.Role,
			Content:    m.Content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		if len(m.ToolCalls) > 0 {
			om.ToolCalls = make([]openai.ToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				om.ToolCalls = append(om.ToolCalls, openai.ToolCall{
					ID:   tc.ID,
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}
		msgs = append(msgs, om)
	}

	tools := make([]openai.Tool, 0, len(req.Tools))
	for _, t := range req.Tools {
		tools = append(tools, openai.Tool{
			Type: openai.ToolTypeFunction,
			Function: &openai.FunctionDefinition{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}

	ocr := openai.ChatCompletionRequest{
		Model:     req.Model,
		Messages:  msgs,
		Tools:     tools,
		MaxTokens: req.MaxTokens,
	}
	resp, err := c.client.CreateChatCompletion(ctx, ocr)
	if err != nil {
		return ChatResponse{}, err
	}
	if len(resp.Choices) == 0 {
		return ChatResponse{Usage: Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}, Model: resp.Model}, nil
	}
	choice := resp.Choices[0]
	out := ChatResponse{
		Content: choice.Message.Content,
		Usage: Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		Model: resp.Model,
	}
	if len(choice.Message.ToolCalls) > 0 {
		out.ToolCalls = make([]ToolCall, 0, len(choice.Message.ToolCalls))
		for _, tc := range choice.Message.ToolCalls {
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				ID:   tc.ID,
				Type: string(tc.Type),
				Function: ToolFunction{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
	}
	return out, nil
}

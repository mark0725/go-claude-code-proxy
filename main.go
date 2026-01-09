package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// ============================================================================
// Configuration
// ============================================================================

var (
	LOG_LEVEL          string
	PROXY_API_KEY      string
	ANTHROPIC_API_KEY  string
	OPENAI_API_KEY     string
	GOOGLE_API_KEY     string
	OPENAI_BASE_URL    string
	GOOGLE_BASE_URL    string
	ANTHROPIC_BASE_URL string
	PROXY_URL          string
)

// ============================================================================
// ANSI Colors for logging
// ============================================================================

const (
	ColorCyan    = "\033[96m"
	ColorBlue    = "\033[94m"
	ColorGreen   = "\033[92m"
	ColorYellow  = "\033[93m"
	ColorRed     = "\033[91m"
	ColorMagenta = "\033[95m"
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
)

// Provider type
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderGoogle    Provider = "google"
	ProviderAnthropic Provider = "anthropic"
)

// ============================================================================
// Data Models - Anthropic API
// ============================================================================

type ContentBlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ContentBlockImage struct {
	Type   string                 `json:"type"`
	Source map[string]interface{} `json:"source"`
}

type ContentBlockToolUse struct {
	Type  string                 `json:"type"`
	ID    string                 `json:"id"`
	Name  string                 `json:"name"`
	Input map[string]interface{} `json:"input"`
}

type ContentBlockToolResult struct {
	Type      string      `json:"type"`
	ToolUseID string      `json:"tool_use_id"`
	Content   interface{} `json:"content"`
}

type SystemContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // Can be string or []ContentBlock
}

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type ThinkingConfig struct {
	Enabled      bool `json:"enabled"`
	BudgetTokens int  `json:"budget_tokens,omitempty"`
}

type MessagesRequest struct {
	Model         string                 `json:"model"`
	MaxTokens     int                    `json:"max_tokens"`
	Messages      []Message              `json:"messages"`
	System        interface{}            `json:"system,omitempty"` // Can be string or []SystemContent
	StopSequences []string               `json:"stop_sequences,omitempty"`
	Stream        bool                   `json:"stream,omitempty"`
	Temperature   *float64               `json:"temperature,omitempty"`
	TopP          *float64               `json:"top_p,omitempty"`
	TopK          *int                   `json:"top_k,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Tools         []Tool                 `json:"tools,omitempty"`
	ToolChoice    map[string]interface{} `json:"tool_choice,omitempty"`
	Thinking      *ThinkingConfig        `json:"thinking,omitempty"`
}

type TokenCountRequest struct {
	Model      string                 `json:"model"`
	Messages   []Message              `json:"messages"`
	System     interface{}            `json:"system,omitempty"`
	Tools      []Tool                 `json:"tools,omitempty"`
	Thinking   *ThinkingConfig        `json:"thinking,omitempty"`
	ToolChoice map[string]interface{} `json:"tool_choice,omitempty"`
}

type TokenCountResponse struct {
	InputTokens int `json:"input_tokens"`
}

type Usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

type MessagesResponse struct {
	ID           string        `json:"id"`
	Model        string        `json:"model"`
	Role         string        `json:"role"`
	Content      []interface{} `json:"content"`
	Type         string        `json:"type"`
	StopReason   *string       `json:"stop_reason"`
	StopSequence *string       `json:"stop_sequence"`
	Usage        Usage         `json:"usage"`
}

// ============================================================================
// Data Models - OpenAI API
// ============================================================================

type OpenAIMessage struct {
	Role       string           `json:"role"`
	Content    interface{}      `json:"content"`
	Name       string           `json:"name,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []OpenAIToolCall `json:"tool_calls,omitempty"`
}

type OpenAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function OpenAIFunctionCall `json:"function"`
}

type OpenAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type OpenAITool struct {
	Type     string         `json:"type"`
	Function OpenAIFunction `json:"function"`
}

type OpenAIFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type OpenAIRequest struct {
	Model               string          `json:"model"`
	Messages            []OpenAIMessage `json:"messages"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	Stop                []string        `json:"stop,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Tools               []OpenAITool    `json:"tools,omitempty"`
	ToolChoice          interface{}     `json:"tool_choice,omitempty"`
}

type OpenAIResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int           `json:"index"`
		Message      OpenAIMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type OpenAIStreamChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string           `json:"role,omitempty"`
			Content   string           `json:"content,omitempty"`
			ToolCalls []OpenAIToolCall `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

// ============================================================================
// Error Response
// ============================================================================

type ErrorResponse struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// ============================================================================
// Helper Functions
// ============================================================================

func initLogger() {
	level := slog.LevelDebug // 默认 debug

	switch strings.ToLower(LOG_LEVEL) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

func init() {
	// Load .env file
	godotenv.Load()

	LOG_LEVEL = getEnvDefault("LOG_LEVEL", "debug")
	PROXY_API_KEY = os.Getenv("PROXY_API_KEY")

	ANTHROPIC_API_KEY = os.Getenv("ANTHROPIC_API_KEY")
	OPENAI_API_KEY = os.Getenv("OPENAI_API_KEY")
	GOOGLE_API_KEY = os.Getenv("GOOGLE_API_KEY")
	OPENAI_BASE_URL = getEnvDefault("OPENAI_BASE_URL", "https://api.openai.com/v1")
	GOOGLE_BASE_URL = getEnvDefault("GOOGLE_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
	ANTHROPIC_BASE_URL = getEnvDefault("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
	PROXY_URL = os.Getenv("PROXY_URL")

	// 初始化 logger
	initLogger()
}

func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateMessageID() string {
	return fmt.Sprintf("msg_%s", uuid.New().String()[:24])
}

func generateToolID() string {
	return fmt.Sprintf("toolu_%s", uuid.New().String()[:24])
}

// getProviderFromPath determines the provider based on the URL path prefix
func getProviderFromPath(path string) Provider {
	if strings.HasPrefix(path, "/openai/") {
		return ProviderOpenAI
	} else if strings.HasPrefix(path, "/google/") {
		return ProviderGoogle
	} else if strings.HasPrefix(path, "/anthropic/") {
		return ProviderAnthropic
	}
	// Default to OpenAI if no prefix matched
	return ProviderOpenAI
}

// cleanGoogleSchema recursively removes unsupported fields from JSON schema for Google
func cleanGoogleSchema(schema interface{}) interface{} {
	switch s := schema.(type) {
	case map[string]interface{}:
		delete(s, "additionalProperties")
		delete(s, "default")

		if t, ok := s["type"].(string); ok && t == "string" {
			if format, ok := s["format"].(string); ok {
				allowedFormats := map[string]bool{"enum": true, "date-time": true}
				if !allowedFormats[format] {
					delete(s, "format")
				}
			}
		}

		for key, value := range s {
			s[key] = cleanGoogleSchema(value)
		}
		return s

	case []interface{}:
		result := make([]interface{}, len(s))
		for i, item := range s {
			result[i] = cleanGoogleSchema(item)
		}
		return result

	default:
		return schema
	}
}

// parseToolResultContent properly parses and normalizes tool result content
func parseToolResultContent(content interface{}) string {
	if content == nil {
		return "No content provided"
	}

	switch c := content.(type) {
	case string:
		return c

	case []interface{}:
		var result strings.Builder
		for _, item := range c {
			switch i := item.(type) {
			case map[string]interface{}:
				if i["type"] == "text" {
					if text, ok := i["text"].(string); ok {
						result.WriteString(text + "\n")
					}
				} else if text, ok := i["text"].(string); ok {
					result.WriteString(text + "\n")
				} else {
					if jsonBytes, err := json.Marshal(i); err == nil {
						result.WriteString(string(jsonBytes) + "\n")
					}
				}
			case string:
				result.WriteString(i + "\n")
			default:
				result.WriteString(fmt.Sprintf("%v\n", i))
			}
		}
		return strings.TrimSpace(result.String())

	case map[string]interface{}:
		if c["type"] == "text" {
			if text, ok := c["text"].(string); ok {
				return text
			}
		}
		if jsonBytes, err := json.Marshal(c); err == nil {
			return string(jsonBytes)
		}
		return fmt.Sprintf("%v", c)

	default:
		return fmt.Sprintf("%v", c)
	}
}

// ============================================================================
// API Key Validation
// ============================================================================

// validateAPIKey checks the x-api-key header against PROXY_API_KEY
// Returns true if valid, false otherwise
func validateAPIKey(r *http.Request) bool {
	// If PROXY_API_KEY is not set, skip validation
	if PROXY_API_KEY == "" {
		return true
	}

	// Get the API key from the request header
	apiKey := r.Header.Get("x-api-key")

	// Also check Authorization header with Bearer token format
	if apiKey == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	return apiKey == PROXY_API_KEY
}

// sendAuthError sends a 401 Unauthorized response
func sendAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	errResp := ErrorResponse{}
	errResp.Error.Type = "authentication_error"
	errResp.Error.Message = "Invalid API key. Please provide a valid API key in the x-api-key header."

	json.NewEncoder(w).Encode(errResp)
}

// ============================================================================
// Conversion Functions
// ============================================================================

func convertAnthropicToOpenAI(req *MessagesRequest, provider Provider) (*OpenAIRequest, error) {
	messages := []OpenAIMessage{}

	// Add system message if present
	if req.System != nil {
		switch s := req.System.(type) {
		case string:
			messages = append(messages, OpenAIMessage{Role: "system", Content: s})
		case []interface{}:
			var systemText strings.Builder
			for _, block := range s {
				if blockMap, ok := block.(map[string]interface{}); ok {
					if blockMap["type"] == "text" {
						if text, ok := blockMap["text"].(string); ok {
							systemText.WriteString(text + "\n\n")
						}
					}
				}
			}
			if systemText.Len() > 0 {
				messages = append(messages, OpenAIMessage{Role: "system", Content: strings.TrimSpace(systemText.String())})
			}
		}
	}

	// Convert conversation messages
	for _, msg := range req.Messages {
		switch content := msg.Content.(type) {
		case string:
			messages = append(messages, OpenAIMessage{Role: msg.Role, Content: content})

		case []interface{}:
			// Check if this is a user message with tool_result
			hasToolResult := false
			for _, block := range content {
				if blockMap, ok := block.(map[string]interface{}); ok {
					if blockMap["type"] == "tool_result" {
						hasToolResult = true
						break
					}
				}
			}

			if msg.Role == "user" && hasToolResult {
				var textContent strings.Builder
				for _, block := range content {
					if blockMap, ok := block.(map[string]interface{}); ok {
						switch blockMap["type"] {
						case "text":
							if text, ok := blockMap["text"].(string); ok {
								textContent.WriteString(text + "\n")
							}
						case "tool_result":
							toolID := ""
							if id, ok := blockMap["tool_use_id"].(string); ok {
								toolID = id
							}
							resultContent := parseToolResultContent(blockMap["content"])
							textContent.WriteString(fmt.Sprintf("Tool result for %s:\n%s\n", toolID, resultContent))
						}
					}
				}
				messages = append(messages, OpenAIMessage{Role: "user", Content: strings.TrimSpace(textContent.String())})
			} else {
				var processedContent []map[string]interface{}
				for _, block := range content {
					if blockMap, ok := block.(map[string]interface{}); ok {
						switch blockMap["type"] {
						case "text":
							processedContent = append(processedContent, map[string]interface{}{
								"type": "text",
								"text": blockMap["text"],
							})
						case "image":
							processedContent = append(processedContent, map[string]interface{}{
								"type":   "image",
								"source": blockMap["source"],
							})
						case "tool_use":
							processedContent = append(processedContent, map[string]interface{}{
								"type":  "tool_use",
								"id":    blockMap["id"],
								"name":  blockMap["name"],
								"input": blockMap["input"],
							})
						}
					}
				}
				messages = append(messages, OpenAIMessage{Role: msg.Role, Content: processedContent})
			}
		}
	}

	// Cap max_tokens for OpenAI/google models
	maxTokens := req.MaxTokens
	if provider == ProviderOpenAI || provider == ProviderGoogle {
		if maxTokens > 16384 {
			maxTokens = 16384
		}
	}

	openAIReq := &OpenAIRequest{
		Model:               req.Model,
		Messages:            messages,
		MaxCompletionTokens: maxTokens,
		Temperature:         req.Temperature,
		Stream:              req.Stream,
	}

	if len(req.StopSequences) > 0 {
		openAIReq.Stop = req.StopSequences
	}

	if req.TopP != nil {
		openAIReq.TopP = req.TopP
	}

	// Convert tools to OpenAI format
	if len(req.Tools) > 0 {
		isGoogleModel := provider == ProviderGoogle
		for _, tool := range req.Tools {
			inputSchema := tool.InputSchema
			if isGoogleModel {
				inputSchema = cleanGoogleSchema(inputSchema).(map[string]interface{})
			}

			openAIReq.Tools = append(openAIReq.Tools, OpenAITool{
				Type: "function",
				Function: OpenAIFunction{
					Name:        tool.Name,
					Description: tool.Description,
					Parameters:  inputSchema,
				},
			})
		}
	}

	// Convert tool_choice to OpenAI format
	if req.ToolChoice != nil {
		choiceType, _ := req.ToolChoice["type"].(string)
		switch choiceType {
		case "auto":
			openAIReq.ToolChoice = "auto"
		case "any":
			openAIReq.ToolChoice = "any"
		case "tool":
			if name, ok := req.ToolChoice["name"].(string); ok {
				openAIReq.ToolChoice = map[string]interface{}{
					"type": "function",
					"function": map[string]string{
						"name": name,
					},
				}
			}
		default:
			openAIReq.ToolChoice = "auto"
		}
	}

	return openAIReq, nil
}

func convertOpenAIToAnthropic(openAIResp *OpenAIResponse, originalReq *MessagesRequest, provider Provider) *MessagesResponse {
	content := []interface{}{}

	if len(openAIResp.Choices) > 0 {
		choice := openAIResp.Choices[0]
		message := choice.Message

		// Add text content if present
		if contentStr, ok := message.Content.(string); ok && contentStr != "" {
			content = append(content, map[string]interface{}{
				"type": "text",
				"text": contentStr,
			})
		}

		// Check if this is an Anthropic provider (supports content blocks natively)
		isAnthropicProvider := provider == ProviderAnthropic

		// Add tool calls if present
		if len(message.ToolCalls) > 0 && isAnthropicProvider {
			for _, toolCall := range message.ToolCalls {
				var args map[string]interface{}
				json.Unmarshal([]byte(toolCall.Function.Arguments), &args)
				if args == nil {
					args = map[string]interface{}{"raw": toolCall.Function.Arguments}
				}

				content = append(content, map[string]interface{}{
					"type":  "tool_use",
					"id":    toolCall.ID,
					"name":  toolCall.Function.Name,
					"input": args,
				})
			}
		} else if len(message.ToolCalls) > 0 && !isAnthropicProvider {
			// For non-Anthropic providers, convert tool calls to text
			var toolText strings.Builder
			toolText.WriteString("\n\nTool usage:\n")
			for _, toolCall := range message.ToolCalls {
				toolText.WriteString(fmt.Sprintf("Tool: %s\nArguments: %s\n\n", toolCall.Function.Name, toolCall.Function.Arguments))
			}

			if len(content) > 0 {
				if textBlock, ok := content[0].(map[string]interface{}); ok {
					if textBlock["type"] == "text" {
						textBlock["text"] = textBlock["text"].(string) + toolText.String()
					}
				}
			} else {
				content = append(content, map[string]interface{}{
					"type": "text",
					"text": toolText.String(),
				})
			}
		}
	}

	// Ensure content is never empty
	if len(content) == 0 {
		content = append(content, map[string]interface{}{
			"type": "text",
			"text": "",
		})
	}

	// Map finish_reason to stop_reason
	var stopReason *string
	if len(openAIResp.Choices) > 0 {
		finishReason := openAIResp.Choices[0].FinishReason
		var reason string
		switch finishReason {
		case "stop":
			reason = "end_turn"
		case "length":
			reason = "max_tokens"
		case "tool_calls":
			reason = "tool_use"
		default:
			reason = "end_turn"
		}
		stopReason = &reason
	}

	return &MessagesResponse{
		ID:         openAIResp.ID,
		Model:      originalReq.Model,
		Role:       "assistant",
		Content:    content,
		Type:       "message",
		StopReason: stopReason,
		Usage: Usage{
			InputTokens:  openAIResp.Usage.PromptTokens,
			OutputTokens: openAIResp.Usage.CompletionTokens,
		},
	}
}

// ============================================================================
// HTTP Client and API Calls
// ============================================================================

func createTransport(proxyUrl string) *http.Transport {
	transport := &http.Transport{}

	if proxyUrl != "" {
		transport.Proxy = func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyUrl)
		}
	}

	return transport
}

var httpClient = &http.Client{
	Transport: createTransport(PROXY_URL),
	Timeout:   5 * time.Minute,
}

func getAPIKeyAndBaseURL(provider Provider) (string, string) {
	switch provider {
	case ProviderOpenAI:
		return OPENAI_API_KEY, OPENAI_BASE_URL
	case ProviderGoogle:
		return GOOGLE_API_KEY, GOOGLE_BASE_URL
	case ProviderAnthropic:
		return ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL
	default:
		return OPENAI_API_KEY, OPENAI_BASE_URL
	}
}

// ============================================================================
// Anthropic Direct Proxy Functions
// ============================================================================

func callAnthropicDirect(ctx context.Context, body []byte) (*http.Response, error) {
	apiKey, baseURL := getAPIKeyAndBaseURL(ProviderAnthropic)

	slog.Info("calling Anthropic API", slog.String("url", baseURL+"/messages"))
	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	return httpClient.Do(httpReq)
}

func handleAnthropicProxy(w http.ResponseWriter, r *http.Request, body []byte, req *MessagesRequest) {
	numTools := len(req.Tools)

	if req.Stream {
		logRequest("POST", r.URL.Path, ProviderAnthropic, req.Model, len(req.Messages), numTools, 200)
		handleAnthropicStreamProxy(r.Context(), w, body)
		return
	}

	logRequest("POST", r.URL.Path, ProviderAnthropic, req.Model, len(req.Messages), numTools, 200)

	startTime := time.Now()
	resp, err := callAnthropicDirect(r.Context(), body)
	if err != nil {
		slog.Error("failed to call Anthropic API", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("API error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	slog.Info("response received",
		slog.String("provider", "anthropic"),
		slog.String("model", req.Model),
		slog.Float64("duration_seconds", time.Since(startTime).Seconds()),
	)

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Read response body for debug logging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read response body", slog.String("error", err.Error()))
		return
	}
	slog.Debug("response body", slog.String("body", string(respBody)))

	// Write response body
	w.Write(respBody)
}

func handleAnthropicStreamProxy(ctx context.Context, w http.ResponseWriter, body []byte) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	resp, err := callAnthropicDirect(ctx, body)
	if err != nil {
		slog.Error("failed to call Anthropic API", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("API error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Set streaming headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Copy x-request-id if present
	if reqID := resp.Header.Get("x-request-id"); reqID != "" {
		w.Header().Set("x-request-id", reqID)
	}

	// Stream response directly
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer size for large responses
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		slog.Debug("stream line", slog.String("line", line))
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		slog.Error("failed to read stream", slog.String("error", err.Error()))
	}
}

func handleAnthropicCountTokensProxy(w http.ResponseWriter, r *http.Request, body []byte) {
	apiKey, baseURL := getAPIKeyAndBaseURL(ProviderAnthropic)

	slog.Info("calling Anthropic API", slog.String("url", baseURL+"/messages/count_tokens"))
	httpReq, err := http.NewRequestWithContext(r.Context(), "POST", baseURL+"/messages/count_tokens", bytes.NewReader(body))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("API error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Read response body for debug logging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read response body", slog.String("error", err.Error()))
		return
	}
	slog.Debug("response body", slog.String("body", string(respBody)))

	// Write response body
	w.Write(respBody)
}

// ============================================================================
// OpenAI/Google API Calls
// ============================================================================

func callOpenAI(ctx context.Context, req *OpenAIRequest, provider Provider) (*OpenAIResponse, error) {
	apiKey, baseURL := getAPIKeyAndBaseURL(provider)

	slog.Info("calling OpenAI API", slog.String("url", baseURL+"/chat/completions"))
	// Process messages for OpenAI compatibility
	for i := range req.Messages {
		if content, ok := req.Messages[i].Content.([]map[string]interface{}); ok {
			var textContent strings.Builder
			for _, block := range content {
				switch block["type"] {
				case "text":
					if text, ok := block["text"].(string); ok {
						textContent.WriteString(text + "\n")
					}
				case "tool_result":
					toolID := ""
					if id, ok := block["tool_use_id"].(string); ok {
						toolID = id
					}
					textContent.WriteString(fmt.Sprintf("[Tool Result ID: %s]\n", toolID))
					textContent.WriteString(parseToolResultContent(block["content"]) + "\n")
				case "tool_use":
					if name, ok := block["name"].(string); ok {
						inputJSON, _ := json.Marshal(block["input"])
						textContent.WriteString(fmt.Sprintf("[Tool: %s]\nInput: %s\n\n", name, string(inputJSON)))
					}
				}
			}
			if textContent.Len() == 0 {
				req.Messages[i].Content = "..."
			} else {
				req.Messages[i].Content = strings.TrimSpace(textContent.String())
			}
		}
		if req.Messages[i].Content == nil {
			req.Messages[i].Content = "..."
		}
	}

	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var openAIResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openAIResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &openAIResp, nil
}

func callOpenAIStream(ctx context.Context, req *OpenAIRequest, provider Provider) (<-chan OpenAIStreamChunk, <-chan error) {
	chunkChan := make(chan OpenAIStreamChunk, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(chunkChan)
		defer close(errChan)

		apiKey, baseURL := getAPIKeyAndBaseURL(provider)
		req.Stream = true

		// Process messages for OpenAI compatibility
		for i := range req.Messages {
			if content, ok := req.Messages[i].Content.([]map[string]interface{}); ok {
				var textContent strings.Builder
				for _, block := range content {
					switch block["type"] {
					case "text":
						if text, ok := block["text"].(string); ok {
							textContent.WriteString(text + "\n")
						}
					case "tool_result":
						toolID := ""
						if id, ok := block["tool_use_id"].(string); ok {
							toolID = id
						}
						textContent.WriteString(fmt.Sprintf("[Tool Result ID: %s]\n", toolID))
						textContent.WriteString(parseToolResultContent(block["content"]) + "\n")
					}
				}
				if textContent.Len() == 0 {
					req.Messages[i].Content = "..."
				} else {
					req.Messages[i].Content = strings.TrimSpace(textContent.String())
				}
			}
		}

		jsonBody, err := json.Marshal(req)
		if err != nil {
			errChan <- fmt.Errorf("failed to marshal request: %w", err)
			return
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/chat/completions", bytes.NewReader(jsonBody))
		if err != nil {
			errChan <- fmt.Errorf("failed to create request: %w", err)
			return
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		httpReq.Header.Set("Accept", "text/event-stream")

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			errChan <- fmt.Errorf("request failed: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			errChan <- fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				break
			}

			var chunk OpenAIStreamChunk
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue
			}

			select {
			case chunkChan <- chunk:
			case <-ctx.Done():
				return
			}
		}
	}()

	return chunkChan, errChan
}

// ============================================================================
// Streaming Handler for OpenAI/Google
// ============================================================================

func handleStreaming(ctx context.Context, w http.ResponseWriter, originalReq *MessagesRequest, openAIReq *OpenAIRequest, provider Provider) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	messageID := generateMessageID()

	// Send message_start event
	messageStart := map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"model":         originalReq.Model,
			"content":       []interface{}{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]int{
				"input_tokens":                0,
				"cache_creation_input_tokens": 0,
				"cache_read_input_tokens":     0,
				"output_tokens":               0,
			},
		},
	}
	writeSSE(w, flusher, "message_start", messageStart)

	// Send content_block_start for text
	writeSSE(w, flusher, "content_block_start", map[string]interface{}{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]interface{}{
			"type": "text",
			"text": "",
		},
	})

	// Send ping
	writeSSE(w, flusher, "ping", map[string]interface{}{"type": "ping"})

	chunkChan, errChan := callOpenAIStream(ctx, openAIReq, provider)

	var mu sync.Mutex
	toolIndex := -1
	lastToolIndex := 0
	textBlockClosed := false
	outputTokens := 0
	hasSentStopReason := false

	for {
		select {
		case chunk, ok := <-chunkChan:
			if !ok {
				// Channel closed
				if !hasSentStopReason {
					finalizeStream(w, flusher, lastToolIndex, textBlockClosed, outputTokens)
				}
				return
			}

			mu.Lock()

			// Handle usage data
			if chunk.Usage != nil {
				outputTokens = chunk.Usage.CompletionTokens
			}

			if len(chunk.Choices) > 0 {
				choice := chunk.Choices[0]
				delta := choice.Delta

				// Handle text content
				if delta.Content != "" && toolIndex < 0 && !textBlockClosed {
					writeSSE(w, flusher, "content_block_delta", map[string]interface{}{
						"type":  "content_block_delta",
						"index": 0,
						"delta": map[string]interface{}{
							"type": "text_delta",
							"text": delta.Content,
						},
					})
				}

				// Handle tool calls
				if len(delta.ToolCalls) > 0 {
					if toolIndex < 0 {
						// First tool call - close text block
						if !textBlockClosed {
							textBlockClosed = true
							writeSSE(w, flusher, "content_block_stop", map[string]interface{}{
								"type":  "content_block_stop",
								"index": 0,
							})
						}
					}

					for _, toolCall := range delta.ToolCalls {
						if toolCall.ID != "" {
							// New tool call
							lastToolIndex++
							toolIndex = lastToolIndex

							writeSSE(w, flusher, "content_block_start", map[string]interface{}{
								"type":  "content_block_start",
								"index": toolIndex,
								"content_block": map[string]interface{}{
									"type":  "tool_use",
									"id":    toolCall.ID,
									"name":  toolCall.Function.Name,
									"input": map[string]interface{}{},
								},
							})
						}

						if toolCall.Function.Arguments != "" {
							writeSSE(w, flusher, "content_block_delta", map[string]interface{}{
								"type":  "content_block_delta",
								"index": toolIndex,
								"delta": map[string]interface{}{
									"type":         "input_json_delta",
									"partial_json": toolCall.Function.Arguments,
								},
							})
						}
					}
				}

				// Handle finish reason
				if choice.FinishReason != nil && !hasSentStopReason {
					hasSentStopReason = true

					// Close tool blocks
					for i := 1; i <= lastToolIndex; i++ {
						writeSSE(w, flusher, "content_block_stop", map[string]interface{}{
							"type":  "content_block_stop",
							"index": i,
						})
					}

					// Close text block if not closed
					if !textBlockClosed {
						writeSSE(w, flusher, "content_block_stop", map[string]interface{}{
							"type":  "content_block_stop",
							"index": 0,
						})
					}

					// Map finish reason
					stopReason := "end_turn"
					switch *choice.FinishReason {
					case "length":
						stopReason = "max_tokens"
					case "tool_calls":
						stopReason = "tool_use"
					}

					writeSSE(w, flusher, "message_delta", map[string]interface{}{
						"type": "message_delta",
						"delta": map[string]interface{}{
							"stop_reason":   stopReason,
							"stop_sequence": nil,
						},
						"usage": map[string]int{
							"output_tokens": outputTokens,
						},
					})

					writeSSE(w, flusher, "message_stop", map[string]interface{}{"type": "message_stop"})
					fmt.Fprintf(w, "data: [DONE]\n\n")
					flusher.Flush()
				}
			}
			mu.Unlock()

		case err := <-errChan:
			if err != nil {
				slog.Error("streaming error", slog.String("error", err.Error()))
				writeSSE(w, flusher, "message_delta", map[string]interface{}{
					"type": "message_delta",
					"delta": map[string]interface{}{
						"stop_reason":   "error",
						"stop_sequence": nil,
					},
					"usage": map[string]int{
						"output_tokens": 0,
					},
				})
				writeSSE(w, flusher, "message_stop", map[string]interface{}{"type": "message_stop"})
				fmt.Fprintf(w, "data: [DONE]\n\n")
				flusher.Flush()
			}
			return

		case <-ctx.Done():
			return
		}
	}
}

func finalizeStream(w http.ResponseWriter, flusher http.Flusher, lastToolIndex int, textBlockClosed bool, outputTokens int) {
	// Close tool blocks
	for i := 1; i <= lastToolIndex; i++ {
		writeSSE(w, flusher, "content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": i,
		})
	}

	// Close text block
	if !textBlockClosed {
		writeSSE(w, flusher, "content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": 0,
		})
	}

	writeSSE(w, flusher, "message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
		},
		"usage": map[string]int{
			"output_tokens": outputTokens,
		},
	})

	writeSSE(w, flusher, "message_stop", map[string]interface{}{"type": "message_stop"})
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(jsonData))
	flusher.Flush()
}

// ============================================================================
// Logging
// ============================================================================

func logRequest(method, path string, provider Provider, model string, numMessages, numTools, statusCode int) {
	endpoint := path
	if idx := strings.Index(endpoint, "?"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	slog.Info("request",
		slog.String("method", method),
		slog.String("endpoint", endpoint),
		slog.String("provider", string(provider)),
		slog.String("model", model),
		slog.Int("messages", numMessages),
		slog.Int("tools", numTools),
		slog.Int("status", statusCode),
	)
}

// ============================================================================
// HTTP Handlers
// ============================================================================

func handleMessages(w http.ResponseWriter, r *http.Request) {
	// Validate API key first
	if !validateAPIKey(r) {
		slog.Warn("authentication failed",
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
		)
		sendAuthError(w)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine provider from URL path
	provider := getProviderFromPath(r.URL.Path)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req MessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// For Anthropic provider, use direct proxy
	if provider == ProviderAnthropic {
		handleAnthropicProxy(w, r, body, &req)
		return
	}

	// For OpenAI/Google, convert and proxy
	openAIReq, err := convertAnthropicToOpenAI(&req, provider)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to convert request: %v", err), http.StatusInternalServerError)
		return
	}

	numTools := len(req.Tools)

	// Handle streaming
	if req.Stream {
		logRequest("POST", r.URL.Path, provider, req.Model, len(openAIReq.Messages), numTools, 200)
		handleStreaming(r.Context(), w, &req, openAIReq, provider)
		return
	}

	// Handle non-streaming
	logRequest("POST", r.URL.Path, provider, req.Model, len(openAIReq.Messages), numTools, 200)

	startTime := time.Now()
	openAIResp, err := callOpenAI(r.Context(), openAIReq, provider)
	if err != nil {
		slog.Error("failed to call API", slog.String("error", err.Error()))
		http.Error(w, fmt.Sprintf("API error: %v", err), http.StatusInternalServerError)
		return
	}
	slog.Info("response received",
		slog.String("provider", string(provider)),
		slog.String("model", req.Model),
		slog.Float64("duration_seconds", time.Since(startTime).Seconds()),
	)

	// Convert response to Anthropic format
	anthropicResp := convertOpenAIToAnthropic(openAIResp, &req, provider)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anthropicResp)
}

func handleCountTokens(w http.ResponseWriter, r *http.Request) {
	// Validate API key first
	if !validateAPIKey(r) {
		slog.Warn("authentication failed",
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
		)
		sendAuthError(w)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Determine provider from URL path
	provider := getProviderFromPath(r.URL.Path)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// For Anthropic provider, use direct proxy
	if provider == ProviderAnthropic {
		var req TokenCountRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
			return
		}
		logRequest("POST", r.URL.Path, provider, req.Model, len(req.Messages), len(req.Tools), 200)
		handleAnthropicCountTokensProxy(w, r, body)
		return
	}

	var req TokenCountRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	numTools := len(req.Tools)
	logRequest("POST", r.URL.Path, provider, req.Model, len(req.Messages), numTools, 200)

	// Simple token estimation (roughly 4 chars per token)
	totalChars := 0
	for _, msg := range req.Messages {
		if content, ok := msg.Content.(string); ok {
			totalChars += len(content)
		}
	}

	estimatedTokens := totalChars / 4
	if estimatedTokens < 100 {
		estimatedTokens = 100
	}

	resp := TokenCountResponse{InputTokens: estimatedTokens}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Anthropic Proxy (Go version)",
		"usage":   "Use /openai/v1/messages, /google/v1/messages, or /anthropic/v1/messages",
	})
}

// ============================================================================
// Main
// ============================================================================

func main() {
	http.HandleFunc("/", handleRoot)

	// OpenAI routes
	http.HandleFunc("/openai/v1/messages", handleMessages)
	http.HandleFunc("/openai/v1/messages/count_tokens", handleCountTokens)

	// Google routes
	http.HandleFunc("/google/v1/messages", handleMessages)
	http.HandleFunc("/google/v1/messages/count_tokens", handleCountTokens)

	// Anthropic routes (direct proxy)
	http.HandleFunc("/anthropic/v1/messages", handleMessages)
	http.HandleFunc("/anthropic/v1/messages/count_tokens", handleCountTokens)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	slog.Info("Anthropic Proxy Server (Go) starting",
		slog.String("port", port),
		slog.String("log_level", LOG_LEVEL),
	)
	slog.Info("available routes",
		slog.String("openai", "/openai/v1/messages -> OpenAI API (converts Anthropic format)"),
		slog.String("google", "/google/v1/messages -> Google API (converts Anthropic format)"),
		slog.String("anthropic", "/anthropic/v1/messages -> Anthropic API (direct proxy)"),
	)

	// Log API key status
	if PROXY_API_KEY != "" {
		slog.Info("API Key authentication enabled")
	} else {
		slog.Warn("API Key authentication disabled (PROXY_API_KEY not set)")
	}

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		slog.Error("server failed to start", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

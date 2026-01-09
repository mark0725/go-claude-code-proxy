# Go Claude Code Proxy

An Anthropic API proxy server written in Go that supports forwarding Anthropic API requests to OpenAI, Google, or Anthropic APIs.

## Key Features

1. **Multi-Provider Support**: Supports OpenAI, Google (Gemini), and Anthropic API providers
2. **API Format Conversion**: Automatically converts Anthropic API format to OpenAI/Google format and converts responses back to Anthropic format
3. **Streaming Response**: Full support for SSE streaming responses, including tool_use events
4. **Tool Calling**: Supports Anthropic's tool_use and tool_result format conversion
5. **API Key Authentication**: Optional proxy-level API key validation
6. **HTTP Proxy Support**: Supports forwarding requests through HTTP proxy

## Routes

| Route | Description |
|-------|-------------|
| `/openai/v1/messages` | Forward to OpenAI API (auto format conversion) |
| `/openai/v1/messages/count_tokens` | OpenAI token counting |
| `/google/v1/messages` | Forward to Google API (auto format conversion) |
| `/google/v1/messages/count_tokens` | Google token counting |
| `/anthropic/v1/messages` | Direct proxy to Anthropic API |
| `/anthropic/v1/messages/count_tokens` | Anthropic token counting |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | No | - | OpenAI API key |
| `GOOGLE_API_KEY` | No | - | Google API key |
| `ANTHROPIC_API_KEY` | No | - | Anthropic API key |
| `OPENAI_BASE_URL` | No | `https://api.openai.com/v1` | OpenAI API base URL |
| `GOOGLE_BASE_URL` | No | `https://generativelanguage.googleapis.com/v1beta` | Google API base URL |
| `ANTHROPIC_BASE_URL` | No | `https://api.anthropic.com/v1` | Anthropic API base URL |
| `PROXY_API_KEY` | No | - | Proxy service API key (for client request validation) |
| `PROXY_URL` | No | - | HTTP proxy URL |
| `PORT` | No | `8082` | Service listening port |
| `LOG_LEVEL` | No | `debug` | Log level (debug/info/warn/error) |

## Usage

### 1. Create `.env` File

```env
# API Keys (configure as needed)
OPENAI_API_KEY=your_openai_key
GOOGLE_API_KEY=your_google_key
ANTHROPIC_API_KEY=your_anthropic_key

# Optional: Proxy authentication
PROXY_API_KEY=your_proxy_key

# Optional: Custom API base URLs
OPENAI_BASE_URL=https://api.openai.com/v1
GOOGLE_BASE_URL=https://generativelanguage.googleapis.com/v1beta
ANTHROPIC_BASE_URL=https://api.anthropic.com/v1

# Optional: HTTP proxy
PROXY_URL=http://127.0.0.1:7890

# Optional: Service configuration
PORT=8082
LOG_LEVEL=info
```

### 2. Run Service

```bash
go run main.go
```

### 3. Send Requests

Send requests using Anthropic API format, selecting target provider by route prefix:

```bash
# Send to OpenAI
curl -X POST http://localhost:8082/openai/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "gpt-4o",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Send to Google
curl -X POST http://localhost:8082/google/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "gemini-pro",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Send to Anthropic (direct proxy)
curl -X POST http://localhost:8082/anthropic/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Authentication

The proxy service supports two authentication methods:

1. **x-api-key Header**: `x-api-key: your_proxy_key`
2. **Authorization Header**: `Authorization: Bearer your_proxy_key`

If the `PROXY_API_KEY` environment variable is not set, authentication validation is skipped.

## Feature Details

### Format Conversion

- **OpenAI/Google Routes**: Converts Anthropic format requests to OpenAI format, calls the corresponding API, then converts responses back to Anthropic format
- **Anthropic Route**: Directly proxies requests to Anthropic API without format conversion

### Streaming Response

Supports SSE (Server-Sent Events) streaming responses, including:
- `message_start` - Message start
- `content_block_start` - Content block start
- `content_block_delta` - Content delta
- `content_block_stop` - Content block stop
- `message_delta` - Message delta
- `message_stop` - Message stop

### Tool Calling

Full support for tool calling functionality:
- Converts Anthropic's `tools` format to OpenAI's `functions` format
- Handles `tool_use` and `tool_result` message types
- Automatically cleans up schema fields not supported by Google API

## Dependencies

- [github.com/google/uuid](https://github.com/google/uuid) - UUID generation
- [github.com/joho/godotenv](https://github.com/joho/godotenv) - Environment variable loading

## Install Dependencies

```bash
go mod tidy
```

## Docker

### Build Image

```bash
docker build -t go-claude-code-proxy .
```

### Run Container

```bash
docker run -d -p 8082:8082 \
    -e OPENAI_API_KEY=your_key \
    -e ANTHROPIC_API_KEY=your_key \
    -e GOOGLE_API_KEY=your_key \
    ghcr.io/mark0725/go-claude-code-proxy:latest
```

## License

MIT

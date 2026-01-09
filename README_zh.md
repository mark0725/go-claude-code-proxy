# Go Claude Code Proxy

一个用 Go 编写的 Anthropic API 代理服务器,支持将 Anthropic API 请求转发到 OpenAI、Google 或 Anthropic API。

## 主要特性

1. **多提供商支持**: 支持 OpenAI、Google (Gemini) 和 Anthropic 三种 API 提供商
2. **API 格式转换**: 自动将 Anthropic API 格式转换为 OpenAI/Google 格式,并将响应转换回 Anthropic 格式
3. **流式响应**: 完整支持 SSE 流式响应,包括 tool_use 事件
4. **工具调用**: 支持 Anthropic 的 tool_use 和 tool_result 格式转换
5. **API Key 认证**: 可选的代理层 API Key 验证
6. **HTTP 代理支持**: 支持通过 HTTP 代理转发请求

## 路由说明

| 路由 | 描述 |
|------|------|
| `/openai/v1/messages` | 转发到 OpenAI API (自动转换格式) |
| `/openai/v1/messages/count_tokens` | OpenAI Token 计数 |
| `/google/v1/messages` | 转发到 Google API (自动转换格式) |
| `/google/v1/messages/count_tokens` | Google Token 计数 |
| `/anthropic/v1/messages` | 直接代理到 Anthropic API |
| `/anthropic/v1/messages/count_tokens` | Anthropic Token 计数 |

## 环境变量

| 变量名 | 必填 | 默认值 | 描述 |
|--------|------|--------|------|
| `OPENAI_API_KEY` | 否 | - | OpenAI API 密钥 |
| `GOOGLE_API_KEY` | 否 | - | Google API 密钥 |
| `ANTHROPIC_API_KEY` | 否 | - | Anthropic API 密钥 |
| `OPENAI_BASE_URL` | 否 | `https://api.openai.com/v1` | OpenAI API 基础 URL |
| `GOOGLE_BASE_URL` | 否 | `https://generativelanguage.googleapis.com/v1beta` | Google API 基础 URL |
| `ANTHROPIC_BASE_URL` | 否 | `https://api.anthropic.com/v1` | Anthropic API 基础 URL |
| `PROXY_API_KEY` | 否 | - | 代理服务的 API Key (用于验证客户端请求) |
| `PROXY_URL` | 否 | - | HTTP 代理 URL |
| `PORT` | 否 | `8082` | 服务监听端口 |
| `LOG_LEVEL` | 否 | `debug` | 日志级别 (debug/info/warn/error) |

## 使用方法

### 1. 创建 `.env` 文件

```env
# API Keys (根据需要配置)
OPENAI_API_KEY=your_openai_key
GOOGLE_API_KEY=your_google_key
ANTHROPIC_API_KEY=your_anthropic_key

# 可选: 代理认证
PROXY_API_KEY=your_proxy_key

# 可选: 自定义 API 基础 URL
OPENAI_BASE_URL=https://api.openai.com/v1
GOOGLE_BASE_URL=https://generativelanguage.googleapis.com/v1beta
ANTHROPIC_BASE_URL=https://api.anthropic.com/v1

# 可选: HTTP 代理
PROXY_URL=http://127.0.0.1:7890

# 可选: 服务配置
PORT=8082
LOG_LEVEL=info
```

### 2. 运行服务

```bash
go run main.go
```

### 3. 发送请求

使用 Anthropic API 格式发送请求,根据路由前缀选择目标提供商:

```bash
# 发送到 OpenAI
curl -X POST http://localhost:8082/openai/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "gpt-4o",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# 发送到 Google
curl -X POST http://localhost:8082/google/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "gemini-pro",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# 发送到 Anthropic (直接代理)
curl -X POST http://localhost:8082/anthropic/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: your_proxy_key" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## 认证

代理服务支持两种认证方式:

1. **x-api-key Header**: `x-api-key: your_proxy_key`
2. **Authorization Header**: `Authorization: Bearer your_proxy_key`

如果未设置 `PROXY_API_KEY` 环境变量,则跳过认证验证。

## 功能说明

### 格式转换

- **OpenAI/Google 路由**: 将 Anthropic 格式的请求转换为 OpenAI 格式,调用对应 API,然后将响应转换回 Anthropic 格式
- **Anthropic 路由**: 直接代理请求到 Anthropic API,不做格式转换

### 流式响应

支持 SSE (Server-Sent Events) 流式响应,包括:
- `message_start` - 消息开始
- `content_block_start` - 内容块开始
- `content_block_delta` - 内容增量
- `content_block_stop` - 内容块结束
- `message_delta` - 消息增量
- `message_stop` - 消息结束

### 工具调用

完整支持工具调用功能:
- 将 Anthropic 的 `tools` 格式转换为 OpenAI 的 `functions` 格式
- 处理 `tool_use` 和 `tool_result` 消息类型
- 自动清理 Google API 不支持的 schema 字段

## 依赖

- [github.com/google/uuid](https://github.com/google/uuid) - UUID 生成
- [github.com/joho/godotenv](https://github.com/joho/godotenv) - 环境变量加载

## 安装依赖

```bash
go mod tidy
```

  使用方法:

## Docker
### 构建镜像
  ```
  docker build -t go-claude-code-proxy .
  ```

### 运行容器
```
docker run -d -p 8082:8082 \
    -e OPENAI_API_KEY=your_key \
    -e ANTHROPIC_API_KEY=your_key \
    -e GOOGLE_API_KEY=your_key \
    ghcr.io/mark0725/go-claude-code-proxy:latest
```
## License

MIT

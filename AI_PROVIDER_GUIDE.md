# AI Provider Configuration Guide

This guide provides detailed instructions for configuring different AI providers with the Discord AI Moderator application.

## Table of Contents

1. [Overview](#overview)
2. [OpenAI](#openai)
3. [Azure OpenAI](#azure-openai)
4. [Anthropic](#anthropic)
5. [Google Vertex AI](#google-vertex-ai)
6. [Hugging Face](#hugging-face)
7. [Local Models](#local-models)
8. [Custom Providers](#custom-providers)
9. [Provider Fallback](#provider-fallback)
10. [Performance Considerations](#performance-considerations)
11. [Cost Management](#cost-management)
12. [Troubleshooting](#troubleshooting)

## Overview

The Discord AI Moderator supports multiple AI providers through a unified API. You can configure the application to use any of the supported providers by setting the appropriate environment variables.

### Provider Selection

Set the `AI_PROVIDER` environment variable to select your preferred provider:

```env
AI_PROVIDER=openai
```

Supported values:
- `openai` - OpenAI API
- `azure` - Azure OpenAI Service
- `anthropic` - Anthropic Claude
- `google` - Google Vertex AI
- `huggingface` - Hugging Face Inference API
- `local` - Local models via Ollama or similar
- `custom` - Custom provider implementation

### Common Configuration

All providers support these common settings:

```env
AI_TIMEOUT=30000           # Request timeout in milliseconds
AI_RETRY_COUNT=3           # Number of retries on failure
AI_RETRY_DELAY=1000        # Delay between retries in milliseconds
AI_CACHE_ENABLED=true      # Enable response caching
AI_CACHE_TTL=3600000       # Cache TTL in milliseconds
AI_MAX_TOKENS=2048         # Maximum tokens in response
AI_TEMPERATURE=0.7         # Temperature for response generation
```

## OpenAI

### Configuration

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4
OPENAI_ORGANIZATION=your_organization_id  # Optional
OPENAI_TEMPERATURE=0.7
OPENAI_MAX_TOKENS=2048
OPENAI_TOP_P=1
OPENAI_FREQUENCY_PENALTY=0
OPENAI_PRESENCE_PENALTY=0
```

### Available Models

| Model | Description | Recommended Use Case |
|-------|-------------|---------------------|
| `gpt-4` | Most capable model, best for complex tasks | Complex moderation, nuanced content analysis |
| `gpt-4-turbo` | Faster version of GPT-4 | General purpose moderation |
| `gpt-3.5-turbo` | Fast and cost-effective | Simple moderation, high-volume servers |
| `gpt-3.5-turbo-16k` | Extended context window | Servers with long conversations |

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'openai',
  apiKey: process.env.OPENAI_API_KEY,
  model: process.env.OPENAI_MODEL || 'gpt-4',
  temperature: parseFloat(process.env.OPENAI_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.OPENAI_MAX_TOKENS || '2048'),
  organization: process.env.OPENAI_ORGANIZATION
};
```

### API Key Acquisition

1. Create an account at [OpenAI](https://platform.openai.com/)
2. Navigate to API keys section
3. Create a new API key
4. Copy the key to your `.env` file

## Azure OpenAI

### Configuration

```env
AI_PROVIDER=azure
AZURE_OPENAI_API_KEY=your_azure_openai_api_key
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=your_deployment_name
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_TEMPERATURE=0.7
AZURE_OPENAI_MAX_TOKENS=2048
```

### Deployment Setup

1. Create an Azure account if you don't have one
2. Request access to Azure OpenAI Service
3. Create an Azure OpenAI resource
4. Create a deployment with your chosen model
5. Get the endpoint and API key from the Azure portal

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'azure',
  apiKey: process.env.AZURE_OPENAI_API_KEY,
  endpoint: process.env.AZURE_OPENAI_ENDPOINT,
  deployment: process.env.AZURE_OPENAI_DEPLOYMENT,
  apiVersion: process.env.AZURE_OPENAI_API_VERSION || '2023-05-15',
  temperature: parseFloat(process.env.AZURE_OPENAI_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.AZURE_OPENAI_MAX_TOKENS || '2048')
};
```

## Anthropic

### Configuration

```env
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-2
ANTHROPIC_MAX_TOKENS=2048
ANTHROPIC_TEMPERATURE=0.7
ANTHROPIC_TOP_P=1
ANTHROPIC_TOP_K=0
```

### Available Models

| Model | Description | Recommended Use Case |
|-------|-------------|---------------------|
| `claude-3-opus` | Most capable Claude model | Complex moderation, nuanced content analysis |
| `claude-3-sonnet` | Balanced performance and cost | General purpose moderation |
| `claude-3-haiku` | Fast and efficient | Simple moderation, high-volume servers |
| `claude-2` | Previous generation model | Legacy support |

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'anthropic',
  apiKey: process.env.ANTHROPIC_API_KEY,
  model: process.env.ANTHROPIC_MODEL || 'claude-2',
  temperature: parseFloat(process.env.ANTHROPIC_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.ANTHROPIC_MAX_TOKENS || '2048')
};
```

### API Key Acquisition

1. Create an account at [Anthropic](https://console.anthropic.com/)
2. Navigate to API keys section
3. Create a new API key
4. Copy the key to your `.env` file

## Google Vertex AI

### Configuration

```env
AI_PROVIDER=google
GOOGLE_PROJECT_ID=your_google_project_id
GOOGLE_LOCATION=us-central1
GOOGLE_MODEL=gemini-pro
GOOGLE_CREDENTIALS_JSON=path/to/credentials.json
GOOGLE_TEMPERATURE=0.7
GOOGLE_MAX_TOKENS=2048
GOOGLE_TOP_P=1
GOOGLE_TOP_K=40
```

### Authentication Setup

1. Create a Google Cloud account if you don't have one
2. Create a new project or use an existing one
3. Enable the Vertex AI API
4. Create a service account with Vertex AI User role
5. Download the service account key as JSON
6. Set the path to the JSON file in your `.env` file or use the content directly

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'google',
  projectId: process.env.GOOGLE_PROJECT_ID,
  location: process.env.GOOGLE_LOCATION || 'us-central1',
  model: process.env.GOOGLE_MODEL || 'gemini-pro',
  credentialsPath: process.env.GOOGLE_CREDENTIALS_JSON,
  temperature: parseFloat(process.env.GOOGLE_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.GOOGLE_MAX_TOKENS || '2048')
};
```

## Hugging Face

### Configuration

```env
AI_PROVIDER=huggingface
HUGGINGFACE_API_KEY=your_huggingface_api_key
HUGGINGFACE_MODEL=mistralai/Mistral-7B-Instruct-v0.2
HUGGINGFACE_TEMPERATURE=0.7
HUGGINGFACE_MAX_TOKENS=2048
HUGGINGFACE_TOP_P=0.95
HUGGINGFACE_REPETITION_PENALTY=1.2
```

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'huggingface',
  apiKey: process.env.HUGGINGFACE_API_KEY,
  model: process.env.HUGGINGFACE_MODEL || 'mistralai/Mistral-7B-Instruct-v0.2',
  temperature: parseFloat(process.env.HUGGINGFACE_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.HUGGINGFACE_MAX_TOKENS || '2048')
};
```

### API Key Acquisition

1. Create an account at [Hugging Face](https://huggingface.co/)
2. Navigate to your profile settings
3. Go to Access Tokens
4. Create a new token with read access
5. Copy the token to your `.env` file

## Local Models

### Configuration

```env
AI_PROVIDER=local
LOCAL_MODEL_ENDPOINT=http://localhost:11434/api/generate
LOCAL_MODEL_NAME=llama2
LOCAL_MODEL_TEMPERATURE=0.7
LOCAL_MODEL_MAX_TOKENS=2048
LOCAL_MODEL_TOP_P=0.95
LOCAL_MODEL_REPETITION_PENALTY=1.1
```

### Ollama Setup

1. Install [Ollama](https://ollama.ai/)
2. Pull your preferred model:
   ```bash
   ollama pull llama2
   ```
3. Start Ollama:
   ```bash
   ollama serve
   ```
4. Configure the Discord AI Moderator to use the local endpoint

### Example Usage

```javascript
// Example configuration in code
const aiConfig = {
  provider: 'local',
  endpoint: process.env.LOCAL_MODEL_ENDPOINT || 'http://localhost:11434/api/generate',
  model: process.env.LOCAL_MODEL_NAME || 'llama2',
  temperature: parseFloat(process.env.LOCAL_MODEL_TEMPERATURE || '0.7'),
  maxTokens: parseInt(process.env.LOCAL_MODEL_MAX_TOKENS || '2048')
};
```

## Custom Providers

You can implement custom AI providers by creating a provider adapter in the `src/ai/providers` directory.

### Implementation

Create a new file `src/ai/providers/custom-provider.js`:

```javascript
class CustomProvider {
  constructor(config) {
    this.config = config;
    // Initialize your provider
  }
  
  async generateResponse(prompt, options = {}) {
    // Implement your provider's API call
    // Return the generated response
  }
  
  async moderateContent(content, options = {}) {
    // Implement content moderation
    // Return moderation results
  }
}

module.exports = CustomProvider;
```

### Registration

Register your custom provider in `src/ai/provider-factory.js`:

```javascript
const CustomProvider = require('./providers/custom-provider');

// In the createProvider function
if (config.provider === 'custom') {
  return new CustomProvider(config);
}
```

### Configuration

```env
AI_PROVIDER=custom
CUSTOM_API_KEY=your_custom_api_key
CUSTOM_ENDPOINT=https://your-custom-endpoint.com/api
CUSTOM_MODEL=your-model-name
CUSTOM_TEMPERATURE=0.7
CUSTOM_MAX_TOKENS=2048
```

## Provider Fallback

You can configure fallback providers to ensure reliability:

```env
AI_PROVIDER=openai
AI_FALLBACK_PROVIDER=anthropic
AI_FALLBACK_THRESHOLD=3  # Number of failures before fallback
```

### Implementation

The fallback system automatically switches to the fallback provider if the primary provider fails:

```javascript
// Example fallback implementation
async function getAIResponse(prompt) {
  try {
    return await primaryProvider.generateResponse(prompt);
  } catch (error) {
    failureCount++;
    
    if (failureCount >= fallbackThreshold) {
      logger.warn(`Primary AI provider failed ${failureCount} times, switching to fallback`);
      return fallbackProvider.generateResponse(prompt);
    }
    
    throw error;
  }
}
```

## Performance Considerations

### Response Time

Different providers have different response times:

| Provider | Typical Response Time | Factors |
|----------|------------------------|---------|
| OpenAI | 1-3 seconds | Model size, prompt length |
| Azure OpenAI | 1-3 seconds | Region, model size |
| Anthropic | 2-5 seconds | Model size, prompt length |
| Google Vertex AI | 2-4 seconds | Region, model size |
| Hugging Face | 3-10 seconds | Model size, hosting type |
| Local Models | 1-30 seconds | Hardware, model size |

### Caching

Enable response caching to improve performance:

```env
AI_CACHE_ENABLED=true
AI_CACHE_TTL=3600000  # 1 hour in milliseconds
```

The caching system uses the tiered cache for efficient storage:

```javascript
// Example caching implementation
async function getCachedAIResponse(prompt) {
  const cacheKey = `ai_response:${hashString(prompt)}`;
  
  // Check cache first
  const cached = cache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Generate new response
  const response = await aiProvider.generateResponse(prompt);
  
  // Cache the response
  cache.set(cacheKey, response, AI_CACHE_TTL);
  
  return response;
}
```

### Concurrent Requests

Manage concurrent requests to avoid rate limiting:

```env
AI_MAX_CONCURRENT_REQUESTS=5
AI_RATE_LIMIT_WINDOW=60000  # 1 minute in milliseconds
AI_RATE_LIMIT_MAX_REQUESTS=60
```

## Cost Management

### Token Usage Tracking

The application tracks token usage for cost management:

```javascript
// Example token tracking
function trackTokenUsage(provider, model, promptTokens, completionTokens) {
  const totalTokens = promptTokens + completionTokens;
  
  // Update metrics
  metrics.increment('ai.tokens.total', totalTokens);
  metrics.increment(`ai.tokens.${provider}.${model}`, totalTokens);
  
  // Log usage
  logger.debug('AI token usage:', {
    provider,
    model,
    promptTokens,
    completionTokens,
    totalTokens
  });
}
```

### Cost Estimates

Approximate costs per 1000 tokens (as of 2023):

| Provider | Model | Input Cost | Output Cost |
|----------|-------|------------|------------|
| OpenAI | GPT-4 | $0.03 | $0.06 |
| OpenAI | GPT-3.5-Turbo | $0.0015 | $0.002 |
| Azure OpenAI | GPT-4 | $0.03 | $0.06 |
| Anthropic | Claude-3-Opus | $0.015 | $0.075 |
| Anthropic | Claude-3-Sonnet | $0.003 | $0.015 |
| Google | Gemini Pro | $0.0025 | $0.0025 |

### Budget Limits

Set budget limits to prevent unexpected costs:

```env
AI_BUDGET_LIMIT_DAILY=10  # $10 per day
AI_BUDGET_LIMIT_MONTHLY=100  # $100 per month
```

## Troubleshooting

### Connection Issues

If you're experiencing connection issues:

1. Verify your API key is correct
2. Check your internet connection
3. Ensure the provider's API is operational
4. Check for any IP restrictions or VPN issues

### Rate Limiting

If you're being rate limited:

1. Reduce the number of concurrent requests
2. Implement exponential backoff for retries
3. Consider upgrading your API tier
4. Use the fallback provider during peak times

### Response Quality

If response quality is poor:

1. Adjust the temperature (lower for more deterministic responses)
2. Try a more capable model
3. Refine your prompts
4. Adjust top_p and top_k parameters

### Provider-Specific Issues

#### OpenAI

- **Issue**: "Rate limit exceeded"
  - **Solution**: Implement exponential backoff, reduce request frequency

- **Issue**: "The model is overloaded"
  - **Solution**: Retry with exponential backoff, use fallback provider

#### Azure OpenAI

- **Issue**: "Resource not found"
  - **Solution**: Verify deployment name and endpoint URL

- **Issue**: "Authentication failed"
  - **Solution**: Check API key and ensure it's for the correct resource

#### Anthropic

- **Issue**: "Invalid API key"
  - **Solution**: Verify API key format and permissions

- **Issue**: "Model not available"
  - **Solution**: Check if you have access to the requested model

#### Google Vertex AI

- **Issue**: "Permission denied"
  - **Solution**: Verify service account has correct permissions

- **Issue**: "Project not found"
  - **Solution**: Check project ID and ensure Vertex AI API is enabled

#### Local Models

- **Issue**: "Connection refused"
  - **Solution**: Ensure Ollama or your local server is running

- **Issue**: "Out of memory"
  - **Solution**: Use a smaller model or increase system RAM

### Diagnostic Commands

Run diagnostics to check AI provider connectivity:

```bash
npm run check-ai-providers
```

This will test each configured provider and report any issues.

## Example Configurations

### High-Performance Configuration

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4
AI_CACHE_ENABLED=true
AI_CACHE_TTL=3600000
AI_MAX_CONCURRENT_REQUESTS=10
AI_RETRY_COUNT=3
AI_RETRY_DELAY=1000
AI_FALLBACK_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-3-sonnet
```

### Cost-Effective Configuration

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-3.5-turbo
AI_CACHE_ENABLED=true
AI_CACHE_TTL=7200000
AI_MAX_TOKENS=1024
AI_BUDGET_LIMIT_DAILY=5
AI_BUDGET_LIMIT_MONTHLY=50
```

### Self-Hosted Configuration

```env
AI_PROVIDER=local
LOCAL_MODEL_ENDPOINT=http://localhost:11434/api/generate
LOCAL_MODEL_NAME=llama2
LOCAL_MODEL_MAX_TOKENS=2048
AI_CACHE_ENABLED=true
AI_CACHE_TTL=3600000
```

### Enterprise Configuration

```env
AI_PROVIDER=azure
AZURE_OPENAI_API_KEY=your_azure_openai_api_key
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=your_deployment_name
AZURE_OPENAI_API_VERSION=2023-05-15
AI_FALLBACK_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-3-opus
AI_CACHE_ENABLED=true
AI_CACHE_TTL=1800000
AI_MAX_CONCURRENT_REQUESTS=20
AI_RETRY_COUNT=5
AI_RETRY_DELAY=2000
```

## Conclusion

This guide covers the configuration of various AI providers for the Discord AI Moderator application. Choose the provider that best fits your needs based on performance, cost, and feature requirements.

For additional assistance, refer to the provider's official documentation or open an issue on the project's GitHub repository.
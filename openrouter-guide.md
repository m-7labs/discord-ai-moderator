# AI Provider Configuration Guide

The Discord AI Moderator supports multiple AI providers through OpenRouter, giving you flexibility in choosing models based on cost, performance, and availability.

## Supported Providers

### 🎯 Recommended: OpenRouter (Multi-Provider Access)

**OpenRouter** provides access to multiple AI providers through a single API, including:
- **Anthropic** (Claude models)
- **OpenAI** (GPT models)
- **Google** (Gemini models)  
- **Meta** (Llama models)
- **Many others**

**Benefits:**
- ✅ Cost comparison across providers
- ✅ Automatic failover between models
- ✅ Pay-per-use pricing
- ✅ No monthly commitments
- ✅ Access to latest models
- ✅ Built-in rate limiting and error handling

### 🔗 Direct Provider: Anthropic

**Direct Anthropic integration** for users who prefer to use Claude models directly.

**Benefits:**
- ✅ Direct API access
- ✅ Potentially lower latency
- ✅ Full control over API settings

## Setup Instructions

### Option 1: OpenRouter Setup (Recommended)

1. **Create OpenRouter Account**
   - Go to [openrouter.ai](https://openrouter.ai)
   - Create an account
   - Add credits to your account (pay-per-use)

2. **Get API Key**
   - Go to "Keys" in your dashboard
   - Create a new API key
   - Copy the key (starts with `sk-or-v1-...`)

3. **Configure Environment**
   ```env
   AI_PROVIDER=OPENROUTER
   OPENROUTER_API_KEY=sk-or-v1-your-key-here
   OPENROUTER_APP_NAME=Discord-AI-Moderator
   OPENROUTER_SITE_URL=https://github.com/yourusername/discord-ai-moderator
   
   # Model Selection (customize as needed)
   LOW_RISK_MODEL=anthropic/claude-3-haiku:beta
   MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta
   HIGH_RISK_MODEL=anthropic/claude-3-opus:beta
   ```

### Option 2: Direct Anthropic Setup

1. **Create Anthropic Account**
   - Go to [console.anthropic.com](https://console.anthropic.com)
   - Create an account and add credits

2. **Get API Key**
   - Create an API key in the console
   - Copy the key (starts with `sk-ant-...`)

3. **Configure Environment**
   ```env
   AI_PROVIDER=ANTHROPIC
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```

## Model Selection Guide

### Understanding Risk Levels

The system automatically selects models based on message risk assessment:

- **Low Risk (70-80% of messages)**: Fast, cheap models for obvious non-violations
- **Medium Risk (15-25% of messages)**: Balanced models for ambiguous content
- **High Risk (5-10% of messages)**: Best models for critical moderation decisions

### Recommended Model Configurations

#### 💰 Cost-Optimized Setup
```env
LOW_RISK_MODEL=anthropic/claude-3-haiku:beta      # $0.25/1M tokens
MEDIUM_RISK_MODEL=anthropic/claude-3-haiku:beta   # Same model for consistency
HIGH_RISK_MODEL=anthropic/claude-3-sonnet:beta    # $3/1M tokens for critical only
```

#### ⚖️ Balanced Setup (Recommended)
```env
LOW_RISK_MODEL=anthropic/claude-3-haiku:beta      # $0.25/1M tokens
MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta  # $3/1M tokens
HIGH_RISK_MODEL=anthropic/claude-3-opus:beta      # $15/1M tokens
```

#### 🎯 Accuracy-Focused Setup
```env
LOW_RISK_MODEL=anthropic/claude-3-sonnet:beta     # $3/1M tokens
MEDIUM_RISK_MODEL=anthropic/claude-3-opus:beta    # $15/1M tokens
HIGH_RISK_MODEL=anthropic/claude-3-opus:beta      # $15/1M tokens
```

#### 🔄 Multi-Provider Setup
```env
LOW_RISK_MODEL=openai/gpt-3.5-turbo             # $0.50/1M tokens
MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta # $3/1M tokens
HIGH_RISK_MODEL=openai/gpt-4                    # $10/1M tokens
```

## Available Models

### Anthropic (Claude)
- `anthropic/claude-3-haiku:beta` - Fast, cost-effective
- `anthropic/claude-3-sonnet:beta` - Balanced performance
- `anthropic/claude-3-opus:beta` - Highest accuracy
- `anthropic/claude-2` - Previous generation

### OpenAI (GPT)
- `openai/gpt-3.5-turbo` - Fast and affordable
- `openai/gpt-4-turbo-preview` - Latest GPT-4 variant
- `openai/gpt-4` - High accuracy
- `openai/gpt-4-32k` - Extended context

### Google (Gemini)
- `google/gemini-pro` - Google's flagship model
- `google/gemini-pro-vision` - With image understanding

### Meta (Llama)
- `meta-llama/llama-2-70b-chat` - Open source alternative
- `meta-llama/llama-2-13b-chat` - Smaller, faster variant

### Other Providers
- Many more available on OpenRouter - check their documentation

## Cost Comparison

### Typical Monthly Costs (10,000 messages)

| Setup Type | Low Traffic | Medium Traffic | High Traffic |
|------------|-------------|----------------|--------------|
| Cost-Optimized | $2-5 | $10-20 | $30-60 |
| Balanced | $5-10 | $20-40 | $60-120 |
| Accuracy-Focused | $10-20 | $40-80 | $120-240 |

*Costs vary based on message length and violation rates*

## Performance Tuning

### Adjusting Risk Thresholds

You can modify the risk assessment in `src/utils/moderationUtils.js`:

```javascript
function selectModelByRisk(riskScore) {
  // More conservative (uses cheaper models more often)
  if (riskScore < 0.1) return getModelForRisk('low');    // 90% low risk
  if (riskScore < 0.5) return getModelForRisk('medium'); // 9% medium risk
  return getModelForRisk('high');                        // 1% high risk
  
  // More aggressive (uses better models more often)
  if (riskScore < 0.5) return getModelForRisk('low');    // 50% low risk
  if (riskScore < 0.8) return getModelForRisk('medium'); // 30% medium risk
  return getModelForRisk('high');                        // 20% high risk
}
```

### Custom Model Rotation

For high-volume servers, you can implement model rotation:

```env
# Rotate between different providers for load balancing
LOW_RISK_MODEL=openai/gpt-3.5-turbo,anthropic/claude-3-haiku:beta
MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta,openai/gpt-4-turbo-preview
HIGH_RISK_MODEL=anthropic/claude-3-opus:beta,openai/gpt-4
```

## Troubleshooting

### Common Issues

**"Model not available" errors:**
- Check OpenRouter's model availability page
- Some models have usage limits or regional restrictions
- Try switching to an alternative model

**High costs:**
- Review your risk thresholds
- Consider using more cost-effective models
- Enable degraded mode during peak times

**Authentication errors:**
- Verify your API key is correct
- Check your account has sufficient credits
- Ensure the key has proper permissions

### Monitoring Costs

1. **OpenRouter Dashboard**
   - Monitor usage in real-time
   - Set up spending alerts
   - View cost breakdowns by model

2. **Bot Dashboard**
   - Use `/modagent_stats` to see token usage
   - Monitor model selection patterns
   - Track cost per message

3. **Custom Alerts**
   ```env
   # Set spending limits (optional)
   MAX_DAILY_SPEND=10.00
   ALERT_THRESHOLD=5.00
   ```

## Best Practices

### Security
- Never commit API keys to version control
- Use environment variables for all sensitive data
- Rotate API keys periodically
- Monitor for unusual usage patterns

### Cost Management
- Start with cost-optimized settings
- Monitor usage for the first week
- Adjust models based on actual needs
- Set up spending alerts

### Performance
- Use caching for repeated content
- Implement rate limiting
- Monitor response times
- Have fallback strategies

## Migration Guide

### From Anthropic to OpenRouter

1. **Get OpenRouter API key**
2. **Update environment variables:**
   ```env
   # Old
   AI_PROVIDER=ANTHROPIC
   ANTHROPIC_API_KEY=sk-ant-...
   
   # New
   AI_PROVIDER=OPENROUTER
   OPENROUTER_API_KEY=sk-or-v1-...
   LOW_RISK_MODEL=anthropic/claude-3-haiku:beta
   ```
3. **Restart the bot**
4. **Monitor for any issues**

### From OpenRouter to Anthropic

1. **Get Anthropic API key**
2. **Update environment variables:**
   ```env
   # Old
   AI_PROVIDER=OPENROUTER
   OPENROUTER_API_KEY=sk-or-v1-...
   
   # New
   AI_PROVIDER=ANTHROPIC
   ANTHROPIC_API_KEY=sk-ant-...
   ```
3. **Restart the bot**

## Support

- **OpenRouter**: [openrouter.ai/docs](https://openrouter.ai/docs)
- **Anthropic**: [docs.anthropic.com](https://docs.anthropic.com)
- **Discord AI Moderator**: Create an issue in the GitHub repository

## Advanced Configuration

### Custom Provider Integration

You can extend the system to support additional providers by modifying `src/anthropic.js`. The architecture is designed to be provider-agnostic.
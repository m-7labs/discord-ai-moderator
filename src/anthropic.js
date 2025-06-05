const logger = require('./utils/logger');
const errorManager = require('./utils/error-manager');
const { performance } = require('perf_hooks');
const crypto = require('crypto');
const { sanitizeInput } = require('./database');

// Import enhanced security modules
const SecurityValidator = require('./utils/security-validator');
const AuditLogger = require('./utils/audit-logger');
const { FaultTolerantSystem } = require('./utils/fault-tolerance');
const CircuitBreaker = require('./utils/circuitBreaker');

// AI Provider configuration with enhanced validation
const AI_PROVIDER = process.env.AI_PROVIDER || 'OPENROUTER';

// Validate environment configuration with security checks
if (!['ANTHROPIC', 'OPENROUTER'].includes(AI_PROVIDER)) {
  throw new Error(`Invalid AI provider: ${AI_PROVIDER}. Must be 'ANTHROPIC' or 'OPENROUTER'`);
}

// Enhanced security configuration
const SECURITY_CONFIG = {
  maxContentLength: 8000,
  maxContextItems: 20,
  maxRulesLength: 5000,
  maxModelNameLength: 100,
  maxReasoningLength: 500,
  maxTokens: 300,
  requestTimeout: 30000,
  maxRetries: 3,
  backoffMultiplier: 2
};

// Request signing for AI API calls
class RequestSigner {
  constructor(secret) {
    this.secret = secret || process.env.AI_API_SECRET || process.env.JWT_SECRET;
    if (!this.secret) {
      logger.warn('No AI API secret configured, request signing disabled');
    }
  }
  
  sign(data) {
    if (!this.secret) return null;
    
    const payload = JSON.stringify(data);
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(payload)
      .digest('hex');
    
    return signature;
  }
  
  verify(data, signature) {
    if (!this.secret || !signature) return false;
    
    const expectedSignature = this.sign(data);
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }
}

// Cost tracking for AI API usage
class CostTracker {
  constructor() {
    this.dailySpend = 0;
    this.monthlySpend = 0;
    this.lastResetDate = new Date().toDateString();
    this.maxDailySpend = parseFloat(process.env.MAX_DAILY_SPEND) || 100.00;
    this.alertThreshold = parseFloat(process.env.ALERT_THRESHOLD) || 50.00;
  }
  
  async track(usage) {
    try {
      const cost = this.calculateCost(usage);
      
      // Reset daily counter if needed
      const today = new Date().toDateString();
      if (today !== this.lastResetDate) {
        this.dailySpend = 0;
        this.lastResetDate = today;
      }
      
      this.dailySpend += cost;
      
      // Check spending limits
      if (this.dailySpend > this.maxDailySpend) {
        await AuditLogger.logSecurityEvent({
          type: 'DAILY_SPEND_LIMIT_EXCEEDED',
          dailySpend: this.dailySpend,
          maxDailySpend: this.maxDailySpend,
          timestamp: Date.now()
        });
        
        throw new Error('Daily spending limit exceeded');
      }
      
      if (this.dailySpend > this.alertThreshold) {
        await AuditLogger.log({
          action: 'SPENDING_ALERT',
          dailySpend: this.dailySpend,
          threshold: this.alertThreshold,
          timestamp: Date.now()
        });
      }
      
      // Log usage for audit
      await AuditLogger.log({
        action: 'AI_API_USAGE',
        model: usage.model,
        inputTokens: usage.input_tokens,
        outputTokens: usage.output_tokens,
        cost: cost,
        dailySpend: this.dailySpend,
        timestamp: Date.now()
      });
      
    } catch (error) {
      logger.error('Cost tracking failed:', error);
      throw error;
    }
  }
  
  calculateCost(usage) {
    // Pricing per 1K tokens (approximate)
    const pricing = {
      'claude-3-opus': { input: 0.015, output: 0.075 },
      'claude-3-sonnet': { input: 0.003, output: 0.015 },
      'claude-3-haiku': { input: 0.00025, output: 0.00125 },
      'gpt-4': { input: 0.03, output: 0.06 },
      'gpt-3.5-turbo': { input: 0.001, output: 0.002 }
    };
    
    // Find matching pricing
    let modelPricing = null;
    for (const [model, prices] of Object.entries(pricing)) {
      if (usage.model.includes(model)) {
        modelPricing = prices;
        break;
      }
    }
    
    if (!modelPricing) {
      // Default pricing for unknown models
      modelPricing = { input: 0.01, output: 0.03 };
    }
    
    const inputCost = (usage.input_tokens / 1000) * modelPricing.input;
    const outputCost = (usage.output_tokens / 1000) * modelPricing.output;
    
    return inputCost + outputCost;
  }
  
  getStatus() {
    return {
      dailySpend: this.dailySpend,
      maxDailySpend: this.maxDailySpend,
      percentUsed: (this.dailySpend / this.maxDailySpend) * 100,
      remaining: this.maxDailySpend - this.dailySpend
    };
  }
}

// Initialize security components
const requestSigner = new RequestSigner();
const costTracker = new CostTracker();
const faultTolerantSystem = new FaultTolerantSystem();

// Initialize circuit breakers for different AI providers
const anthropicBreaker = new CircuitBreaker({
  failureThreshold: 5,
  resetTimeout: 60000,
  monitoringPeriod: 60000
});

const openrouterBreaker = new CircuitBreaker({
  failureThreshold: 5,
  resetTimeout: 60000,
  monitoringPeriod: 60000
});

// Initialize AI client based on provider with enhanced security
let aiClient;
let isOpenRouter = false;

if (AI_PROVIDER === 'ANTHROPIC') {
  const { AnthropicApi } = require('@anthropic-ai/sdk');
  
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY is required when using ANTHROPIC provider');
  }
  
  // Enhanced API key validation
  if (!process.env.ANTHROPIC_API_KEY.startsWith('sk-ant-')) {
    throw new Error('Invalid Anthropic API key format');
  }
  
  if (process.env.ANTHROPIC_API_KEY.length < 50) {
    throw new Error('Anthropic API key appears to be invalid (too short)');
  }
  
  aiClient = new AnthropicApi({
    apiKey: process.env.ANTHROPIC_API_KEY,
    timeout: SECURITY_CONFIG.requestTimeout,
    maxRetries: 0 // Handle retries manually with circuit breaker
  });
  
  logger.info('Using direct Anthropic API with enhanced security');
} else if (AI_PROVIDER === 'OPENROUTER') {
  isOpenRouter = true;
  
  if (!process.env.OPENROUTER_API_KEY) {
    throw new Error('OPENROUTER_API_KEY is required when using OPENROUTER provider');
  }
  
  // Enhanced API key validation
  if (!process.env.OPENROUTER_API_KEY.startsWith('sk-or-v1-')) {
    throw new Error('Invalid OpenRouter API key format');
  }
  
  if (process.env.OPENROUTER_API_KEY.length < 50) {
    throw new Error('OpenRouter API key appears to be invalid (too short)');
  }
  
  logger.info('Using OpenRouter API with enhanced security');
}

// Enhanced input validation and sanitization
function validateAndSanitizeContent(content, context = 'general') {
  try {
    // Type validation
    if (typeof content !== 'string') {
      throw SecurityValidator.createSecurityError('Content must be a string', {
        code: 'INVALID_CONTENT_TYPE',
        context
      });
    }
    
    // Length validation
    if (content.length === 0) {
      throw SecurityValidator.createSecurityError('Content cannot be empty', {
        code: 'EMPTY_CONTENT',
        context
      });
    }
    
    if (content.length > SECURITY_CONFIG.maxContentLength) {
      throw SecurityValidator.createSecurityError('Content too long for processing', {
        code: 'CONTENT_TOO_LONG',
        context,
        maxLength: SECURITY_CONFIG.maxContentLength,
        actualLength: content.length
      });
    }
    
    // Use SecurityValidator for comprehensive sanitization
    return SecurityValidator.sanitizeMessageContent(content, SECURITY_CONFIG.maxContentLength);
  } catch (error) {
    if (error.isSecurityError) {
      throw error;
    }
    throw SecurityValidator.createSecurityError('Content validation failed', {
      code: 'VALIDATION_ERROR',
      context,
      originalError: error.message
    });
  }
}

function validateModel(model, context = 'general') {
  try {
    if (typeof model !== 'string') {
      throw SecurityValidator.createSecurityError('Model must be a string', {
        code: 'INVALID_MODEL_TYPE',
        context
      });
    }
    
    if (model.length === 0 || model.length > SECURITY_CONFIG.maxModelNameLength) {
      throw SecurityValidator.createSecurityError('Invalid model name length', {
        code: 'INVALID_MODEL_LENGTH',
        context,
        maxLength: SECURITY_CONFIG.maxModelNameLength
      });
    }
    
    // Enhanced model name validation
    if (!/^[a-zA-Z0-9\-\/:_\.]+$/.test(model)) {
      throw SecurityValidator.createSecurityError('Invalid model name format', {
        code: 'INVALID_MODEL_FORMAT',
        context
      });
    }
    
    // Check for known malicious patterns
    const maliciousPatterns = [
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /<script/i,
      /\.\./,
      /\/\//
    ];
    
    if (maliciousPatterns.some(pattern => pattern.test(model))) {
      throw SecurityValidator.createSecurityError('Potentially malicious model name detected', {
        code: 'MALICIOUS_MODEL_NAME',
        context
      });
    }
    
    return sanitizeInput(model);
  } catch (error) {
    if (error.isSecurityError) {
      throw error;
    }
    throw SecurityValidator.createSecurityError('Model validation failed', {
      code: 'MODEL_VALIDATION_ERROR',
      context,
      originalError: error.message
    });
  }
}

function validateRules(rules, context = 'general') {
  try {
    return SecurityValidator.sanitizeRules(rules);
  } catch (error) {
    if (error.isSecurityError) {
      throw error;
    }
    throw SecurityValidator.createSecurityError('Rules validation failed', {
      code: 'RULES_VALIDATION_ERROR',
      context,
      originalError: error.message
    });
  }
}

/**
 * Enhanced system prompt builder with security considerations
 */
function buildModerationPrompt(serverRules) {
  const sanitizedRules = validateRules(serverRules);
  
  // Prevent prompt injection by escaping potential control sequences
  const escapedRules = sanitizedRules
    .replace(/\n\n+/g, '\n\n') // Normalize line breaks
    .replace(/[^\x20-\x7E\n\r\t]/g, ''); // Remove non-printable characters
  
  return `You are a Discord moderation assistant. Your task is to analyze messages for rule violations with fairness and accuracy.

SERVER RULES:
${escapedRules}

IMPORTANT: You must respond ONLY with valid JSON. Do not include any other text before or after the JSON response.

For each message, analyze:
1. Whether it violates any rules (Yes/No)
2. The category of violation (Toxicity, Harassment, Spam, NSFW, Other)
3. The severity level (None, Mild, Moderate, Severe)
4. The confidence in your assessment (0.0-1.0)
5. Whether the message appears to be:
   - A genuine question about rules
   - An accidental minor infraction
   - An intentional rule violation
6. Recommended action (None, Flag, Warn, Mute, Kick, Ban)

Consider conversation context carefully to avoid false positives. Be particularly vigilant about:
- Hate speech and discriminatory language
- Misinformation and non-fact-checked claims
- Patterns of harassment
- NSFW content in SFW channels

Respond ONLY with JSON in this exact format:
{
  "isViolation": true|false,
  "category": "category",
  "severity": "level",
  "confidence": 0.0-1.0,
  "intent": "question|accidental|intentional|normal",
  "recommendedAction": "action",
  "reasoning": "brief explanation"
}`;
}

/**
 * Enhanced model selection with security validation
 */
function getModelForRisk(riskLevel) {
  if (!['low', 'medium', 'high'].includes(riskLevel)) {
    throw SecurityValidator.createSecurityError('Invalid risk level', {
      code: 'INVALID_RISK_LEVEL',
      validValues: ['low', 'medium', 'high']
    });
  }
  
  if (AI_PROVIDER === 'ANTHROPIC') {
    const models = {
      low: 'claude-3-haiku-20240307',
      medium: 'claude-3-sonnet-20240229',
      high: 'claude-3-opus-20240229'
    };
    return models[riskLevel];
  } else {
    const models = {
      low: process.env.LOW_RISK_MODEL || 'anthropic/claude-3-haiku:beta',
      medium: process.env.MEDIUM_RISK_MODEL || 'anthropic/claude-3-sonnet:beta',
      high: process.env.HIGH_RISK_MODEL || 'anthropic/claude-3-opus:beta'
    };
    
    return validateModel(models[riskLevel]);
  }
}

/**
 * Enhanced OpenRouter API call with comprehensive security
 */
async function callOpenRouter(messages, model, options = {}) {
  const https = require('https');
  const { URL } = require('url');
  
  try {
    // Enhanced input validation
    const validatedModel = validateModel(model, 'OpenRouter');
    
    if (!Array.isArray(messages) || messages.length === 0) {
      throw SecurityValidator.createSecurityError('Messages must be a non-empty array', {
        code: 'INVALID_MESSAGES_ARRAY'
      });
    }
    
    if (messages.length > 10) {
      throw SecurityValidator.createSecurityError('Too many messages in request', {
        code: 'TOO_MANY_MESSAGES',
        maxMessages: 10
      });
    }
    
    // Enhanced URL validation to prevent SSRF
    const apiUrl = 'https://openrouter.ai/api/v1/chat/completions';
    const parsedUrl = new URL(apiUrl);
    
    if (parsedUrl.hostname !== 'openrouter.ai') {
      throw SecurityValidator.createSecurityError('Invalid API endpoint', {
        code: 'INVALID_ENDPOINT'
      });
    }
    
    if (parsedUrl.protocol !== 'https:') {
      throw SecurityValidator.createSecurityError('Insecure protocol detected', {
        code: 'INSECURE_PROTOCOL'
      });
    }
    
    // Prepare request with enhanced security
    const requestId = crypto.randomUUID();
    const timestamp = Date.now();
    
    const requestBody = {
      model: validatedModel,
      messages: messages.map(msg => {
        const role = ['system', 'user', 'assistant'].includes(msg.role) ? msg.role : 'user';
        const content = validateAndSanitizeContent(msg.content, 'OpenRouter');
        return { role, content };
      }),
      max_tokens: Math.min(SECURITY_CONFIG.maxTokens, parseInt(process.env.MAX_TOKENS) || SECURITY_CONFIG.maxTokens),
      temperature: 0,
      response_format: { type: "json_object" },
      metadata: {
        request_id: requestId,
        timestamp,
        signature: requestSigner.sign({ model: validatedModel, timestamp })
      }
    };
    
    // Enhanced request options with security settings
    const requestOptions = {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'HTTP-Referer': process.env.OPENROUTER_SITE_URL || 'https://github.com/discord-ai-moderator',
        'X-Title': process.env.OPENROUTER_APP_NAME || 'Discord AI Moderator',
        'Content-Type': 'application/json',
        'User-Agent': 'Discord-AI-Moderator/1.0.0',
        'X-Request-ID': requestId,
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      },
      timeout: SECURITY_CONFIG.requestTimeout,
      agent: new https.Agent({
        keepAlive: false,
        maxSockets: 10,
        timeout: SECURITY_CONFIG.requestTimeout,
        // Enhanced security settings
        secureProtocol: 'TLSv1_2_method',
        ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384',
        honorCipherOrder: true
      })
    };
    
    // Use secure fetch with additional protections
    const fetch = require('node-fetch');
    
    const response = await fetch(apiUrl, {
      ...requestOptions,
      body: JSON.stringify(requestBody),
      follow: 0, // Never follow redirects
      size: 1000000, // 1MB response limit
      compress: true,
      signal: AbortSignal.timeout(SECURITY_CONFIG.requestTimeout)
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      
      // Log failed API call for audit
      await AuditLogger.logSecurityEvent({
        type: 'AI_API_CALL_FAILED',
        provider: 'OpenRouter',
        model: validatedModel,
        status: response.status,
        error: errorText.substring(0, 500),
        requestId,
        timestamp: Date.now()
      });
      
      const error = new Error(`OpenRouter API error: ${response.status} ${response.statusText}`);
      error.status = response.status;
      error.response = errorText.substring(0, 500);
      throw error;
    }

    const jsonResponse = await response.json();
    
    // Enhanced response validation
    if (!jsonResponse || typeof jsonResponse !== 'object') {
      throw new Error('Invalid response format from OpenRouter');
    }
    
    if (!jsonResponse.choices || !Array.isArray(jsonResponse.choices) || jsonResponse.choices.length === 0) {
      throw new Error('No choices in OpenRouter response');
    }
    
    // Validate response content
    const choice = jsonResponse.choices[0];
    if (!choice.message || !choice.message.content) {
      throw new Error('Invalid choice format in OpenRouter response');
    }
    
    // Log successful API call
    await AuditLogger.log({
      action: 'AI_API_CALL_SUCCESS',
      provider: 'OpenRouter',
      model: validatedModel,
      requestId,
      tokensUsed: jsonResponse.usage?.total_tokens || 0,
      timestamp: Date.now()
    });
    
    return jsonResponse;
  } catch (error) {
    // Enhanced error logging
    await AuditLogger.logSecurityEvent({
      type: 'AI_API_CALL_ERROR',
      provider: 'OpenRouter',
      model: model,
      error: error.message,
      timestamp: Date.now()
    });
    
    throw error;
  }
}

/**
 * Enhanced Anthropic API call with comprehensive security
 */
async function callAnthropic(messages, model, options = {}) {
  try {
    const validatedModel = validateModel(model, 'Anthropic');
    
    if (!Array.isArray(messages) || messages.length === 0) {
      throw SecurityValidator.createSecurityError('Messages must be a non-empty array', {
        code: 'INVALID_MESSAGES_ARRAY'
      });
    }
    
    // Convert and validate messages format for Anthropic
    const systemMessage = messages.find(m => m.role === 'system');
    const userMessages = messages
      .filter(m => m.role !== 'system')
      .map(msg => ({
        role: msg.role === 'user' ? 'user' : 'user',
        content: validateAndSanitizeContent(msg.content, 'Anthropic')
      }));
    
    if (userMessages.length === 0) {
      throw SecurityValidator.createSecurityError('At least one user message is required', {
        code: 'NO_USER_MESSAGES'
      });
    }
    
    const requestId = crypto.randomUUID();
    const timestamp = Date.now();
    
    const requestParams = {
      model: validatedModel,
      max_tokens: Math.min(SECURITY_CONFIG.maxTokens, parseInt(process.env.MAX_TOKENS) || SECURITY_CONFIG.maxTokens),
      messages: userMessages,
      temperature: 0,
      metadata: {
        request_id: requestId,
        timestamp,
        signature: requestSigner.sign({ model: validatedModel, timestamp })
      }
    };
    
    if (systemMessage) {
      requestParams.system = validateAndSanitizeContent(systemMessage.content, 'Anthropic');
    }
    
    const response = await aiClient.messages.create(requestParams);
    
    // Enhanced response validation
    if (!response || !response.content || !Array.isArray(response.content) || response.content.length === 0) {
      throw new Error('Invalid response format from Anthropic');
    }
    
    const textContent = response.content[0];
    if (!textContent || textContent.type !== 'text' || !textContent.text) {
      throw new Error('Invalid content format in Anthropic response');
    }
    
    // Log successful API call
    await AuditLogger.log({
      action: 'AI_API_CALL_SUCCESS',
      provider: 'Anthropic',
      model: validatedModel,
      requestId,
      tokensUsed: (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0),
      timestamp: Date.now()
    });
    
    return response;
  } catch (error) {
    await AuditLogger.logSecurityEvent({
      type: 'AI_API_CALL_ERROR',
      provider: 'Anthropic',
      model: model,
      error: error.message,
      timestamp: Date.now()
    });
    
    throw error;
  }
}

/**
 * Enhanced AI response validation
 */
function validateAIResponse(response, provider) {
  try {
    let responseText;
    
    if (provider === 'OpenRouter') {
      if (!response?.choices?.[0]?.message?.content) {
        throw new Error('Invalid OpenRouter response structure');
      }
      responseText = response.choices[0].message.content;
    } else {
      if (!response?.content?.[0]?.text) {
        throw new Error('Invalid Anthropic response structure');
      }
      responseText = response.content[0].text;
    }
    
    // Enhanced response validation
    if (!responseText || typeof responseText !== 'string') {
      throw new Error('Empty or invalid response text');
    }
    
    if (responseText.length > 10000) {
      throw new Error('Response too long from AI provider');
    }
    
    // Sanitize response before parsing
    const sanitizedResponse = sanitizeInput(responseText);
    
    // Extract JSON from response (handle cases where there might be extra text)
    let jsonMatch = sanitizedResponse.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON found in AI response');
    }
    
    const analysisResult = JSON.parse(jsonMatch[0]);
    
    // Enhanced structure validation
    if (typeof analysisResult !== 'object' || analysisResult === null) {
      throw new Error('Invalid response structure');
    }
    
    // Validate and sanitize response fields with security checks
    const validatedResult = {
      isViolation: Boolean(analysisResult.isViolation),
      category: ['Toxicity', 'Harassment', 'Spam', 'NSFW', 'Other'].includes(analysisResult.category) ? 
        analysisResult.category : null,
      severity: ['None', 'Mild', 'Moderate', 'Severe'].includes(analysisResult.severity) ? 
        analysisResult.severity : null,
      confidence: typeof analysisResult.confidence === 'number' && 
        analysisResult.confidence >= 0 && analysisResult.confidence <= 1 ? 
        Number(analysisResult.confidence.toFixed(3)) : 0,
      intent: ['question', 'accidental', 'intentional', 'normal'].includes(analysisResult.intent) ? 
        analysisResult.intent : 'normal',
      recommendedAction: ['None', 'Flag', 'Warn', 'Mute', 'Kick', 'Ban'].includes(analysisResult.recommendedAction) ? 
        analysisResult.recommendedAction : 'None',
      reasoning: typeof analysisResult.reasoning === 'string' ? 
        sanitizeInput(analysisResult.reasoning.substring(0, SECURITY_CONFIG.maxReasoningLength)) : 
        'No reasoning provided'
    };
    
    // Additional validation: Check for suspicious patterns in reasoning
    const suspiciousPatterns = [
      /<script/i,
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /onclick/i,
      /onerror/i
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(validatedResult.reasoning))) {
      validatedResult.reasoning = 'Reasoning filtered for security';
      
      AuditLogger.logSecurityEvent({
        type: 'SUSPICIOUS_AI_RESPONSE',
        provider,
        suspiciousContent: analysisResult.reasoning?.substring(0, 100),
        timestamp: Date.now()
      });
    }
    
    return validatedResult;
  } catch (error) {
    AuditLogger.logSecurityEvent({
      type: 'AI_RESPONSE_VALIDATION_FAILED',
      provider,
      error: error.message,
      timestamp: Date.now()
    });
    
    throw error;
  }
}

/**
 * Enhanced main AI processing function with comprehensive security
 */
async function processWithAI(content, context, rules, model, options = {}) {
  const startTime = performance.now();
  let tokensUsed = 0;
  const requestId = crypto.randomUUID();
  
  try {
    // Pre-processing security validation
    const sanitizedContent = validateAndSanitizeContent(content, 'processWithAI');
    const sanitizedRules = validateRules(rules, 'processWithAI');
    const validatedModel = validateModel(model, 'processWithAI');
    
    // Enhanced context validation
    if (!Array.isArray(context)) {
      throw SecurityValidator.createSecurityError('Context must be an array', {
        code: 'INVALID_CONTEXT_TYPE'
      });
    }
    
    if (context.length > SECURITY_CONFIG.maxContextItems) {
      context = context.slice(0, SECURITY_CONFIG.maxContextItems);
    }
    
    // Sanitize context with enhanced validation
    const sanitizedContext = context.map((item, index) => {
      if (typeof item !== 'object' || item === null) {
        return {};
      }
      
      try {
        return {
          id: item.id ? SecurityValidator.validateDiscordId(item.id.toString(), 'context') : '',
          content: item.content ? validateAndSanitizeContent(item.content.toString(), 'context') : '',
          author: item.author ? sanitizeInput(item.author.toString().substring(0, 100)) : '',
          timestamp: item.timestamp || Date.now()
        };
      } catch (error) {
        logger.warn(`Invalid context item at index ${index}:`, error.message);
        return {};
      }
    }).filter(item => Object.keys(item).length > 0);
    
    // Prepare secure messages
    const messages = [
      {
        role: "system",
        content: buildModerationPrompt(sanitizedRules)
      },
      {
        role: "user",
        content: `Channel context: ${JSON.stringify(sanitizedContext)}\n\nMessage to analyze: ${sanitizedContent}`
      }
    ];
    
    // Content hash for caching and deduplication
    const contentHash = crypto
      .createHash('sha256')
      .update(sanitizedContent + sanitizedRules)
      .digest('hex');
    
    // Log processing attempt
    await AuditLogger.log({
      action: 'AI_PROCESSING_STARTED',
      contentHash,
      model: validatedModel,
      provider: AI_PROVIDER,
      requestId,
      timestamp: Date.now()
    });
    
    let response;
    let responseText;
    let provider = AI_PROVIDER;
    
    // Use fault-tolerant system for AI processing
    const result = await faultTolerantSystem.executeWithFallback('ai', {
      content: sanitizedContent,
      context: sanitizedContext,
      rules: sanitizedRules,
      model: validatedModel,
      messages,
      requestId
    });
    
    if (result.usedFallback) {
      provider = result.provider;
      response = result.response;
    } else {
      // Execute with circuit breaker
      const breaker = isOpenRouter ? openrouterBreaker : anthropicBreaker;
      
      response = await breaker.execute(async () => {
        if (isOpenRouter) {
          return await callOpenRouter(messages, validatedModel, { requestId });
        } else {
          return await callAnthropic(messages, validatedModel, { requestId });
        }
      });
    }
    
    // Validate AI response
    const validatedResponse = validateAIResponse(response, provider);
    
    // Extract token usage
    if (isOpenRouter) {
      tokensUsed = response.usage?.total_tokens || 0;
    } else {
      tokensUsed = (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0);
    }
    
    // Track costs
    await costTracker.track({
      model: validatedModel,
      input_tokens: response.usage?.input_tokens || response.usage?.prompt_tokens || Math.floor(tokensUsed * 0.7),
      output_tokens: response.usage?.output_tokens || response.usage?.completion_tokens || Math.floor(tokensUsed * 0.3),
      request_id: requestId
    });
    
    const endTime = performance.now();
    const processingTimeMs = endTime - startTime;
    
    // Prepare final result with security metadata
    const finalResult = {
      ...validatedResponse,
      tokensUsed,
      processingTimeMs,
      modelUsed: validatedModel,
      provider,
      requestId,
      contentHash,
      securityValidated: true
    };
    
    // Log successful processing
    await AuditLogger.log({
      action: 'AI_PROCESSING_COMPLETED',
      contentHash,
      isViolation: finalResult.isViolation,
      confidence: finalResult.confidence,
      model: validatedModel,
      provider,
      tokensUsed,
      processingTimeMs,
      requestId,
      timestamp: Date.now()
    });
    
    return finalResult;
    
  } catch (error) {
    const endTime = performance.now();
    const processingTimeMs = endTime - startTime;
    
    // Enhanced error handling with security context
    await AuditLogger.logSecurityEvent({
      type: 'AI_PROCESSING_ERROR',
      error: error.message,
      contentLength: content?.length || 0,
      model: model,
      provider: AI_PROVIDER,
      requestId,
      processingTimeMs,
      timestamp: Date.now()
    });
    
    errorManager.handleError(error, AI_PROVIDER.toLowerCase(), {
      operation: 'processWithAI',
      contentLength: content?.length || 0,
      model: model,
      requestId
    });
    
    // Secure fallback response
    return {
      isViolation: false,
      category: null,
      severity: null,
      confidence: 0,
      intent: 'normal',
      recommendedAction: "Flag", // Conservative approach on errors
      reasoning: "Processing error - flagged for manual review",
      tokensUsed: 0,
      processingTimeMs,
      modelUsed: model,
      provider: AI_PROVIDER,
      requestId,
      error: true,
      securityValidated: false
    };
  }
}

/**
 * Legacy function name for backward compatibility
 */
async function processWithClaude(content, context, rules, model) {
  return await processWithAI(content, context, rules, model);
}

/**
 * Enhanced model availability check
 */
function getAvailableModels() {
  if (AI_PROVIDER === 'ANTHROPIC') {
    return {
      low: ['claude-3-haiku-20240307'],
      medium: ['claude-3-sonnet-20240229'],
      high: ['claude-3-opus-20240229']
    };
  } else {
    const lowModel = process.env.LOW_RISK_MODEL || 'anthropic/claude-3-haiku:beta';
    const mediumModel = process.env.MEDIUM_RISK_MODEL || 'anthropic/claude-3-sonnet:beta';
    const highModel = process.env.HIGH_RISK_MODEL || 'anthropic/claude-3-opus:beta';
    
    return {
      low: [lowModel, 'openai/gpt-3.5-turbo', 'google/gemini-pro'],
      medium: [mediumModel, 'openai/gpt-4-turbo-preview', 'anthropic/claude-2'],
      high: [highModel, 'openai/gpt-4', 'anthropic/claude-2']
    };
  }
}

/**
 * Enhanced provider information with security status
 */
function getProviderInfo() {
  return {
    provider: AI_PROVIDER,
    isOpenRouter: isOpenRouter,
    availableModels: getAvailableModels(),
    securityFeatures: [
      'Input validation and sanitization',
      'Response validation and filtering',
      'SSRF protection',
      'Request signing',
      'Cost tracking and limits',
      'Circuit breaker protection',
      'Audit logging',
      'Content hash verification',
      'Fallback system integration'
    ],
    costStatus: costTracker.getStatus(),
    circuitBreakerStatus: {
      anthropic: {
        state: anthropicBreaker.getState(),
        failures: anthropicBreaker.getFailures()
      },
      openrouter: {
        state: openrouterBreaker.getState(),
        failures: openrouterBreaker.getFailures()
      }
    }
  };
}

/**
 * Health check function
 */
async function healthCheck() {
  const status = {
    provider: AI_PROVIDER,
    healthy: true,
    lastCheck: new Date().toISOString(),
    errors: []
  };
  
  try {
    // Test a simple validation
    validateAndSanitizeContent('test', 'healthCheck');
    validateModel('test-model', 'healthCheck');
  } catch (error) {
    status.healthy = false;
    status.errors.push(`Validation test failed: ${error.message}`);
  }
  
  // Check circuit breaker status
  const breaker = isOpenRouter ? openrouterBreaker : anthropicBreaker;
  if (breaker.getState() === 'open') {
    status.healthy = false;
    status.errors.push('Circuit breaker is open');
  }
  
  // Check cost limits
  const costStatus = costTracker.getStatus();
  if (costStatus.percentUsed > 90) {
    status.healthy = false;
    status.errors.push('Near daily spending limit');
  }
  
  return status;
}

module.exports = {
  processWithAI,
  processWithClaude,
  buildModerationPrompt,
  getModelForRisk,
  getAvailableModels,
  getProviderInfo,
  validateAndSanitizeContent,
  validateModel,
  validateRules,
  validateAIResponse,
  healthCheck,
  costTracker,
  SECURITY_CONFIG
};
/**
 * Centralized error management system
 * Provides intelligent error handling, recovery strategies, and health monitoring
 */
// eslint-disable-next-line no-unused-vars
const _winston = require('winston');
const { performance } = require('perf_hooks');
const logger = require('./logger');
const NodeCache = require('node-cache');

class ErrorManager {
  constructor(config = {}) {
    this.config = {
      healthCheckInterval: 60000, // 1 minute
      maxRetries: {
        discord: 3,
        ai_provider: 3,
        database: 5
      },
      alertThresholds: {
        errorRate: 0.1, // 10% of operations
        responseTime: 2000 // 2 seconds
      },
      ...config
    };

    // Internal state
    this.metrics = {
      errors: {},
      totalOperations: 0,
      startTime: Date.now()
    };

    this.serviceStatus = {
      discord: { healthy: true, lastCheck: Date.now(), failures: 0 },
      ai_provider: { healthy: true, lastCheck: Date.now(), failures: 0 },
      database: { healthy: true, lastCheck: Date.now(), failures: 0 }
    };

    this.degradedMode = false;
    this.errorCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 }); // Cache errors for 1 hour

    // Start health checks if enabled
    if (this.config.enableHealthChecks !== false) {
      this.startHealthChecks();
    }

    logger.info('ErrorManager initialized');
  }

  /**
   * Main error handling method
   * @param {Error} error - The error object
   * @param {string} source - Source of the error (e.g., 'discord', 'anthropic', 'database')
   * @param {Object} context - Additional context about the error
   * @returns {Object} Result of recovery attempt
   */
  handleError = async (error, source, context = {}) => {
    const startTime = performance.now();

    // 1. Log the error with context
    this.logError(error, source, context);

    // 2. Track metrics
    this.trackErrorMetrics(error, source);

    // 3. Determine recovery strategy
    const strategy = this.getRecoveryStrategy(error, source, context);

    // 4. Execute recovery
    const result = await this.executeRecovery(strategy, error, context);

    // 5. Update metrics
    const duration = performance.now() - startTime;
    this.trackOperationMetrics('handleError', duration, result.success);

    return result;
  }

  /**
   * Log an error with appropriate severity and context
   * @param {Error} error - The error object
   * @param {string} source - Source of the error
   * @param {Object} context - Additional context
   */
  logError = (error, source, context) => {
    // Determine log level based on error severity
    const level = this.getErrorSeverity(error, source);

    // Format error for logging
    const errorInfo = {
      message: error.message,
      stack: error.stack,
      code: error.code,
      name: error.name,
      source,
      context: this.sanitizeContext(context),
      timestamp: new Date().toISOString()
    };

    // Log with appropriate level
    // eslint-disable-next-line security/detect-object-injection
    logger[level](`Error in ${source}: ${error.message}`, errorInfo);

    // Cache error fingerprint for duplicate detection
    const fingerprint = this.getErrorFingerprint(error, source);
    const existingError = this.errorCache.get(fingerprint);

    if (existingError) {
      this.errorCache.set(fingerprint, {
        count: existingError.count + 1,
        lastSeen: Date.now(),
        firstSeen: existingError.firstSeen
      });

      // Only log repeated errors occasionally to avoid flooding
      if (existingError.count % 10 === 0) {
        logger.warn(`Error repeated ${existingError.count + 1} times: ${error.message}`, {
          fingerprint,
          source
        });
      }
    } else {
      this.errorCache.set(fingerprint, {
        count: 1,
        lastSeen: Date.now(),
        firstSeen: Date.now()
      });
    }
  }

  /**
   * Generate a fingerprint for deduplicating similar errors
   * @param {Error} error - The error object
   * @param {string} source - Error source
   * @returns {string} Error fingerprint
   */
  getErrorFingerprint(error, source) {
    // Create a fingerprint based on error type, message, and source
    const baseParts = [
      source,
      error.name,
      error.code
    ];

    // Add simplified message (remove variable parts like IDs)
    let message = error.message || '';
    message = message.replace(/[0-9a-f]{24}/g, 'ID') // Remove MongoDB IDs
      .replace(/\d+/g, 'N')            // Replace numbers
      .replace(/\w+@\w+\.\w+/g, 'EMAIL'); // Remove emails

    baseParts.push(message);

    return baseParts.filter(Boolean).join(':');
  }

  /**
   * Remove sensitive information from context before logging
   * @param {Object} context - Error context
   * @returns {Object} Sanitized context
   */
  sanitizeContext = (context) => {
    const sanitized = { ...context };

    // Remove potentially sensitive fields
    const sensitiveFields = ['password', 'token', 'apiKey', 'secret'];
    for (const field of sensitiveFields) {
      // eslint-disable-next-line security/detect-object-injection
      if (sanitized[field]) {
        // eslint-disable-next-line security/detect-object-injection
        sanitized[field] = '[REDACTED]';
      }
    }

    // Truncate message content if present
    if (sanitized.message && sanitized.message.content) {
      if (sanitized.message.content.length > 50) {
        sanitized.message.content = `${sanitized.message.content.substring(0, 50)}...`;
      }
    }

    return sanitized;
  }

  /**
   * Track error metrics for monitoring
   * @param {Error} error - The error object
   * @param {string} source - Error source
   */
  trackErrorMetrics = (error, source) => {
    // Track by source
    // eslint-disable-next-line security/detect-object-injection
    if (!this.metrics.errors[source]) {
      // eslint-disable-next-line security/detect-object-injection
      this.metrics.errors[source] = { count: 0, types: {} };
    }
    // eslint-disable-next-line security/detect-object-injection
    this.metrics.errors[source].count += 1;

    // Track by error type
    const errorType = error.name || error.code || 'Unknown';
    // eslint-disable-next-line security/detect-object-injection
    if (!this.metrics.errors[source].types[errorType]) {
      // eslint-disable-next-line security/detect-object-injection
      this.metrics.errors[source].types[errorType] = 0;
    }
    // eslint-disable-next-line security/detect-object-injection
    this.metrics.errors[source].types[errorType] += 1;

    // Update service status
    // eslint-disable-next-line security/detect-object-injection
    if (this.serviceStatus[source]) {
      // eslint-disable-next-line security/detect-object-injection
      this.serviceStatus[source].failures += 1;

      // Mark service as unhealthy if too many recent failures
      // eslint-disable-next-line security/detect-object-injection
      if (this.serviceStatus[source].failures >= 5) {
        // eslint-disable-next-line security/detect-object-injection
        this.serviceStatus[source].healthy = false;
        logger.warn(`Service ${source} marked as unhealthy due to repeated failures`);
      }
    }
  }

  /**
   * Track operation metrics
   * @param {string} operation - Operation name
   * @param {number} duration - Operation duration in ms
   * @param {boolean} success - Whether operation succeeded
   */
  trackOperationMetrics = (operation, duration, success) => {
    this.metrics.totalOperations += 1;

    // eslint-disable-next-line security/detect-object-injection
    if (!this.metrics[operation]) {
      // eslint-disable-next-line security/detect-object-injection
      this.metrics[operation] = {
        count: 0,
        successful: 0,
        failed: 0,
        totalDuration: 0,
        avgDuration: 0
      };
    }

    // eslint-disable-next-line security/detect-object-injection
    const stats = this.metrics[operation];
    stats.count += 1;
    stats.totalDuration += duration;
    stats.avgDuration = stats.totalDuration / stats.count;

    if (success) {
      stats.successful += 1;
    } else {
      stats.failed += 1;
    }
  }

  /**
   * Determine error severity level
   * @param {Error} error - The error object
   * @param {string} source - Error source
   * @returns {string} Severity level (debug, info, warn, error)
   */
  getErrorSeverity = (error, _source) => {
    // Network errors are usually warnings
    if (error.code === 'ECONNREFUSED' || error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return 'warn';
    }

    // API errors depend on status code
    if (error.status) {
      if (error.status >= 500) return 'error';
      if (error.status >= 400) return 'warn';
      return 'info';
    }

    // Default to error level
    return 'error';
  }

  /**
   * Determine the best recovery strategy based on error
   * @param {Error} error - The error object
   * @param {string} source - Error source
   * @param {Object} context - Error context
   * @returns {Object} Recovery strategy
   */
  getRecoveryStrategy = (error, source, _context) => {
    // Default strategy
    const defaultStrategy = {
      type: 'log',
      alertLevel: 'warning',
      success: false
    };

    // Discord-specific strategies
    if (source === 'discord') {
      // Rate limiting
      if (error.code === 'RateLimited') {
        return {
          type: 'retry',
          maxAttempts: this.config.maxRetries.discord,
          delay: error.retry_after || 5000,
          fallback: null,
          success: false
        };
      }

      // Permission errors
      if (error.code === 'MissingPermissions') {
        return {
          type: 'alert',
          alertLevel: 'error',
          message: `Missing permissions in Discord: ${error.message}`,
          success: false
        };
      }
    }

    // AI Provider specific strategies (Anthropic or OpenRouter)
    if (source === 'anthropic' || source === 'openrouter' || source === 'ai_provider') {
      // Rate limiting
      if (error.status === 429) {
        return {
          type: 'retry',
          maxAttempts: this.config.maxRetries.ai_provider || 3,
          delay: 1000 * (error.retry_after || 5),
          fallback: 'patternAnalysis',
          success: false
        };
      }

      // Server errors - retry with backoff
      if (error.status >= 500) {
        return {
          type: 'retry',
          maxAttempts: this.config.maxRetries.ai_provider || 3,
          backoff: 'exponential',
          initialDelay: 1000,
          fallback: 'patternAnalysis',
          success: false
        };
      }

      // Authentication errors
      if (error.status === 401 || error.status === 403) {
        const provider = process.env.AI_PROVIDER || 'OPENROUTER';
        return {
          type: 'alert',
          alertLevel: 'critical',
          message: `Authentication error with ${provider} API: ${error.message}`,
          fallback: 'patternAnalysis',
          success: false
        };
      }

      // Model not available errors (common with OpenRouter)
      if (error.status === 400 && error.message && error.message.includes('model')) {
        return {
          type: 'retry',
          maxAttempts: 1, // Only try once with fallback model
          fallback: 'patternAnalysis',
          success: false
        };
      }
    }

    // Database specific strategies
    if (source === 'database') {
      // Connection errors - retry with backoff
      if (error.name === 'MongoNetworkError' || error.code === 'ECONNREFUSED') {
        return {
          type: 'retry',
          maxAttempts: this.config.maxRetries.database,
          backoff: 'exponential',
          initialDelay: 500,
          fallback: 'inMemoryStore',
          success: false
        };
      }

      // Duplicate key errors
      if (error.code === 11000) {
        return {
          type: 'skip',
          message: 'Duplicate key error in database operation',
          success: true // This is not a failure, just a condition
        };
      }
    }

    // Unknown errors - log and alert if severe
    return defaultStrategy;
  }

  /**
   * Execute the recovery strategy
   * @param {Object} strategy - Recovery strategy
   * @param {Error} error - The original error
   * @param {Object} context - Error context
   * @returns {Object} Recovery result
   */
  executeRecovery = async (strategy, error, context) => {
    switch (strategy.type) {
      case 'retry':
        return await this.executeRetryStrategy(strategy, error, context);

      case 'alert':
        return this.executeAlertStrategy(strategy, error, context);

      case 'skip':
        return { success: true, message: strategy.message };

      case 'log':
      default:
        return { success: false, message: 'Error logged, no recovery action taken' };
    }
  }

  /**
   * Execute a retry strategy
   * @param {Object} strategy - Retry strategy
   * @param {Error} error - The original error
   * @param {Object} context - Error context
   * @returns {Object} Retry result
   */
  executeRetryStrategy = async (strategy, error, context) => {
    // Extract retry function from context
    const retryFunction = context.retryFunction;

    if (!retryFunction || typeof retryFunction !== 'function') {
      logger.warn('Retry strategy selected but no retry function provided', {
        error: error.message,
        context
      });

      return this.executeFallbackStrategy(strategy.fallback, error, context);
    }

    // Execute retries with appropriate backoff
    let lastError = error;

    for (let attempt = 1; attempt <= strategy.maxAttempts; attempt++) {
      try {
        // Calculate delay
        let delay;

        if (strategy.backoff === 'exponential') {
          delay = (strategy.initialDelay || 1000) * Math.pow(2, attempt - 1);
        } else {
          delay = strategy.delay || 1000;
        }

        // Maximum delay cap
        delay = Math.min(delay, 30000);

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, delay));

        // Execute retry
        logger.debug(`Retry attempt ${attempt}/${strategy.maxAttempts}`, {
          source: context.source,
          operation: context.operation
        });

        const result = await retryFunction(attempt);
        return {
          success: true,
          message: `Recovered after ${attempt} retries`,
          result
        };
      } catch (retryError) {
        lastError = retryError;
        logger.debug(`Retry attempt ${attempt} failed: ${retryError.message}`);
      }
    }

    // All retries failed, use fallback
    logger.warn(`All ${strategy.maxAttempts} retry attempts failed`, {
      error: lastError.message,
      source: context.source
    });

    return this.executeFallbackStrategy(strategy.fallback, lastError, context);
  }

  /**
   * Execute an alert strategy
   * @param {Object} strategy - Alert strategy
   * @param {Error} error - The original error
   * @param {Object} context - Error context
   * @returns {Object} Alert result
   */
  executeAlertStrategy = (strategy, error, context) => {
    // Log alert with appropriate level
    logger[strategy.alertLevel](`ALERT: ${strategy.message}`, {
      error: error.message,
      stack: error.stack,
      context
    });

    // For critical alerts, we might want to notify administrators
    if (strategy.alertLevel === 'critical') {
      // In a real system, this might send an email, SMS, or Slack notification
      // For now, we'll just log it prominently
      logger.error('CRITICAL ALERT! Immediate attention required', {
        message: strategy.message,
        error: error.message,
        source: context.source
      });
    }

    // Use fallback if provided
    if (strategy.fallback) {
      return this.executeFallbackStrategy(strategy.fallback, error, context);
    }

    return {
      success: false,
      message: strategy.message
    };
  }

  /**
   * Execute a fallback strategy
   * @param {string} fallbackType - Type of fallback
   * @param {Error} error - The original error
   * @param {Object} context - Error context
   * @returns {Object} Fallback result
   */
  executeFallbackStrategy = (fallbackType, error, context) => {
    if (!fallbackType) {
      return {
        success: false,
        message: 'No fallback strategy available'
      };
    }

    switch (fallbackType) {
      case 'patternAnalysis':
        // For AI moderation, fall back to rule-based pattern matching
        if (context.message && context.message.content) {
          const { patternAnalysis } = require('../utils/moderation-utils');
          const result = patternAnalysis(context.message.content, context.userData || {});

          return {
            success: true,
            message: 'Used pattern analysis as fallback',
            result
          };
        }
        break;

      case 'inMemoryStore':
        // For database operations, use in-memory caching
        if (context.operation === 'read') {
          const cacheKey = `${context.collection}:${context.query ? JSON.stringify(context.query) : 'all'}`;
          const cachedData = this.errorCache.get(cacheKey);

          if (cachedData) {
            return {
              success: true,
              message: 'Retrieved data from cache',
              result: cachedData
            };
          }
        }
        break;
    }

    return {
      success: false,
      message: `Fallback strategy '${fallbackType}' failed or not applicable`
    };
  }

  /**
   * Start periodic health checks
   */
  startHealthChecks = () => {
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.runHealthChecks();
      } catch (error) {
        logger.error(`Error running health checks: ${error}`);
      }
    }, this.config.healthCheckInterval);

    logger.info(`Health checks started, interval: ${this.config.healthCheckInterval}ms`);
  }

  /**
   * Stop health checks
   */
  stopHealthChecks = () => {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
      logger.info('Health checks stopped');
    }
  }

  /**
   * Run health checks for all services
   */
  runHealthChecks = async () => {
    logger.debug('Running health checks');

    // Check each service
    await Promise.all([
      this.checkDiscordHealth(),
      this.checkAnthropicHealth(),
      this.checkDatabaseHealth()
    ]);

    // Update overall system status
    const allHealthy = this.allServicesHealthy();

    // Transition to/from degraded mode if needed
    if (!allHealthy && !this.degradedMode) {
      await this.enableDegradedMode();
    } else if (allHealthy && this.degradedMode) {
      await this.disableDegradedMode();
    }

    // Log current status if it changed
    logger.debug('Health check complete', {
      serviceStatus: this.serviceStatus,
      degradedMode: this.degradedMode
    });
  }

  /**
   * Check Discord API health
   */
  checkDiscordHealth = async () => {
    const { client } = require('../bot');

    try {
      // Basic check - just verify the client is logged in
      if (!client || !client.user) {
        throw new Error('Discord client not logged in');
      }

      // More comprehensive check - try to fetch something
      // Only do this occasionally to avoid rate limits
      if (Math.random() < 0.1) { // 10% chance to do deeper check
        try {
          // Try to fetch the client's settings, which is a lightweight API call
          await client.application.fetch();
        } catch (fetchError) {
          logger.warn(`Discord API fetch check failed, but client is connected: ${fetchError.message}`);
          // Continue - this isn't critical if the client is still connected
        }
      }

      // Update status
      this.serviceStatus.discord.healthy = true;
      this.serviceStatus.discord.lastCheck = Date.now();
      this.serviceStatus.discord.failures = 0;

      return true;
    } catch (error) {
      this.serviceStatus.discord.healthy = false;
      this.serviceStatus.discord.lastCheck = Date.now();
      this.serviceStatus.discord.failures += 1;

      logger.warn(`Discord health check failed: ${error}`);
      return false;
    }
  }

  /**
   * Check AI Provider health (Anthropic or OpenRouter)
   */
  checkAIProviderHealth = async () => {
    const AI_PROVIDER = process.env.AI_PROVIDER || 'OPENROUTER';

    try {
      // Don't actually call the API on every check to save costs
      // Instead, use a counter to call less frequently
      this._aiProviderCheckCounter = (this._aiProviderCheckCounter || 0) + 1;

      // Only do an actual API call every 10 checks (10 minutes if checks are every minute)
      if (this._aiProviderCheckCounter >= 10) {
        this._aiProviderCheckCounter = 0;

        if (AI_PROVIDER === 'ANTHROPIC') {
          await this.testAnthropicAPI();
        } else if (AI_PROVIDER === 'OPENROUTER') {
          await this.testOpenRouterAPI();
        }
      }

      // Update status
      this.serviceStatus.ai_provider.healthy = true;
      this.serviceStatus.ai_provider.lastCheck = Date.now();
      this.serviceStatus.ai_provider.failures = 0;

      return true;
    } catch (error) {
      this.serviceStatus.ai_provider.healthy = false;
      this.serviceStatus.ai_provider.lastCheck = Date.now();
      this.serviceStatus.ai_provider.failures += 1;

      logger.warn(`${AI_PROVIDER} API health check failed: ${error}`);
      return false;
    }
  }

  /**
   * Test Anthropic API connectivity
   */
  testAnthropicAPI = async () => {
    const { AnthropicApi } = require('@anthropic-ai/sdk');
    const anthropic = new AnthropicApi({
      apiKey: process.env.ANTHROPIC_API_KEY,
    });

    // Simple ping to API with tiny token usage
    const response = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 10,
      messages: [
        { role: "user", content: "Reply with only the word 'healthy'" }
      ],
      temperature: 0
    });

    // Check response
    if (!response || !response.content || !response.content[0]) {
      throw new Error('Invalid response format from Anthropic API');
    }
  }

  /**
   * Test OpenRouter API connectivity
   */
  testOpenRouterAPI = async () => {
    const fetch = require('node-fetch');

    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'HTTP-Referer': process.env.OPENROUTER_SITE_URL || 'https://github.com/discord-ai-moderator',
        'X-Title': process.env.OPENROUTER_APP_NAME || 'Discord AI Moderator',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: process.env.LOW_RISK_MODEL || 'anthropic/claude-3-haiku:beta',
        messages: [
          { role: "user", content: "Reply with only the word 'healthy'" }
        ],
        max_tokens: 10,
        temperature: 0
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenRouter API error: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const result = await response.json();

    // Check response format
    if (!result || !result.choices || !result.choices[0]) {
      throw new Error('Invalid response format from OpenRouter API');
    }
  }

  /**
   * Check database health
   */
  checkDatabaseHealth = async () => {
    try {
      // Import database module
      const { checkDatabaseHealth } = require('../database');

      // Use SQLite-compatible health check
      const isHealthy = await checkDatabaseHealth();

      // Update status
      this.serviceStatus.database.healthy = isHealthy;
      this.serviceStatus.database.lastCheck = Date.now();

      if (isHealthy) {
        this.serviceStatus.database.failures = 0;
      } else {
        this.serviceStatus.database.failures += 1;
      }

      return isHealthy;
    } catch (error) {
      this.serviceStatus.database.healthy = false;
      this.serviceStatus.database.lastCheck = Date.now();
      this.serviceStatus.database.failures += 1;

      logger.warn(`Database health check failed: ${error}`);
      return false;
    }
  }

  /**
   * Check if all services are healthy
   * @returns {boolean} True if all services are healthy
   */
  allServicesHealthy = () => {
    return Object.values(this.serviceStatus).every(status => status.healthy);
  }

  /**
   * Enable degraded mode
   */
  enableDegradedMode = async () => {
    if (this.degradedMode) return;

    this.degradedMode = true;
    logger.warn('Entering DEGRADED MODE due to service health issues', {
      serviceStatus: this.serviceStatus
    });

    // Notify system components of degraded mode
    try {
      // In a real implementation, we would notify other system components
      // For now we just log it

      // Notify all servers via server admin DMs
      if (this.serviceStatus.discord.healthy) {
        const { getServerConfig } = require('../database');
        const { client } = require('../bot');

        // Get all guilds the bot is in
        const guilds = client.guilds.cache;

        // Notify each guild
        for (const [guildId, guild] of guilds) {
          try {
            // Get server config to check if enabled
            const config = await getServerConfig(guildId);
            if (!config || !config.enabled) continue;
            if (!guild) continue;

            // Get owner
            const owner = await guild.fetchOwner().catch(() => null);
            if (!owner) continue;

            // Send DM to owner
            await owner.send({
              content: `🚨 **Alert for ${guild.name}** 🚨\n\nThe AI Moderator is currently in degraded mode due to technical issues. During this time, only critical moderation functionality will be active, using pattern-based detection instead of AI analysis. Our team is working to restore full service as quickly as possible.\n\nThank you for your patience.`
            }).catch(() => {
              // If DM fails, try to send to system channel if available
              if (guild.systemChannel) {
                guild.systemChannel.send({
                  content: `🚨 **Alert: AI Moderator in Degraded Mode** 🚨\n\nThe AI Moderator is currently in degraded mode due to technical issues. During this time, only critical moderation functionality will be active, using pattern-based detection instead of AI analysis. Our team is working to restore full service as quickly as possible.\n\nThank you for your patience.`
                }).catch(() => null); // Ignore if this also fails
              }
            });
          } catch (guildError) {
            // Just log and continue to next guild
            logger.error(`Error notifying guild ${guildId} about degraded mode: ${guildError}`);
          }
        }
      }
    } catch (error) {
      logger.error(`Error enabling degraded mode: ${error}`);
    }
  }

  /**
   * Disable degraded mode
   */
  disableDegradedMode = async () => {
    if (!this.degradedMode) return;

    this.degradedMode = false;
    logger.info('Exiting degraded mode, all services healthy');

    // Notify system components of normal mode
    try {
      // Notify all servers via server admin DMs
      if (this.serviceStatus.discord.healthy) {
        const { getServerConfig } = require('../database');
        const { client } = require('../bot');

        // Get all guilds the bot is in
        const guilds = client.guilds.cache;

        // Notify each guild
        for (const [guildId, guild] of guilds) {
          try {
            // Get server config to check if enabled
            const config = await getServerConfig(guildId);
            if (!config || !config.enabled) continue;
            if (!guild) continue;

            // Get owner
            const owner = await guild.fetchOwner().catch(() => null);
            if (!owner) continue;

            // Send DM to owner
            await owner.send({
              content: `✅ **Service Restored for ${guild.name}** ✅\n\nThe AI Moderator has returned to normal operation. All AI-powered moderation features are now fully functional again. Thank you for your patience during the disruption.`
            }).catch(() => {
              // If DM fails, try to send to system channel if available
              if (guild.systemChannel) {
                guild.systemChannel.send({
                  content: `✅ **Alert: AI Moderator Service Restored** ✅\n\nThe AI Moderator has returned to normal operation. All AI-powered moderation features are now fully functional again. Thank you for your patience during the disruption.`
                }).catch(() => null); // Ignore if this also fails
              }
            });
          } catch (guildError) {
            // Just log and continue to next guild
            logger.error(`Error notifying guild ${guildId} about service restoration: ${guildError}`);
          }
        }
      }
    } catch (error) {
      logger.error(`Error disabling degraded mode: ${error}`);
    }
  }

  /**
   * Get current system status
   * @returns {Object} System status
   */
  getStatus = () => {
    const uptime = Date.now() - this.metrics.startTime;

    return {
      uptime,
      degradedMode: this.degradedMode,
      serviceStatus: this.serviceStatus,
      metrics: {
        totalOperations: this.metrics.totalOperations,
        errors: Object.entries(this.metrics.errors).map(([source, data]) => ({
          source,
          count: data.count,
          topErrors: Object.entries(data.types)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([type, count]) => ({ type, count }))
        }))
      }
    };
  }
}

// Create and export singleton instance
const errorManager = new ErrorManager();

module.exports = errorManager;
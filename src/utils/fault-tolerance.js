const EventEmitter = require('events');
const crypto = require('crypto');
const logger = require('./logger');
const AuditLogger = require('./auditLogger');

/**
 * Circuit Breaker implementation for fault tolerance
 */
class CircuitBreaker extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      failureThreshold: options.failureThreshold || 5,
      resetTimeout: options.resetTimeout || 60000,
      monitoringPeriod: options.monitoringPeriod || 60000,
      halfOpenRequests: options.halfOpenRequests || 3,
      name: options.name || 'unknown'
    };
    
    this.state = 'closed'; // closed, open, half-open
    this.failures = 0;
    this.successes = 0;
    this.nextAttempt = Date.now();
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      circuitOpened: 0,
      circuitClosed: 0
    };
  }
  
  async execute(operation) {
    this.stats.totalRequests++;
    
    if (this.state === 'open') {
      if (Date.now() < this.nextAttempt) {
        throw new Error(`Circuit breaker is open for ${this.config.name}`);
      }
      this.state = 'half-open';
      this.emit('halfOpen', { name: this.config.name });
    }
    
    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  onSuccess() {
    this.failures = 0;
    this.stats.successfulRequests++;
    
    if (this.state === 'half-open') {
      this.successes++;
      if (this.successes >= this.config.halfOpenRequests) {
        this.state = 'closed';
        this.successes = 0;
        this.stats.circuitClosed++;
        this.emit('closed', { name: this.config.name });
      }
    }
  }
  
  onFailure() {
    this.failures++;
    this.successes = 0;
    this.stats.failedRequests++;
    
    if (this.failures >= this.config.failureThreshold) {
      this.state = 'open';
      this.nextAttempt = Date.now() + this.config.resetTimeout;
      this.stats.circuitOpened++;
      this.emit('opened', { 
        name: this.config.name, 
        failures: this.failures,
        resetTime: this.nextAttempt
      });
    }
  }
  
  getState() {
    return this.state;
  }
  
  getFailures() {
    return this.failures;
  }
  
  getStats() {
    return {
      ...this.stats,
      state: this.state,
      failures: this.failures,
      nextAttempt: this.nextAttempt
    };
  }
  
  isOpen() {
    return this.state === 'open' && Date.now() < this.nextAttempt;
  }
  
  reset() {
    this.state = 'closed';
    this.failures = 0;
    this.successes = 0;
    this.nextAttempt = Date.now();
  }
}

/**
 * Enhanced Fault Tolerant System with multiple strategies
 */
class FaultTolerantSystem extends EventEmitter {
  constructor() {
    super();
    
    this.initialized = false;
    this.circuitBreakers = new Map();
    this.fallbackStrategies = new Map();
    this.healthChecks = new Map();
    this.retryPolicies = new Map();
    
    this.config = {
      defaultRetryAttempts: 3,
      defaultRetryDelay: 1000,
      defaultBackoffMultiplier: 2,
      maxRetryDelay: 30000,
      healthCheckInterval: 30000,
      enableFallbacks: true,
      enableCircuitBreakers: true,
      enableRetries: true
    };
    
    this.stats = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      fallbacksUsed: 0,
      retriesAttempted: 0,
      circuitBreakerTrips: 0
    };
    
    this.initializeStrategies();
  }
  
  /**
   * Initialize default fallback strategies
   */
  initializeStrategies() {
    // AI Service Fallback Chain
    this.fallbackStrategies.set('ai', [
      { 
        name: 'primary', 
        handler: this.primaryAIHandler.bind(this),
        timeout: 30000,
        priority: 1
      },
      { 
        name: 'secondary', 
        handler: this.secondaryAIHandler.bind(this),
        timeout: 45000,
        priority: 2
      },
      { 
        name: 'pattern', 
        handler: this.patternBasedHandler.bind(this),
        timeout: 5000,
        priority: 3
      },
      { 
        name: 'conservative', 
        handler: this.conservativeHandler.bind(this),
        timeout: 1000,
        priority: 4
      }
    ]);
    
    // Database Fallback Chain
    this.fallbackStrategies.set('database', [
      { 
        name: 'primary', 
        handler: this.primaryDBHandler.bind(this),
        timeout: 10000,
        priority: 1
      },
      { 
        name: 'replica', 
        handler: this.replicaDBHandler.bind(this),
        timeout: 15000,
        priority: 2
      },
      { 
        name: 'cache', 
        handler: this.cacheHandler.bind(this),
        timeout: 5000,
        priority: 3
      },
      { 
        name: 'emergency', 
        handler: this.emergencyDBHandler.bind(this),
        timeout: 2000,
        priority: 4
      }
    ]);
    
    // API Service Fallback Chain
    this.fallbackStrategies.set('api', [
      { 
        name: 'primary', 
        handler: this.primaryAPIHandler.bind(this),
        timeout: 15000,
        priority: 1
      },
      { 
        name: 'cached', 
        handler: this.cachedAPIHandler.bind(this),
        timeout: 2000,
        priority: 2
      },
      { 
        name: 'default', 
        handler: this.defaultAPIHandler.bind(this),
        timeout: 1000,
        priority: 3
      }
    ]);
    
    // Authentication Service Fallback
    this.fallbackStrategies.set('auth', [
      { 
        name: 'primary', 
        handler: this.primaryAuthHandler.bind(this),
        timeout: 10000,
        priority: 1
      },
      { 
        name: 'cached', 
        handler: this.cachedAuthHandler.bind(this),
        timeout: 5000,
        priority: 2
      },
      { 
        name: 'emergency', 
        handler: this.emergencyAuthHandler.bind(this),
        timeout: 2000,
        priority: 3
      }
    ]);
  }
  
  /**
   * Initialize the fault tolerant system
   */
  async initialize() {
    try {
      // Initialize circuit breakers for each service
      for (const [service, strategies] of this.fallbackStrategies) {
        for (const strategy of strategies) {
          const breakerName = `${service}_${strategy.name}`;
          this.circuitBreakers.set(breakerName, new CircuitBreaker({
            name: breakerName,
            failureThreshold: 5,
            resetTimeout: 60000,
            monitoringPeriod: 60000
          }));
        }
      }
      
      // Set up circuit breaker event handlers
      for (const [name, breaker] of this.circuitBreakers) {
        breaker.on('opened', async (data) => {
          await this.handleCircuitBreakerOpened(name, data);
        });
        
        breaker.on('closed', async (data) => {
          await this.handleCircuitBreakerClosed(name, data);
        });
        
        breaker.on('halfOpen', async (data) => {
          await this.handleCircuitBreakerHalfOpen(name, data);
        });
      }
      
      // Initialize health checks
      this.startHealthChecks();
      
      this.initialized = true;
      
      await AuditLogger.logSystemEvent({
        type: 'FAULT_TOLERANT_SYSTEM_INITIALIZED',
        strategies: Array.from(this.fallbackStrategies.keys()),
        circuitBreakers: Array.from(this.circuitBreakers.keys()),
        timestamp: Date.now()
      });
      
      logger.info('Fault tolerant system initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize fault tolerant system:', error);
      throw error;
    }
  }
  
  /**
   * Execute operation with fault tolerance
   */
  async executeWithFallback(operation, context, options = {}) {
    if (!this.initialized) {
      throw new Error('Fault tolerant system not initialized');
    }
    
    this.stats.totalOperations++;
    
    const strategies = this.fallbackStrategies.get(operation);
    if (!strategies) {
      throw new Error(`No fallback strategies defined for operation: ${operation}`);
    }
    
    let lastError;
    let usedFallback = false;
    let strategyUsed = null;
    
    // Sort strategies by priority
    const sortedStrategies = [...strategies].sort((a, b) => a.priority - b.priority);
    
    for (const strategy of sortedStrategies) {
      try {
        const breakerName = `${operation}_${strategy.name}`;
        const breaker = this.circuitBreakers.get(breakerName);
        
        // Check if circuit breaker is open
        if (breaker && breaker.isOpen()) {
          logger.warn(`Circuit breaker open for ${breakerName}, skipping strategy`);
          continue;
        }
        
        // Execute with timeout and retry
        const result = await this.executeWithRetryAndTimeout(
          () => strategy.handler(context, options),
          strategy,
          breaker
        );
        
        // Log successful recovery if not using primary strategy
        if (strategy.priority > 1) {
          usedFallback = true;
          await this.logRecovery(operation, strategy.name, context);
        }
        
        strategyUsed = strategy.name;
        this.stats.successfulOperations++;
        
        return {
          result,
          usedFallback,
          strategy: strategyUsed,
          provider: strategy.name
        };
        
      } catch (error) {
        lastError = error;
        await this.logFailure(operation, strategy.name, error, context);
        
        // If this was the primary strategy and it failed, mark as fallback for next iteration
        if (strategy.priority === 1) {
          usedFallback = true;
        }
        
        continue;
      }
    }
    
    // All strategies failed
    this.stats.failedOperations++;
    
    await AuditLogger.logSecurityEvent({
      type: 'ALL_FALLBACK_STRATEGIES_EXHAUSTED',
      operation,
      context: this.sanitizeContext(context),
      lastError: lastError?.message,
      timestamp: Date.now()
    });
    
    throw new Error(`All fallback strategies exhausted for ${operation}: ${lastError?.message}`);
  }
  
  /**
   * Execute with retry and timeout
   */
  async executeWithRetryAndTimeout(operation, strategy, circuitBreaker) {
    const maxAttempts = this.config.defaultRetryAttempts;
    let attempt = 0;
    let delay = this.config.defaultRetryDelay;
    
    while (attempt < maxAttempts) {
      attempt++;
      
      try {
        // Execute with circuit breaker if available
        if (circuitBreaker) {
          return await circuitBreaker.execute(async () => {
            return await this.executeWithTimeout(operation, strategy.timeout);
          });
        } else {
          return await this.executeWithTimeout(operation, strategy.timeout);
        }
        
      } catch (error) {
        this.stats.retriesAttempted++;
        
        // Don't retry on the last attempt
        if (attempt >= maxAttempts) {
          throw error;
        }
        
        // Log retry attempt
        logger.warn(`Retry ${attempt}/${maxAttempts} for ${strategy.name}:`, error.message);
        
        // Wait before retry with exponential backoff
        await this.delay(delay);
        delay = Math.min(delay * this.config.defaultBackoffMultiplier, this.config.maxRetryDelay);
      }
    }
  }
  
  /**
   * Execute operation with timeout
   */
  async executeWithTimeout(operation, timeout) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Operation timed out after ${timeout}ms`));
      }, timeout);
      
      operation()
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }
  
  /**
   * Add custom fallback strategy
   */
  addFallbackStrategy(operation, strategy) {
    if (!this.fallbackStrategies.has(operation)) {
      this.fallbackStrategies.set(operation, []);
    }
    
    const strategies = this.fallbackStrategies.get(operation);
    strategies.push(strategy);
    
    // Sort by priority
    strategies.sort((a, b) => a.priority - b.priority);
    
    // Create circuit breaker for new strategy
    const breakerName = `${operation}_${strategy.name}`;
    this.circuitBreakers.set(breakerName, new CircuitBreaker({
      name: breakerName,
      failureThreshold: 5,
      resetTimeout: 60000
    }));
  }
  
  /**
   * Start health checks for all services
   */
  startHealthChecks() {
    setInterval(async () => {
      await this.runHealthChecks();
    }, this.config.healthCheckInterval);
  }
  
  /**
   * Run health checks
   */
  async runHealthChecks() {
    const healthResults = new Map();
    
    for (const [operation, strategies] of this.fallbackStrategies) {
      for (const strategy of strategies) {
        try {
          const isHealthy = await this.checkStrategyHealth(operation, strategy);
          healthResults.set(`${operation}_${strategy.name}`, isHealthy);
          
          // Reset circuit breaker if strategy is healthy and breaker is open
          const breakerName = `${operation}_${strategy.name}`;
          const breaker = this.circuitBreakers.get(breakerName);
          if (breaker && breaker.getState() === 'open' && isHealthy) {
            breaker.reset();
            logger.info(`Reset circuit breaker for healthy service: ${breakerName}`);
          }
          
        } catch (error) {
          healthResults.set(`${operation}_${strategy.name}`, false);
          logger.warn(`Health check failed for ${operation}_${strategy.name}:`, error.message);
        }
      }
    }
    
    this.healthChecks = healthResults;
    
    // Emit health check results
    this.emit('healthCheck', {
      results: Object.fromEntries(healthResults),
      timestamp: Date.now()
    });
  }
  
  /**
   * Check strategy health
   */
  async checkStrategyHealth(operation, strategy) {
    // Default health check - override for specific strategies
    return true;
  }
  
  /**
   * Fallback Strategy Handlers
   */
  
  // AI Service Handlers
  async primaryAIHandler(context, options = {}) {
    const { processWithAI } = require('./anthropic');
    return await processWithAI(
      context.content,
      context.context,
      context.rules,
      context.model
    );
  }
  
  async secondaryAIHandler(context, options = {}) {
    // Use alternative AI provider or model
    const { processWithAI } = require('./anthropic');
    const fallbackModel = context.model.includes('opus') ? 
      context.model.replace('opus', 'sonnet') :
      context.model.replace('sonnet', 'haiku');
    
    return await processWithAI(
      context.content,
      context.context,
      context.rules,
      fallbackModel
    );
  }
  
  async patternBasedHandler(context, options = {}) {
    // Fallback to pattern-based detection
    const patterns = await this.loadPatterns();
    const result = this.analyzeWithPatterns(context.content, patterns);
    
    return {
      isViolation: result.violation,
      category: result.category,
      confidence: result.confidence * 0.7, // Lower confidence
      recommendedAction: this.getConservativeAction(result.severity),
      reasoning: 'Analyzed using pattern matching due to AI service unavailability',
      fallback: true
    };
  }
  
  async conservativeHandler(context, options = {}) {
    // Ultra-conservative mode - flag for human review
    return {
      isViolation: false,
      category: null,
      confidence: 0,
      recommendedAction: 'flag',
      reasoning: 'Flagged for manual review due to system issues',
      fallback: true,
      conservative: true
    };
  }
  
  // Database Handlers
  async primaryDBHandler(context, options = {}) {
    // Primary database connection
    const mongoose = require('mongoose');
    return await this.executeDatabaseOperation(context, mongoose.connection);
  }
  
  async replicaDBHandler(context, options = {}) {
    // Read replica connection
    const mongoose = require('mongoose');
    // This would use a read replica connection
    return await this.executeDatabaseOperation(context, mongoose.connection);
  }
  
  async cacheHandler(context, options = {}) {
    // Cache-based fallback
    return await this.executeFromCache(context);
  }
  
  async emergencyDBHandler(context, options = {}) {
    // Emergency read-only mode
    return await this.executeEmergencyOperation(context);
  }
  
  // API Handlers
  async primaryAPIHandler(context, options = {}) {
    // Primary API endpoint
    return await this.executeAPICall(context.url, context.data, context.headers);
  }
  
  async cachedAPIHandler(context, options = {}) {
    // Cached API response
    return await this.getCachedAPIResponse(context);
  }
  
  async defaultAPIHandler(context, options = {}) {
    // Default response
    return this.getDefaultAPIResponse(context);
  }
  
  // Authentication Handlers
  async primaryAuthHandler(context, options = {}) {
    // Primary authentication service
    const { SessionManager } = require('./sessionManager');
    return await SessionManager.verifyToken(context.token, context.options);
  }
  
  async cachedAuthHandler(context, options = {}) {
    // Cached authentication result
    return await this.getCachedAuthResult(context);
  }
  
  async emergencyAuthHandler(context, options = {}) {
    // Emergency authentication mode
    return await this.performEmergencyAuth(context);
  }
  
  /**
   * Helper methods
   */
  
  async loadPatterns() {
    // Load predefined patterns for content analysis
    return {
      toxicity: [/\b(hate|toxic|abuse)\b/i],
      spam: [/\b(buy now|click here|free money)\b/i],
      harassment: [/\b(kill yourself|kys|shut up)\b/i]
    };
  }
  
  analyzeWithPatterns(content, patterns) {
    let violation = false;
    let category = null;
    let severity = 'none';
    let confidence = 0;
    
    for (const [cat, patternList] of Object.entries(patterns)) {
      for (const pattern of patternList) {
        if (pattern.test(content)) {
          violation = true;
          category = cat;
          severity = 'moderate';
          confidence = 0.8;
          break;
        }
      }
      if (violation) break;
    }
    
    return { violation, category, severity, confidence };
  }
  
  getConservativeAction(severity) {
    const actions = {
      'none': 'none',
      'mild': 'flag',
      'moderate': 'warn',
      'severe': 'flag'
    };
    return actions[severity] || 'flag';
  }
  
  async executeDatabaseOperation(context, connection) {
    // Execute database operation
    throw new Error('Database operation not implemented');
  }
  
  async executeFromCache(context) {
    // Get data from cache
    return { cached: true, data: null };
  }
  
  async executeEmergencyOperation(context) {
    // Emergency database operation
    return { emergency: true, data: null };
  }
  
  async executeAPICall(url, data, headers) {
    // Execute API call
    throw new Error('API call not implemented');
  }
  
  async getCachedAPIResponse(context) {
    // Get cached API response
    return { cached: true, data: null };
  }
  
  getDefaultAPIResponse(context) {
    // Return default API response
    return { default: true, data: null };
  }
  
  async getCachedAuthResult(context) {
    // Get cached authentication result
    return { cached: true, valid: false };
  }
  
  async performEmergencyAuth(context) {
    // Emergency authentication
    return { emergency: true, valid: false };
  }
  
  /**
   * Event handlers
   */
  
  async handleCircuitBreakerOpened(name, data) {
    this.stats.circuitBreakerTrips++;
    
    await AuditLogger.logSecurityEvent({
      type: 'CIRCUIT_BREAKER_OPENED',
      breaker: name,
      failures: data.failures,
      resetTime: data.resetTime,
      timestamp: Date.now()
    });
    
    logger.warn(`Circuit breaker opened: ${name}`, data);
    
    this.emit('circuitBreakerOpened', { name, data });
  }
  
  async handleCircuitBreakerClosed(name, data) {
    await AuditLogger.logSystemEvent({
      type: 'CIRCUIT_BREAKER_CLOSED',
      breaker: name,
      timestamp: Date.now()
    });
    
    logger.info(`Circuit breaker closed: ${name}`, data);
    
    this.emit('circuitBreakerClosed', { name, data });
  }
  
  async handleCircuitBreakerHalfOpen(name, data) {
    await AuditLogger.logSystemEvent({
      type: 'CIRCUIT_BREAKER_HALF_OPEN',
      breaker: name,
      timestamp: Date.now()
    });
    
    logger.info(`Circuit breaker half-open: ${name}`, data);
    
    this.emit('circuitBreakerHalfOpen', { name, data });
  }
  
  /**
   * Logging methods
   */
  
  async logRecovery(operation, strategy, context) {
    await AuditLogger.logSystemEvent({
      type: 'FALLBACK_STRATEGY_SUCCESS',
      operation,
      strategy,
      context: this.sanitizeContext(context),
      timestamp: Date.now()
    });
    
    logger.info(`Fallback strategy succeeded: ${operation}/${strategy}`);
  }
  
  async logFailure(operation, strategy, error, context) {
    await AuditLogger.logSystemEvent({
      type: 'FALLBACK_STRATEGY_FAILED',
      operation,
      strategy,
      error: error.message,
      context: this.sanitizeContext(context),
      timestamp: Date.now()
    });
    
    logger.warn(`Fallback strategy failed: ${operation}/${strategy}`, error.message);
  }
  
  /**
   * Utility methods
   */
  
  sanitizeContext(context) {
    if (!context || typeof context !== 'object') return {};
    
    const sanitized = { ...context };
    
    // Remove sensitive data
    delete sanitized.token;
    delete sanitized.password;
    delete sanitized.secret;
    delete sanitized.key;
    
    // Truncate long content
    if (sanitized.content && sanitized.content.length > 100) {
      sanitized.content = sanitized.content.substring(0, 100) + '...';
    }
    
    return sanitized;
  }
  
  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Get system statistics
   */
  getStats() {
    const circuitBreakerStats = {};
    for (const [name, breaker] of this.circuitBreakers) {
      circuitBreakerStats[name] = breaker.getStats();
    }
    
    return {
      ...this.stats,
      isInitialized: this.initialized,
      fallbackStrategies: Array.from(this.fallbackStrategies.keys()),
      circuitBreakers: circuitBreakerStats,
      healthChecks: Object.fromEntries(this.healthChecks),
      config: this.config
    };
  }
  
  /**
   * Get health status
   */
  getHealthStatus() {
    const status = {
      healthy: true,
      services: {},
      circuitBreakers: {}
    };
    
    // Check circuit breaker states
    for (const [name, breaker] of this.circuitBreakers) {
      const state = breaker.getState();
      status.circuitBreakers[name] = {
        state,
        healthy: state !== 'open',
        failures: breaker.getFailures()
      };
      
      if (state === 'open') {
        status.healthy = false;
      }
    }
    
    // Check health check results
    for (const [service, isHealthy] of this.healthChecks) {
      status.services[service] = isHealthy;
      if (!isHealthy) {
        status.healthy = false;
      }
    }
    
    return status;
  }
  
  /**
   * Reset all circuit breakers
   */
  resetAllCircuitBreakers() {
    for (const [name, breaker] of this.circuitBreakers) {
      breaker.reset();
      logger.info(`Reset circuit breaker: ${name}`);
    }
  }
  
  /**
   * Shutdown fault tolerant system
   */
  async shutdown() {
    try {
      logger.info('Shutting down fault tolerant system...');
      
      this.initialized = false;
      
      await AuditLogger.logSystemEvent({
        type: 'FAULT_TOLERANT_SYSTEM_SHUTDOWN',
        stats: this.getStats(),
        timestamp: Date.now()
      });
      
      logger.info('Fault tolerant system shut down successfully');
      
    } catch (error) {
      logger.error('Error shutting down fault tolerant system:', error);
    }
  }
}

module.exports = { FaultTolerantSystem, CircuitBreaker };
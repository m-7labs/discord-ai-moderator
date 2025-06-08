/**
 * Advanced Rate Limiter - Multi-tier rate limiting and DDoS protection
 * Implements sophisticated rate limiting with user behavior analysis
 */

// eslint-disable-next-line no-unused-vars
const _crypto = require('crypto');
const _crypto2 = require('crypto');
const EventEmitter = require('events');
const logger = require('./logger');

/**
 * Token Bucket Algorithm Implementation
 */
class TokenBucket {
  constructor(capacity, refillRate) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
  }

  consume(tokens = 1) {
    this.refill();

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }

    return false;
  }

  refill() {
    const now = Date.now();
    const timePassed = (now - this.lastRefill) / 1000;
    const tokensToAdd = timePassed * this.refillRate;

    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  getTokens() {
    this.refill();
    return this.tokens;
  }

  getRetryAfter() {
    if (this.tokens >= 1) return 0;

    const tokensNeeded = 1 - this.tokens;
    const secondsToWait = tokensNeeded / this.refillRate;

    return Math.ceil(secondsToWait * 1000);
  }
}

/**
 * Advanced Rate Limiter
 */
class AdvancedRateLimiter extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = this.validateConfig({
      global: {
        window: options.global?.window || 60000,
        max: options.global?.max || 10000
      },

      perIP: {
        window: options.perIP?.window || 60000,
        max: options.perIP?.max || 100,
        blockDuration: options.perIP?.blockDuration || 3600000
      },

      perUser: {
        window: options.perUser?.window || 60000,
        max: options.perUser?.max || 500
      },

      perServer: {
        window: options.perServer?.window || 60000,
        max: options.perServer?.max || 1000
      },

      endpoints: options.endpoints || {
        '/api/login': { window: 300000, max: 5, blockDuration: 1800000 },
        '/api/servers/:serverId/config': { window: 60000, max: 30 },
        '/api/servers/:serverId/stats': { window: 60000, max: 60 },
        '/api/moderation/analyze': { window: 60000, max: 100 }
      },

      adaptive: {
        enabled: options.adaptive?.enabled !== false,
        newUserMultiplier: options.adaptive?.newUserMultiplier || 0.5,
        trustedUserMultiplier: options.adaptive?.trustedUserMultiplier || 2.0,
        violationMultiplier: options.adaptive?.violationMultiplier || 0.3
      },

      ddos: {
        enabled: options.ddos?.enabled !== false,
        threshold: options.ddos?.threshold || 1000,
        blockDuration: options.ddos?.blockDuration || 7200000,
        suspicionThreshold: options.ddos?.suspicionThreshold || 0.7
      },

      redis: options.redis || null,

      // Enhanced pattern detection
      patternDetection: {
        enabled: options.patternDetection?.enabled !== false,
        analysisWindow: options.patternDetection?.analysisWindow || 300000, // 5 minutes
        minimumRequests: options.patternDetection?.minimumRequests || 10
      },

      // IP Reputation System
      ipReputation: {
        enabled: options.ipReputation?.enabled !== false,
        minScore: options.ipReputation?.minScore || 0,
        maxScore: options.ipReputation?.maxScore || 100,
        defaultScore: options.ipReputation?.defaultScore || 50,
        blockThreshold: options.ipReputation?.blockThreshold || 20,
        decayRate: options.ipReputation?.decayRate || 0.05, // 5% decay per hour
        decayInterval: options.ipReputation?.decayInterval || 3600000, // 1 hour
        highReputationThreshold: options.ipReputation?.highReputationThreshold || 80
      }
    });

    this.buckets = new Map();
    this.blacklist = new Map();
    this.whitelist = new Set();
    this.suspicionScores = new Map();
    this.patterns = new Map();
    this.userTrustLevels = new Map();

    // IP Reputation tracking
    this.ipReputationScores = new Map();
    this.requestCounts = new Map();
    this.blockList = new Set();
    this.suspiciousPatterns = new Map();

    this.stats = {
      allowed: 0,
      blocked: 0,
      blacklisted: 0,
      ddosAttempts: 0,
      patternAnomalies: 0,
      reputationBlocks: 0
    };

    this.redisHealthy = false;

    this.initializeRedis();
    this.startCleanup();
    this.startPatternAnalysis();
    this.startReputationDecay();
  }

  /**
   * Validate configuration
   */
  validateConfig(config) {
    const errors = [];

    if (config.global.max <= 0) errors.push('Global max must be positive');
    if (config.perIP.max <= 0) errors.push('Per-IP max must be positive');
    if (config.ddos.threshold <= 0) errors.push('DDoS threshold must be positive');

    if (errors.length > 0) {
      throw new Error(`Invalid rate limiter configuration: ${errors.join(', ')}`);
    }

    return config;
  }

  /**
   * Initialize Redis with health monitoring
   */
  async initializeRedis() {
    if (this.config.redis) {
      try {
        this.redis = this.config.redis;

        // Test connection
        await this.redis.ping();
        this.redisHealthy = true;

        // Monitor Redis health
        this.redis.on('error', (err) => {
          logger.error('Redis error:', err);
          this.redisHealthy = false;
        });

        this.redis.on('connect', () => {
          logger.info('Redis connected');
          this.redisHealthy = true;
        });

        logger.info('Rate limiter connected to Redis');
      } catch (error) {
        logger.error('Failed to connect to Redis for rate limiting:', error);
        this.redis = null;
        this.redisHealthy = false;
      }
    }
  }

  /**
   * Express middleware factory
   */
  middleware(options = {}) {
    return async (req, res, next) => {
      try {
        const result = await this.checkLimit(req);

        if (!result.allowed) {
          // Add rate limit headers
          res.set({
            'X-RateLimit-Limit': this.getLimit(req),
            'X-RateLimit-Remaining': result.details?.[0]?.result?.remaining || 0,
            'X-RateLimit-Reset': new Date(Date.now() + (result.retryAfter || 60000)).toISOString(),
            'Retry-After': Math.ceil((result.retryAfter || 60000) / 1000)
          });

          const responseData = {
            error: 'Rate limit exceeded',
            message: result.reason || 'Too many requests',
            retryAfter: result.retryAfter
          };

          if (options.includeDetails) {
            responseData.details = result.details;
          }

          return res.status(429).json(responseData);
        }

        // Add current rate limit info to headers
        res.set({
          'X-RateLimit-Limit': this.getLimit(req),
          'X-RateLimit-Remaining': result.details?.[0]?.result?.remaining || 0
        });

        next();
      } catch (error) {
        logger.error('Rate limiter middleware error:', error);
        // Fail open on errors
        next();
      }
    };
  }

  /**
   * Get effective limit for request
   */
  getLimit(req) {
    const identifiers = this.extractIdentifiers(req);
    const endpointConfig = this.findEndpointConfig(identifiers.endpoint);

    if (endpointConfig) {
      return endpointConfig.max;
    }

    return this.config.perIP.max;
  }

  /**
   * Calculate dynamic window based on IP reputation
   */
  calculateDynamicWindow(ip, baseWindow) {
    if (!this.config.ipReputation.enabled) {
      return baseWindow;
    }

    const reputation = this.getIPReputation(ip);
    const { maxScore, highReputationThreshold } = this.config.ipReputation;

    // High reputation IPs get longer windows (more lenient)
    if (reputation >= highReputationThreshold) {
      const factor = 1 + ((reputation - highReputationThreshold) / (maxScore - highReputationThreshold));
      return Math.floor(baseWindow * factor);
    }

    // Low reputation IPs get shorter windows (more strict)
    if (reputation < this.config.ipReputation.defaultScore) {
      const factor = Math.max(0.1, reputation / this.config.ipReputation.defaultScore);
      return Math.floor(baseWindow * factor);
    }

    return baseWindow;
  }

  async checkLimit(req) {
    try {
      const identifiers = this.extractIdentifiers(req);
      const ip = identifiers.ip;

      // Check if IP is in block list from reputation system
      if (this.blockList.has(ip)) {
        this.stats.blocked++;
        this.stats.reputationBlocks++;
        return {
          allowed: false,
          reason: 'IP blocked due to low reputation score',
          retryAfter: this.config.perIP.blockDuration
        };
      }

      if (this.whitelist.has(ip)) {
        this.stats.allowed++;
        return { allowed: true, whitelisted: true };
      }

      if (await this.isBlacklisted(ip)) {
        this.stats.blocked++;
        this.stats.blacklisted++;
        return {
          allowed: false,
          reason: 'IP blacklisted',
          retryAfter: this.config.perIP.blockDuration
        };
      }

      // Track request count for this IP
      this.incrementRequestCount(ip);

      // Check for suspicious patterns
      const isSuspicious = this.checkSuspiciousPatterns(ip, req);
      if (isSuspicious) {
        this.decreaseReputation(ip, 5, 'Suspicious request pattern detected');
      }

      const checks = await this.performChecks(identifiers, req);
      const result = this.analyzeResults(checks, identifiers);

      // Enhanced pattern tracking
      await this.trackAdvancedPattern(identifiers, result);

      if (result.allowed) {
        this.stats.allowed++;
      } else {
        this.stats.blocked++;

        // Decrease reputation for rate limit violations
        this.decreaseReputation(ip, 2, 'Rate limit exceeded');

        if (this.config.ddos.enabled) {
          await this.checkForDDoS(identifiers, result);
        }
      }

      return result;

    } catch (error) {
      logger.error('Rate limit check error:', error);
      return { allowed: true, error: true };
    }
  }

  extractIdentifiers(req) {
    return {
      ip: this.getClientIP(req),
      userId: req.user?.userId || null,
      serverId: req.user?.serverId || req.params?.serverId || null,
      endpoint: this.normalizeEndpoint(req.path),
      method: req.method,
      userAgent: req.get('User-Agent') || 'unknown',
      timestamp: Date.now(),
      sessionId: req.sessionID || null
    };
  }

  getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }

    return req.headers['x-real-ip'] ||
      req.connection?.remoteAddress ||
      req.ip ||
      'unknown';
  }

  normalizeEndpoint(path) {
    return path
      .replace(/\/\d{17,19}/g, '/:id')
      .replace(/\/[a-f0-9]{24}/g, '/:id')
      .replace(/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g, '/:id');
  }

  async performChecks(identifiers, _req) {
    const checks = [];

    checks.push({
      type: 'global',
      result: await this.checkGlobalLimit()
    });

    checks.push({
      type: 'ip',
      result: await this.checkIPLimit(identifiers.ip)
    });

    if (identifiers.userId) {
      checks.push({
        type: 'user',
        result: await this.checkUserLimit(identifiers.userId)
      });
    }

    if (identifiers.serverId) {
      checks.push({
        type: 'server',
        result: await this.checkServerLimit(identifiers.serverId)
      });
    }

    checks.push({
      type: 'endpoint',
      result: await this.checkEndpointLimit(identifiers.endpoint, identifiers.userId || identifiers.ip)
    });

    return checks;
  }

  async checkGlobalLimit() {
    const key = 'global';
    const bucket = this.getOrCreateBucket(key, this.config.global.max, this.config.global.max / (this.config.global.window / 1000));

    return {
      allowed: bucket.consume(),
      remaining: bucket.getTokens(),
      retryAfter: bucket.getRetryAfter()
    };
  }

  async checkIPLimit(ip) {
    const key = `ip:${ip}`;
    const config = this.config.perIP;

    // Apply dynamic window based on reputation
    const dynamicWindow = this.calculateDynamicWindow(ip, config.window);

    const suspicionScore = await this.getSuspicionScore(ip);
    const multiplier = this.getAdaptiveMultiplier(suspicionScore);

    const adjustedMax = Math.floor(config.max * multiplier);
    const bucket = this.getOrCreateBucket(key, adjustedMax, adjustedMax / (dynamicWindow / 1000));

    const allowed = bucket.consume();

    await this.trackIPPattern(ip, allowed);

    // If not allowed, decrease reputation
    if (!allowed) {
      this.decreaseReputation(ip, 1, 'IP rate limit exceeded');
    }

    return {
      allowed,
      remaining: bucket.getTokens(),
      retryAfter: bucket.getRetryAfter(),
      suspicionScore,
      reputation: this.getIPReputation(ip)
    };
  }

  async checkUserLimit(userId) {
    const key = `user:${userId}`;
    const config = this.config.perUser;

    const trustLevel = await this.getUserTrustLevel(userId);
    const multiplier = this.getAdaptiveMultiplier(trustLevel);

    const adjustedMax = Math.floor(config.max * multiplier);
    const bucket = this.getOrCreateBucket(key, adjustedMax, adjustedMax / (config.window / 1000));

    return {
      allowed: bucket.consume(),
      remaining: bucket.getTokens(),
      retryAfter: bucket.getRetryAfter(),
      trustLevel
    };
  }

  async checkServerLimit(serverId) {
    const key = `server:${serverId}`;
    const config = this.config.perServer;

    const bucket = this.getOrCreateBucket(key, config.max, config.max / (config.window / 1000));

    return {
      allowed: bucket.consume(),
      remaining: bucket.getTokens(),
      retryAfter: bucket.getRetryAfter()
    };
  }

  async checkEndpointLimit(endpoint, identifier) {
    const endpointConfig = this.findEndpointConfig(endpoint);
    if (!endpointConfig) {
      return { allowed: true };
    }

    const key = `endpoint:${endpoint}:${identifier}`;
    const bucket = this.getOrCreateBucket(
      key,
      endpointConfig.max,
      endpointConfig.max / (endpointConfig.window / 1000)
    );

    return {
      allowed: bucket.consume(),
      remaining: bucket.getTokens(),
      retryAfter: bucket.getRetryAfter(),
      endpoint
    };
  }

  findEndpointConfig(endpoint) {
    // eslint-disable-next-line security/detect-object-injection
    if (this.config.endpoints[endpoint]) {
      // eslint-disable-next-line security/detect-object-injection
      return this.config.endpoints[endpoint];
    }

    for (const [pattern, config] of Object.entries(this.config.endpoints)) {
      // eslint-disable-next-line security/detect-non-literal-regexp
      const regex = new RegExp('^' + pattern.replace(/:\w+/g, '[^/]+') + '$');
      if (regex.test(endpoint)) {
        return config;
      }
    }

    return null;
  }

  getOrCreateBucket(key, capacity, refillRate) {
    if (!this.buckets.has(key)) {
      this.buckets.set(key, new TokenBucket(capacity, refillRate));
    }

    return this.buckets.get(key);
  }

  analyzeResults(checks, _identifiers) {
    let mostRestrictive = null;
    let reason = null;

    for (const check of checks) {
      if (!check.result.allowed) {
        if (!mostRestrictive || check.result.retryAfter > mostRestrictive.retryAfter) {
          mostRestrictive = check.result;
          reason = `${check.type} rate limit exceeded`;
        }
      }
    }

    if (mostRestrictive) {
      return {
        allowed: false,
        reason,
        retryAfter: mostRestrictive.retryAfter,
        details: checks
      };
    }

    return {
      allowed: true,
      details: checks
    };
  }

  getAdaptiveMultiplier(score) {
    if (!this.config.adaptive.enabled) {
      return 1.0;
    }

    if (score < 0.3) {
      return this.config.adaptive.trustedUserMultiplier;
    } else if (score > 0.7) {
      return this.config.adaptive.violationMultiplier;
    } else {
      return 1.0;
    }
  }

  async getSuspicionScore(ip) {
    if (this.suspicionScores.has(ip)) {
      return this.suspicionScores.get(ip);
    }

    const patterns = this.patterns.get(ip) || {};
    const score = this.calculateSuspicionScore(patterns);

    this.suspicionScores.set(ip, score);
    return score;
  }

  calculateSuspicionScore(patterns) {
    let score = 0;

    if (patterns.requestRate > 100) score += 0.3;
    if (patterns.failedAttempts > 10) score += 0.3;
    if (patterns.suspiciousPatterns > 5) score += 0.2;
    if (patterns.geoAnomalies > 0) score += 0.2;

    // Enhanced: Check for bot-like behavior
    if (patterns.uniformIntervals > 10) score += 0.2;
    if (patterns.sequentialRequests > 20) score += 0.2;
    if (patterns.distinctUserAgents > 10) score += 0.1;

    return Math.min(1.0, score);
  }

  /**
   * Get IP reputation score (0-100)
   */
  getIPReputation(ip) {
    if (!this.config.ipReputation.enabled) {
      return this.config.ipReputation.defaultScore;
    }

    if (!this.ipReputationScores.has(ip)) {
      this.ipReputationScores.set(ip, this.config.ipReputation.defaultScore);
    }

    return this.ipReputationScores.get(ip);
  }

  /**
   * Decrease IP reputation score
   */
  decreaseReputation(ip, amount, reason) {
    if (!this.config.ipReputation.enabled) return;

    const currentScore = this.getIPReputation(ip);
    const newScore = Math.max(this.config.ipReputation.minScore, currentScore - amount);

    this.ipReputationScores.set(ip, newScore);

    // Log significant reputation drops
    if (currentScore - newScore >= 5) {
      logger.warn(`IP reputation decreased significantly`, {
        ip,
        oldScore: currentScore,
        newScore,
        reason
      });
    }

    // Check if IP should be blocked
    if (newScore <= this.config.ipReputation.blockThreshold && !this.blockList.has(ip)) {
      this.blockList.add(ip);
      logger.warn(`IP blocked due to low reputation score`, {
        ip,
        score: newScore,
        threshold: this.config.ipReputation.blockThreshold,
        reason
      });
    }

    // Store in Redis if available
    if (this.redis && this.redisHealthy) {
      try {
        this.redis.setex(`ip_reputation:${ip}`, 86400, newScore.toString());
      } catch (error) {
        logger.error('Failed to store IP reputation in Redis:', error);
      }
    }
  }

  /**
   * Increase IP reputation score
   */
  increaseReputation(ip, amount) {
    if (!this.config.ipReputation.enabled) return;

    const currentScore = this.getIPReputation(ip);
    const newScore = Math.min(this.config.ipReputation.maxScore, currentScore + amount);

    this.ipReputationScores.set(ip, newScore);

    // Remove from block list if reputation is now above threshold
    if (newScore > this.config.ipReputation.blockThreshold && this.blockList.has(ip)) {
      this.blockList.delete(ip);
      logger.info(`IP unblocked due to improved reputation score`, {
        ip,
        score: newScore,
        threshold: this.config.ipReputation.blockThreshold
      });
    }

    // Store in Redis if available
    if (this.redis && this.redisHealthy) {
      try {
        this.redis.setex(`ip_reputation:${ip}`, 86400, newScore.toString());
      } catch (error) {
        logger.error('Failed to store IP reputation in Redis:', error);
      }
    }
  }

  /**
   * Start reputation decay process
   */
  startReputationDecay() {
    if (!this.config.ipReputation.enabled) return;

    this.reputationDecayInterval = setInterval(() => {
      this.decayReputationScores();
    }, this.config.ipReputation.decayInterval);

    logger.info('IP reputation decay process started', {
      interval: this.config.ipReputation.decayInterval,
      decayRate: this.config.ipReputation.decayRate
    });
  }

  /**
   * Decay all reputation scores toward default
   */
  decayReputationScores() {
    const { defaultScore, decayRate } = this.config.ipReputation;
    let updated = 0;

    for (const [ip, score] of this.ipReputationScores.entries()) {
      if (score === defaultScore) continue;

      // Decay toward default score
      let newScore;
      if (score < defaultScore) {
        newScore = Math.min(defaultScore, score + (defaultScore * decayRate));
      } else {
        newScore = Math.max(defaultScore, score - ((score - defaultScore) * decayRate));
      }

      if (newScore !== score) {
        this.ipReputationScores.set(ip, newScore);
        updated++;

        // Remove from block list if reputation is now above threshold
        if (newScore > this.config.ipReputation.blockThreshold && this.blockList.has(ip)) {
          this.blockList.delete(ip);
        }
      }
    }

    if (updated > 0) {
      logger.debug(`Decayed ${updated} IP reputation scores`);
    }
  }

  /**
   * Track request count for IP
   */
  incrementRequestCount(ip) {
    const now = Date.now();
    const minute = Math.floor(now / 60000);

    if (!this.requestCounts.has(ip)) {
      this.requestCounts.set(ip, new Map());
    }

    const counts = this.requestCounts.get(ip);
    counts.set(minute, (counts.get(minute) || 0) + 1);

    // Clean up old counts (keep last 10 minutes)
    for (const m of counts.keys()) {
      if (m < minute - 10) {
        counts.delete(m);
      }
    }
  }

  /**
   * Check for suspicious patterns in requests
   */
  checkSuspiciousPatterns(ip, req) {
    if (!this.config.ipReputation.enabled) return false;

    const counts = this.requestCounts.get(ip);
    if (!counts || counts.size < 2) return false;

    // Get current minute count
    const now = Date.now();
    const minute = Math.floor(now / 60000);
    const currentCount = counts.get(minute) || 0;

    // Check for sudden spikes (3x increase from previous minute)
    const prevCount = counts.get(minute - 1) || 0;
    if (prevCount > 5 && currentCount > prevCount * 3) {
      this.trackSuspiciousPattern(ip, 'SUDDEN_SPIKE', req);
      return true;
    }

    // Check for high frequency requests
    if (currentCount > 100) {
      this.trackSuspiciousPattern(ip, 'HIGH_FREQUENCY', req);
      return true;
    }

    return false;
  }

  /**
   * Track suspicious pattern
   */
  trackSuspiciousPattern(ip, type, req) {
    if (!this.suspiciousPatterns.has(ip)) {
      this.suspiciousPatterns.set(ip, []);
    }

    const patterns = this.suspiciousPatterns.get(ip);
    patterns.push({
      type,
      timestamp: Date.now(),
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent')
    });

    // Keep only last 20 patterns
    if (patterns.length > 20) {
      patterns.shift();
    }

    logger.warn(`Suspicious request pattern detected`, {
      ip,
      type,
      path: req.path,
      method: req.method
    });
  }

  /**
   * Enhanced pattern tracking
   */
  async trackAdvancedPattern(identifiers, result) {
    const ip = identifiers.ip;

    if (!this.patterns.has(ip)) {
      this.patterns.set(ip, {
        requestRate: 0,
        failedAttempts: 0,
        suspiciousPatterns: 0,
        geoAnomalies: 0,
        uniformIntervals: 0,
        sequentialRequests: 0,
        distinctUserAgents: new Set(),
        requestTimes: [],
        endpoints: new Set(),
        methods: new Set(),
        firstSeen: Date.now(),
        lastSeen: Date.now()
      });
    }

    const pattern = this.patterns.get(ip);
    const now = Date.now();

    pattern.lastSeen = now;
    pattern.requestRate++;
    pattern.requestTimes.push(now);
    pattern.endpoints.add(identifiers.endpoint);
    pattern.methods.add(identifiers.method);
    pattern.distinctUserAgents.add(identifiers.userAgent);

    // Keep only last 100 request times
    if (pattern.requestTimes.length > 100) {
      pattern.requestTimes = pattern.requestTimes.slice(-100);
    }

    if (!result.allowed) {
      pattern.failedAttempts++;
    }

    // Detect uniform intervals (bot behavior)
    if (pattern.requestTimes.length >= 5) {
      const intervals = [];
      for (let i = 1; i < pattern.requestTimes.length; i++) {
        // eslint-disable-next-line security/detect-object-injection
        intervals.push(pattern.requestTimes[i] - pattern.requestTimes[i - 1]);
      }

      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((acc, interval) => acc + Math.pow(interval - avgInterval, 2), 0) / intervals.length;

      // Low variance indicates uniform timing (bot-like)
      if (variance < 1000 && avgInterval < 10000) { // Less than 1 second variance, less than 10 second intervals
        pattern.uniformIntervals++;

        // Decrease reputation for bot-like behavior
        if (pattern.uniformIntervals % 5 === 0) {
          this.decreaseReputation(ip, 3, 'Bot-like request patterns detected');
        }
      }
    }

    // Detect sequential request patterns
    if (pattern.endpoints.size === 1 && pattern.requestRate > 10) {
      pattern.sequentialRequests++;
    }
  }

  async trackIPPattern(ip, allowed) {
    // This is maintained for backward compatibility
    await this.trackAdvancedPattern({ ip }, { allowed });
  }

  /**
   * Enhanced user trust level calculation
   */
  async getUserTrustLevel(userId) {
    if (this.userTrustLevels.has(userId)) {
      return this.userTrustLevels.get(userId);
    }

    // Default trust level - can be enhanced with database lookup
    let trustLevel = 0.5;

    // Check Redis for stored trust level
    if (this.redis && this.redisHealthy) {
      try {
        const stored = await this.redis.get(`trust:${userId}`);
        if (stored) {
          trustLevel = parseFloat(stored);
        }
      } catch (error) {
        logger.error('Failed to get trust level from Redis:', error);
      }
    }

    this.userTrustLevels.set(userId, trustLevel);
    return trustLevel;
  }

  /**
   * Update user trust level
   */
  async updateUserTrustLevel(userId, level) {
    const clampedLevel = Math.max(0, Math.min(1, level));
    this.userTrustLevels.set(userId, clampedLevel);

    if (this.redis && this.redisHealthy) {
      try {
        await this.redis.setex(`trust:${userId}`, 86400 * 7, clampedLevel.toString()); // 7 days
      } catch (error) {
        logger.error('Failed to store trust level in Redis:', error);
      }
    }
  }

  /**
   * Start pattern analysis
   */
  startPatternAnalysis() {
    if (!this.config.patternDetection.enabled) return;

    this.patternInterval = setInterval(() => {
      this.analyzePatterns();
    }, this.config.patternDetection.analysisWindow);
  }

  /**
   * Analyze patterns for anomalies
   */
  async analyzePatterns() {
    const now = Date.now();
    const _analysisWindow = this.config.patternDetection.analysisWindow;

    for (const [ip, pattern] of this.patterns.entries()) {
      if (pattern.requestRate < this.config.patternDetection.minimumRequests) {
        continue;
      }

      // Check for anomalies
      const anomalies = this.detectAnomalies(pattern);

      if (anomalies.length > 0) {
        this.stats.patternAnomalies++;

        this.emit('patternAnomaly', {
          ip,
          anomalies,
          pattern: this.sanitizePattern(pattern),
          timestamp: now
        });

        // Auto-adjust suspicion score
        const currentScore = await this.getSuspicionScore(ip);
        const newScore = Math.min(1.0, currentScore + anomalies.length * 0.1);
        this.suspicionScores.set(ip, newScore);

        // Decrease reputation based on anomalies
        this.decreaseReputation(ip, anomalies.length, `Pattern anomalies detected: ${anomalies.join(', ')}`);
      }
    }
  }

  /**
   * Detect pattern anomalies
   */
  detectAnomalies(pattern) {
    const anomalies = [];

    // High request rate
    if (pattern.requestRate > this.config.ddos.threshold * 0.5) {
      anomalies.push('HIGH_REQUEST_RATE');
    }

    // Uniform timing (bot behavior)
    if (pattern.uniformIntervals > 10) {
      anomalies.push('UNIFORM_TIMING');
    }

    // Too many user agents from same IP
    if (pattern.distinctUserAgents.size > 20) {
      anomalies.push('MULTIPLE_USER_AGENTS');
    }

    // High failure rate
    const failureRate = pattern.failedAttempts / pattern.requestRate;
    if (failureRate > 0.5) {
      anomalies.push('HIGH_FAILURE_RATE');
    }

    // Scanning behavior (many endpoints)
    if (pattern.endpoints.size > 50) {
      anomalies.push('ENDPOINT_SCANNING');
    }

    return anomalies;
  }

  /**
   * Sanitize pattern for logging
   */
  sanitizePattern(pattern) {
    return {
      requestRate: pattern.requestRate,
      failedAttempts: pattern.failedAttempts,
      suspiciousPatterns: pattern.suspiciousPatterns,
      uniformIntervals: pattern.uniformIntervals,
      sequentialRequests: pattern.sequentialRequests,
      distinctUserAgents: pattern.distinctUserAgents.size,
      endpoints: pattern.endpoints.size,
      methods: Array.from(pattern.methods),
      duration: pattern.lastSeen - pattern.firstSeen
    };
  }

  async checkForDDoS(identifiers, _result) {
    const ip = identifiers.ip;
    const pattern = this.patterns.get(ip) || {};

    if (pattern.requestRate > this.config.ddos.threshold) {
      logger.warn('Potential DDoS detected from IP:', ip);

      const threatLevel = this.calculateThreatLevel(pattern);

      if (threatLevel > this.config.ddos.suspicionThreshold) {
        await this.handleDDoSAttempt(ip, threatLevel);
        this.stats.ddosAttempts++;

        // Severely decrease reputation for DDoS attempts
        this.decreaseReputation(ip, 50, 'DDoS attempt detected');
      }
    }
  }

  calculateThreatLevel(pattern) {
    const factors = {
      requestRate: Math.min(1, pattern.requestRate / this.config.ddos.threshold),
      failureRate: pattern.failedAttempts / (pattern.requestRate || 1),
      duration: Math.min(1, (Date.now() - pattern.firstSeen) / 3600000),
      patterns: Math.min(1, pattern.suspiciousPatterns / 10),
      uniformity: Math.min(1, pattern.uniformIntervals / 20)
    };

    return (
      factors.requestRate * 0.3 +
      factors.failureRate * 0.2 +
      factors.duration * 0.1 +
      factors.patterns * 0.2 +
      factors.uniformity * 0.2
    );
  }

  async handleDDoSAttempt(ip, threatLevel) {
    logger.error('DDoS attempt detected', {
      ip,
      threatLevel,
      pattern: this.sanitizePattern(this.patterns.get(ip))
    });

    await this.blacklistIP(ip, 'DDoS attempt', this.config.ddos.blockDuration);

    this.emit('ddosDetected', {
      ip,
      threatLevel,
      timestamp: Date.now()
    });

    this.patterns.delete(ip);
    this.suspicionScores.delete(ip);
  }

  async blacklistIP(ip, reason, duration = null) {
    const expiry = duration ? Date.now() + duration : null;

    this.blacklist.set(ip, {
      reason,
      timestamp: Date.now(),
      expiry
    });

    if (this.redis && this.redisHealthy) {
      try {
        const key = `blacklist:${ip}`;
        const value = JSON.stringify({ reason, timestamp: Date.now(), expiry });

        if (duration) {
          await this.redis.setex(key, Math.ceil(duration / 1000), value);
        } else {
          await this.redis.set(key, value);
        }
      } catch (error) {
        logger.error('Failed to store blacklist in Redis:', error);
      }
    }

    logger.info('IP blacklisted', { ip, reason, duration });
  }

  async isBlacklisted(ip) {
    const entry = this.blacklist.get(ip);
    if (entry) {
      if (!entry.expiry || entry.expiry > Date.now()) {
        return true;
      } else {
        this.blacklist.delete(ip);
      }
    }

    if (this.redis && this.redisHealthy) {
      try {
        const key = `blacklist:${ip}`;
        const value = await this.redis.get(key);

        if (value) {
          const entry = JSON.parse(value);
          this.blacklist.set(ip, entry);
          return true;
        }
      } catch (error) {
        logger.error('Failed to check blacklist in Redis:', error);
      }
    }

    return false;
  }

  whitelistIP(ip) {
    this.whitelist.add(ip);

    // Reset reputation to default and remove from block list
    if (this.config.ipReputation.enabled) {
      this.ipReputationScores.set(ip, this.config.ipReputation.defaultScore);
      this.blockList.delete(ip);
    }

    logger.info('IP whitelisted', { ip });
  }

  removeFromWhitelist(ip) {
    this.whitelist.delete(ip);
    logger.info('IP removed from whitelist', { ip });
  }

  async removeFromBlacklist(ip) {
    this.blacklist.delete(ip);

    // Also remove from reputation block list
    if (this.config.ipReputation.enabled) {
      this.blockList.delete(ip);
      // Reset reputation to minimum acceptable level
      this.ipReputationScores.set(ip, this.config.ipReputation.blockThreshold + 5);
    }

    if (this.redis && this.redisHealthy) {
      try {
        await this.redis.del(`blacklist:${ip}`);
      } catch (error) {
        logger.error('Failed to remove from Redis blacklist:', error);
      }
    }

    logger.info('IP removed from blacklist', { ip });
  }

  startCleanup() {
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 300000);
  }

  cleanup() {
    const now = Date.now();
    let cleaned = 0;
    const memoryUsage = process.memoryUsage();
    const memoryPressure = memoryUsage.heapUsed / memoryUsage.heapTotal;

    // More aggressive cleanup under memory pressure
    const patternExpiryTime = memoryPressure > 0.8 ? 1800000 : 3600000; // 30 min vs 1 hour
    const bucketExpiryTime = memoryPressure > 0.8 ? 300000 : 600000; // 5 min vs 10 min

    // Clean up blacklist
    for (const [ip, entry] of this.blacklist.entries()) {
      if (entry.expiry && entry.expiry < now) {
        this.blacklist.delete(ip);
        cleaned++;
      }
    }

    // Clean up reputation block list
    if (this.config.ipReputation.enabled) {
      for (const ip of this.blockList) {
        const score = this.ipReputationScores.get(ip);
        if (score > this.config.ipReputation.blockThreshold) {
          this.blockList.delete(ip);
          cleaned++;
        }
      }

      // Clean up old reputation scores
      for (const [ip, _score] of this.ipReputationScores.entries()) {
        if (!this.patterns.has(ip) || this.patterns.get(ip).lastSeen < now - 86400000) {
          this.ipReputationScores.delete(ip);
          cleaned++;
        }
      }

      // Clean up request counts
      for (const [ip, counts] of this.requestCounts.entries()) {
        if (counts.size === 0 || !this.patterns.has(ip)) {
          this.requestCounts.delete(ip);
          cleaned++;
        }
      }
    }

    // Clean up old patterns
    const patternExpiry = now - patternExpiryTime;
    for (const [ip, pattern] of this.patterns.entries()) {
      if (pattern.lastSeen < patternExpiry ||
        (memoryPressure > 0.9 && pattern.requestRate < 10)) {
        this.patterns.delete(ip);
        this.suspicionScores.delete(ip);
        cleaned++;
      }
    }

    // Clean up old buckets
    const bucketExpiry = now - bucketExpiryTime;
    for (const [key, bucket] of this.buckets.entries()) {
      if (bucket.lastRefill < bucketExpiry) {
        this.buckets.delete(key);
        cleaned++;
      }
    }

    // Clean up trust levels
    const trustExpiry = now - 86400000 * 7; // 7 days
    for (const [userId, timestamp] of this.userTrustLevels.entries()) {
      if (timestamp < trustExpiry) {
        this.userTrustLevels.delete(userId);
        cleaned++;
      }
    }

    // Enforce maximum map sizes under memory pressure
    if (memoryPressure > 0.8) {
      this.enforceMaxMapSizes();
    }

    if (cleaned > 0) {
      logger.debug(`Rate limiter cleanup: removed ${cleaned} expired entries (memory pressure: ${(memoryPressure * 100).toFixed(1)}%)`);
    }

    // Emit memory stats for monitoring
    this.emit('memoryStats', {
      heapUsed: memoryUsage.heapUsed,
      heapTotal: memoryUsage.heapTotal,
      pressure: memoryPressure,
      maps: {
        buckets: this.buckets.size,
        patterns: this.patterns.size,
        blacklist: this.blacklist.size,
        whitelist: this.whitelist.size,
        suspicionScores: this.suspicionScores.size,
        userTrustLevels: this.userTrustLevels.size,
        ipReputationScores: this.ipReputationScores.size,
        blockList: this.blockList.size
      }
    });
  }

  /**
   * Enforce maximum map sizes to prevent unbounded growth
   */
  enforceMaxMapSizes() {
    const maxBuckets = 10000;
    const maxPatterns = 5000;
    const maxScores = 5000;

    // Remove oldest buckets if over limit
    if (this.buckets.size > maxBuckets) {
      const sorted = Array.from(this.buckets.entries())
        .sort((a, b) => a[1].lastRefill - b[1].lastRefill);
      const toRemove = sorted.slice(0, this.buckets.size - maxBuckets);
      for (const [key] of toRemove) {
        this.buckets.delete(key);
      }
    }

    // Remove least active patterns if over limit
    if (this.patterns.size > maxPatterns) {
      const sorted = Array.from(this.patterns.entries())
        .sort((a, b) => a[1].requestRate - b[1].requestRate);
      const toRemove = sorted.slice(0, this.patterns.size - maxPatterns);
      for (const [key] of toRemove) {
        this.patterns.delete(key);
        this.suspicionScores.delete(key);
      }
    }

    // Remove oldest reputation scores if over limit
    if (this.ipReputationScores.size > maxScores) {
      const ips = Array.from(this.ipReputationScores.keys());
      const toRemove = ips.slice(0, this.ipReputationScores.size - maxScores);
      for (const ip of toRemove) {
        if (!this.blockList.has(ip)) {
          this.ipReputationScores.delete(ip);
        }
      }
    }
  }

  getStats() {
    return {
      ...this.stats,
      blacklisted: this.blacklist.size,
      whitelisted: this.whitelist.size,
      patterns: this.patterns.size,
      buckets: this.buckets.size,
      trustLevels: this.userTrustLevels.size,
      reputationTracked: this.ipReputationScores.size,
      reputationBlocked: this.blockList.size,
      redisHealthy: this.redisHealthy
    };
  }

  reset() {
    this.buckets.clear();
    this.blacklist.clear();
    this.patterns.clear();
    this.suspicionScores.clear();
    this.userTrustLevels.clear();

    // Reset reputation tracking
    if (this.config.ipReputation.enabled) {
      this.ipReputationScores.clear();
      this.requestCounts.clear();
      this.blockList.clear();
      this.suspiciousPatterns.clear();
    }

    this.stats = {
      allowed: 0,
      blocked: 0,
      blacklisted: 0,
      ddosAttempts: 0,
      patternAnomalies: 0,
      reputationBlocks: 0
    };

    logger.info('Rate limiter reset');
  }

  generateReport() {
    const report = {
      timestamp: Date.now(),
      stats: this.getStats(),
      topOffenders: [],
      blacklist: Array.from(this.blacklist.entries()).map(([ip, entry]) => ({
        ip,
        ...entry
      })),
      suspiciousIPs: [],
      patternAnomalies: [],
      reputationBlocked: Array.from(this.blockList).map(ip => ({
        ip,
        score: this.ipReputationScores.get(ip) || 0
      }))
    };

    // Top offenders
    const offenders = Array.from(this.patterns.entries())
      .sort((a, b) => b[1].failedAttempts - a[1].failedAttempts)
      .slice(0, 10);

    report.topOffenders = offenders.map(([ip, pattern]) => ({
      ip,
      ...this.sanitizePattern(pattern),
      suspicionScore: this.suspicionScores.get(ip) || 0,
      reputationScore: this.ipReputationScores.get(ip) || this.config.ipReputation.defaultScore
    }));

    // Suspicious IPs
    const suspicious = Array.from(this.suspicionScores.entries())
      .filter(([_ip, score]) => score > 0.5)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    report.suspiciousIPs = suspicious.map(([ip, score]) => ({
      ip,
      score,
      pattern: this.sanitizePattern(this.patterns.get(ip) || {}),
      reputationScore: this.ipReputationScores.get(ip) || this.config.ipReputation.defaultScore
    }));

    return report;
  }

  shutdown() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    if (this.patternInterval) {
      clearInterval(this.patternInterval);
    }

    if (this.reputationDecayInterval) {
      clearInterval(this.reputationDecayInterval);
    }

    logger.info('Rate limiter shutdown');
  }
}

// Usage example
const rateLimiter = new AdvancedRateLimiter({
  redis: require('redis').createClient(),
  endpoints: {
    '/api/login': { window: 300000, max: 5 },
    '/api/register': { window: 600000, max: 3 },
    '/api/moderation/analyze': { window: 60000, max: 100 }
  },
  ddos: {
    enabled: true,
    threshold: 1000,
    suspicionThreshold: 0.7
  }
});

// Event handlers
rateLimiter.on('ddosDetected', (data) => {
  // eslint-disable-next-line no-console
  console.log('DDoS detected:', data);
  // Notify security team, enable additional protections, etc.
});

rateLimiter.on('patternAnomaly', (data) => {
  // eslint-disable-next-line no-console
  console.log('Pattern anomaly detected:', data);
  // Log for analysis, adjust security measures, etc.
});

module.exports = rateLimiter;
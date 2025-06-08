const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Redis = require('ioredis');
const logger = require('./logger');
const AuditLogger = require('./audit-logger');

/**
 * Enhanced Session Manager with Redis backend and security features
 */
class SessionManager {
  constructor() {
    this.initialized = false;
    this.redis = null;
    this.config = {
      sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
      refreshThreshold: 60 * 60 * 1000, // 1 hour
      cleanupInterval: 60 * 60 * 1000, // 1 hour
      maxSessions: 5, // Max concurrent sessions per user
      enableEncryption: true,
      enableRotation: true,
      secureMode: process.env.NODE_ENV === 'production'
    };
    this.encryptionKey = null;
    this.stats = {
      created: 0,
      verified: 0,
      refreshed: 0,
      revoked: 0,
      expired: 0,
      errors: 0
    };
    this.cleanupTimer = null;
  }

  /**
   * Initialize session manager
   */
  async initialize(options = {}) {
    try {
      this.config = { ...this.config, ...options };

      // Initialize encryption key
      this.encryptionKey = process.env.SESSION_ENCRYPTION_KEY ||
        process.env.ENCRYPTION_KEY ||
        crypto.randomBytes(32);

      if (typeof this.encryptionKey === 'string') {
        this.encryptionKey = Buffer.from(this.encryptionKey, 'hex');
      }

      if (this.encryptionKey.length !== 32) {
        this.encryptionKey = crypto.scryptSync(this.encryptionKey.toString(), 'salt', 32);
      }

      // Initialize Redis connection
      if (options.redisUrl || process.env.REDIS_URL) {
        await this.initializeRedis(options.redisUrl || process.env.REDIS_URL);
      } else {
        logger.warn('No Redis URL provided, using in-memory session storage (not recommended for production)');
        this.sessions = new Map();
        this.blacklist = new Map();
      }

      // Start cleanup timer
      this.startCleanup();

      this.initialized = true;

      await AuditLogger.logSystemEvent({
        type: 'SESSION_MANAGER_INITIALIZED',
        config: {
          redisEnabled: !!this.redis,
          encryptionEnabled: this.config.enableEncryption,
          sessionTimeout: this.config.sessionTimeout,
          maxSessions: this.config.maxSessions
        },
        timestamp: Date.now()
      });

      logger.info('Session manager initialized successfully');

    } catch (error) {
      logger.error('Failed to initialize session manager:', error);
      throw error;
    }
  }

  /**
   * Initialize Redis connection
   */
  async initializeRedis(redisUrl) {
    try {
      const redisOptions = {
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        maxMemoryPolicy: 'allkeys-lru',
        connectTimeout: 5000,
        commandTimeout: 5000,
        lazyConnect: true
      };

      // Parse Redis URL for connection options
      if (redisUrl.includes('rediss://')) {
        redisOptions.tls = {};
      }

      this.redis = new Redis(redisUrl, redisOptions);

      // Set up event handlers
      this.redis.on('connect', () => {
        logger.info('Connected to Redis for session management');
      });

      this.redis.on('error', (error) => {
        logger.error('Redis session error:', error);
        this.stats.errors++;
      });

      this.redis.on('close', () => {
        logger.warn('Redis session connection closed');
      });

      this.redis.on('reconnecting', () => {
        logger.info('Reconnecting to Redis...');
      });

      // Test connection
      await this.redis.ping();

      // Configure Redis for sessions
      await this.redis.config('SET', 'maxmemory-policy', 'allkeys-lru');

      logger.info('Redis session storage initialized successfully');

    } catch (error) {
      logger.error('Failed to initialize Redis:', error);
      throw error;
    }
  }

  /**
   * Create a new session
   */
  async createSession(userId, serverId, permissions = [], options = {}) {
    try {
      if (!this.initialized) {
        throw new Error('Session manager not initialized');
      }

      // Generate session ID and JWT ID
      const sessionId = crypto.randomBytes(32).toString('hex');
      const jti = crypto.randomBytes(16).toString('hex');
      const deviceId = options.deviceId || crypto.randomBytes(16).toString('hex');

      // Check session limits
      await this.enforceSessionLimits(userId);

      const now = Date.now();
      const expiry = now + this.config.sessionTimeout;

      // Create JWT payload
      const payload = {
        userId,
        serverId,
        permissions,
        sessionId,
        jti,
        deviceId,
        iat: Math.floor(now / 1000),
        exp: Math.floor(expiry / 1000),
        nbf: Math.floor(now / 1000) // Not before
      };

      // Add additional claims
      if (options.userAgent) {
        payload.userAgent = this.hashUserAgent(options.userAgent);
      }

      if (options.ipAddress) {
        payload.ipHash = this.hashIP(options.ipAddress);
      }

      // Create JWT token
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        issuer: 'discord-ai-moderator',
        audience: serverId,
        jwtid: jti
      });

      // Create session data
      const sessionData = {
        userId,
        serverId,
        permissions,
        deviceId,
        createdAt: now,
        lastActivity: now,
        expiresAt: expiry,
        ipHash: payload.ipHash,
        userAgentHash: payload.userAgent,
        refreshCount: 0,
        isActive: true
      };

      // Encrypt session data if enabled
      if (this.config.enableEncryption) {
        sessionData.encrypted = true;
        sessionData.data = this.encryptData(sessionData);
        // Remove sensitive data from main object
        delete sessionData.permissions;
      }

      // Store session
      await this.storeSession(sessionId, sessionData);

      // Store user session mapping
      await this.addUserSession(userId, sessionId);

      this.stats.created++;

      // Log session creation
      await AuditLogger.log({
        action: 'SESSION_CREATED',
        userId,
        serverId,
        sessionId,
        deviceId,
        timestamp: now,
        ip: options.ipAddress,
        userAgent: options.userAgent
      });

      return { token, sessionId, expiresAt: expiry };

    } catch (error) {
      this.stats.errors++;
      logger.error('Failed to create session:', error);
      throw error;
    }
  }

  /**
   * Verify and decode a JWT token
   */
  async verifyToken(token, options = {}) {
    try {
      if (!this.initialized) {
        throw new Error('Session manager not initialized');
      }

      // Basic token validation
      if (!token || typeof token !== 'string') {
        throw new Error('Invalid token format');
      }

      // Check token blacklist first
      if (await this.isTokenBlacklisted(token)) {
        throw new Error('Token has been revoked');
      }

      // Verify JWT
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256'],
        issuer: 'discord-ai-moderator',
        clockTolerance: 30 // 30 seconds clock tolerance
      });

      // Validate required fields
      if (!decoded.sessionId || !decoded.userId || !decoded.serverId) {
        throw new Error('Invalid token payload');
      }

      // Get session data
      const sessionData = await this.getSession(decoded.sessionId);
      if (!sessionData) {
        throw new Error('Session not found');
      }

      // Check if session is active
      if (!sessionData.isActive) {
        throw new Error('Session is inactive');
      }

      // Check expiry
      if (Date.now() > sessionData.expiresAt) {
        await this.revokeSession(decoded.sessionId, 'expired');
        throw new Error('Session expired');
      }

      // Decrypt session data if needed
      let permissions = decoded.permissions || [];
      if (sessionData.encrypted && sessionData.data) {
        const decryptedData = this.decryptData(sessionData.data);
        permissions = decryptedData.permissions || [];
      }

      // Enhanced security checks
      if (options.ipAddress) {
        const currentIpHash = this.hashIP(options.ipAddress);
        if (sessionData.ipHash && sessionData.ipHash !== currentIpHash) {
          await AuditLogger.logSecurityEvent({
            type: 'SESSION_IP_MISMATCH',
            userId: decoded.userId,
            sessionId: decoded.sessionId,
            expectedIpHash: sessionData.ipHash,
            actualIpHash: currentIpHash,
            timestamp: Date.now()
          });

          if (this.config.secureMode) {
            throw new Error('IP address mismatch');
          }
        }
      }

      if (options.userAgent) {
        const currentUAHash = this.hashUserAgent(options.userAgent);
        if (sessionData.userAgentHash && sessionData.userAgentHash !== currentUAHash) {
          await AuditLogger.logSecurityEvent({
            type: 'SESSION_USER_AGENT_MISMATCH',
            userId: decoded.userId,
            sessionId: decoded.sessionId,
            timestamp: Date.now()
          });

          // User agent mismatch is less critical, just log
        }
      }

      // Update last activity
      await this.updateSessionActivity(decoded.sessionId);

      this.stats.verified++;

      return {
        ...decoded,
        permissions,
        sessionData: {
          createdAt: sessionData.createdAt,
          lastActivity: sessionData.lastActivity,
          refreshCount: sessionData.refreshCount
        }
      };

    } catch (error) {
      this.stats.errors++;

      // Log failed verification attempts
      if (error.name !== 'TokenExpiredError') {
        await AuditLogger.logSecurityEvent({
          type: 'TOKEN_VERIFICATION_FAILED',
          error: error.message,
          timestamp: Date.now(),
          options: {
            ip: options.ipAddress,
            userAgent: options.userAgent
          }
        });
      }

      throw error;
    }
  }

  /**
   * Refresh a token if needed
   */
  async refreshIfNeeded(token) {
    try {
      if (!this.config.enableRotation) return null;

      const decoded = jwt.decode(token);
      if (!decoded || !decoded.exp || !decoded.sessionId) return null;

      const now = Date.now();
      const expiry = decoded.exp * 1000;
      const timeUntilExpiry = expiry - now;

      // Check if refresh is needed
      if (timeUntilExpiry > this.config.refreshThreshold) {
        return null;
      }

      // Get session data
      const sessionData = await this.getSession(decoded.sessionId);
      if (!sessionData || !sessionData.isActive) {
        return null;
      }

      // Create new token with extended expiry
      const newExpiry = now + this.config.sessionTimeout;
      const newPayload = {
        ...decoded,
        iat: Math.floor(now / 1000),
        exp: Math.floor(newExpiry / 1000),
        jti: crypto.randomBytes(16).toString('hex') // New JWT ID
      };

      const newToken = jwt.sign(newPayload, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        issuer: 'discord-ai-moderator',
        audience: decoded.serverId
      });

      // Update session data
      sessionData.expiresAt = newExpiry;
      sessionData.lastActivity = now;
      sessionData.refreshCount = (sessionData.refreshCount || 0) + 1;

      await this.storeSession(decoded.sessionId, sessionData);

      // Blacklist old token
      await this.blacklistToken(token, 'refreshed');

      this.stats.refreshed++;

      await AuditLogger.log({
        action: 'SESSION_REFRESHED',
        userId: decoded.userId,
        sessionId: decoded.sessionId,
        refreshCount: sessionData.refreshCount,
        timestamp: now
      });

      return newToken;

    } catch (error) {
      logger.error('Failed to refresh token:', error);
      return null;
    }
  }

  /**
   * Revoke a session
   */
  async revokeSession(sessionId, reason = 'manual') {
    try {
      const sessionData = await this.getSession(sessionId);
      if (!sessionData) return false;

      // Mark session as inactive
      sessionData.isActive = false;
      sessionData.revokedAt = Date.now();
      sessionData.revokeReason = reason;

      await this.storeSession(sessionId, sessionData);

      // Remove from user sessions
      await this.removeUserSession(sessionData.userId, sessionId);

      this.stats.revoked++;

      await AuditLogger.log({
        action: 'SESSION_REVOKED',
        userId: sessionData.userId,
        sessionId,
        reason,
        timestamp: Date.now()
      });

      return true;

    } catch (error) {
      logger.error('Failed to revoke session:', error);
      return false;
    }
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeUserSessions(userId, reason = 'security') {
    try {
      const sessionIds = await this.getUserSessions(userId);
      let revokedCount = 0;

      for (const sessionId of sessionIds) {
        if (await this.revokeSession(sessionId, reason)) {
          revokedCount++;
        }
      }

      await AuditLogger.log({
        action: 'USER_SESSIONS_REVOKED',
        userId,
        revokedCount,
        reason,
        timestamp: Date.now()
      });

      return revokedCount;

    } catch (error) {
      logger.error('Failed to revoke user sessions:', error);
      return 0;
    }
  }

  /**
   * Revoke all sessions (emergency use)
   */
  async revokeAllSessions(reason = 'emergency') {
    try {
      let revokedCount = 0;

      if (this.redis) {
        // Get all session keys
        const sessionKeys = await this.redis.keys('session:*');

        for (const key of sessionKeys) {
          const sessionId = key.replace('session:', '');
          if (await this.revokeSession(sessionId, reason)) {
            revokedCount++;
          }
        }
      } else {
        // In-memory fallback
        for (const [sessionId] of this.sessions) {
          if (await this.revokeSession(sessionId, reason)) {
            revokedCount++;
          }
        }
      }

      await AuditLogger.logSecurityEvent({
        type: 'ALL_SESSIONS_REVOKED',
        revokedCount,
        reason,
        timestamp: Date.now()
      });

      return revokedCount;

    } catch (error) {
      logger.error('Failed to revoke all sessions:', error);
      return 0;
    }
  }

  /**
   * Blacklist a token
   */
  async blacklistToken(token, reason = 'revoked') {
    try {
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      const expiry = this.getTokenExpiry(token);
      const ttl = expiry ? Math.max(0, Math.floor((expiry - Date.now()) / 1000)) : 86400;

      if (this.redis) {
        await this.redis.setex(`blacklist:${hash}`, ttl, JSON.stringify({
          reason,
          timestamp: Date.now()
        }));
      } else {
        this.blacklist.set(hash, {
          reason,
          timestamp: Date.now(),
          expiry: Date.now() + ttl * 1000
        });
      }

    } catch (error) {
      logger.error('Failed to blacklist token:', error);
    }
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(token) {
    try {
      const hash = crypto.createHash('sha256').update(token).digest('hex');

      if (this.redis) {
        const result = await this.redis.get(`blacklist:${hash}`);
        return !!result;
      } else {
        const entry = this.blacklist.get(hash);
        if (entry && entry.expiry > Date.now()) {
          return true;
        } else if (entry) {
          this.blacklist.delete(hash);
        }
        return false;
      }
    } catch (error) {
      logger.error('Failed to check blacklist:', error);
      return false;
    }
  }

  /**
   * Get session ID from token
   */
  getSessionId(token) {
    try {
      const decoded = jwt.decode(token);
      return decoded?.sessionId || null;
    } catch {
      return null;
    }
  }

  /**
   * Store session data
   */
  async storeSession(sessionId, sessionData) {
    const ttl = Math.ceil((sessionData.expiresAt - Date.now()) / 1000);

    if (this.redis) {
      await this.redis.setex(
        `session:${sessionId}`,
        Math.max(ttl, 1),
        JSON.stringify(sessionData)
      );
    } else {
      this.sessions.set(sessionId, sessionData);
    }
  }

  /**
   * Get session data
   */
  async getSession(sessionId) {
    try {
      if (this.redis) {
        const data = await this.redis.get(`session:${sessionId}`);
        return data ? JSON.parse(data) : null;
      } else {
        const sessionData = this.sessions.get(sessionId);
        if (sessionData && sessionData.expiresAt > Date.now()) {
          return sessionData;
        } else if (sessionData) {
          this.sessions.delete(sessionId);
        }
        return null;
      }
    } catch (error) {
      logger.error('Failed to get session:', error);
      return null;
    }
  }

  /**
   * Update session activity
   */
  async updateSessionActivity(sessionId) {
    try {
      const sessionData = await this.getSession(sessionId);
      if (sessionData) {
        sessionData.lastActivity = Date.now();
        await this.storeSession(sessionId, sessionData);
      }
    } catch (error) {
      logger.error('Failed to update session activity:', error);
    }
  }

  /**
   * Add session to user session list
   */
  async addUserSession(userId, sessionId) {
    try {
      if (this.redis) {
        await this.redis.sadd(`user_sessions:${userId}`, sessionId);
        await this.redis.expire(`user_sessions:${userId}`, 86400 * 7); // 7 days
      }
    } catch (error) {
      logger.error('Failed to add user session:', error);
    }
  }

  /**
   * Remove session from user session list
   */
  async removeUserSession(userId, sessionId) {
    try {
      if (this.redis) {
        await this.redis.srem(`user_sessions:${userId}`, sessionId);
      }
    } catch (error) {
      logger.error('Failed to remove user session:', error);
    }
  }

  /**
   * Get user sessions
   */
  async getUserSessions(userId) {
    try {
      if (this.redis) {
        return await this.redis.smembers(`user_sessions:${userId}`);
      }
      return [];
    } catch (error) {
      logger.error('Failed to get user sessions:', error);
      return [];
    }
  }

  /**
   * Enforce session limits per user
   */
  async enforceSessionLimits(userId) {
    try {
      const sessions = await this.getUserSessions(userId);

      if (sessions.length >= this.config.maxSessions) {
        // Remove oldest sessions
        const sessionsToRemove = sessions.length - this.config.maxSessions + 1;

        for (let i = 0; i < sessionsToRemove; i++) {
          // eslint-disable-next-line security/detect-object-injection
          await this.revokeSession(sessions[i], 'session_limit');
        }

        await AuditLogger.log({
          action: 'SESSION_LIMIT_ENFORCED',
          userId,
          sessionsRemoved: sessionsToRemove,
          timestamp: Date.now()
        });
      }
    } catch (error) {
      logger.error('Failed to enforce session limits:', error);
    }
  }

  /**
   * Encrypt data
   */
  encryptData(data) {
    try {
      const iv = crypto.randomBytes(16);
      // TODO: Replace with createCipheriv for better security
      // eslint-disable-next-line node/no-deprecated-api
      const cipher = crypto.createCipher('aes-256-gcm', this.encryptionKey, iv);

      const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(data), 'utf8'),
        cipher.final()
      ]);

      const authTag = cipher.getAuthTag();

      return {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      };
    } catch (error) {
      logger.error('Failed to encrypt session data:', error);
      return data;
    }
  }

  /**
   * Decrypt data
   */
  decryptData(encryptedData) {
    try {
      // TODO: Replace with createDecipheriv for better security
      // eslint-disable-next-line node/no-deprecated-api
      const decipher = crypto.createDecipher(
        'aes-256-gcm',
        this.encryptionKey,
        Buffer.from(encryptedData.iv, 'hex')
      );

      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedData.encrypted, 'hex')),
        decipher.final()
      ]);

      return JSON.parse(decrypted.toString('utf8'));
    } catch (error) {
      logger.error('Failed to decrypt session data:', error);
      return {};
    }
  }

  /**
   * Hash IP address
   */
  hashIP(ip) {
    return crypto.createHash('sha256').update(ip + this.encryptionKey.toString('hex')).digest('hex').substring(0, 16);
  }

  /**
   * Hash user agent
   */
  hashUserAgent(userAgent) {
    return crypto.createHash('sha256').update(userAgent + this.encryptionKey.toString('hex')).digest('hex').substring(0, 16);
  }

  /**
   * Get token expiry
   */
  getTokenExpiry(token) {
    try {
      const decoded = jwt.decode(token);
      return decoded?.exp ? decoded.exp * 1000 : null;
    } catch {
      return null;
    }
  }

  /**
   * Start cleanup process
   */
  startCleanup() {
    this.cleanupTimer = setInterval(async () => {
      await this.cleanupExpiredSessions();
    }, this.config.cleanupInterval);
  }

  /**
   * Cleanup expired sessions
   */
  async cleanupExpiredSessions() {
    try {
      let cleanedCount = 0;

      if (this.redis) {
        // Redis TTL handles most cleanup, but clean user session sets
        const userSessionKeys = await this.redis.keys('user_sessions:*');

        for (const key of userSessionKeys) {
          const sessions = await this.redis.smembers(key);
          for (const sessionId of sessions) {
            const exists = await this.redis.exists(`session:${sessionId}`);
            if (!exists) {
              await this.redis.srem(key, sessionId);
              cleanedCount++;
            }
          }
        }
      } else {
        // In-memory cleanup
        const now = Date.now();

        for (const [sessionId, sessionData] of this.sessions) {
          if (sessionData.expiresAt <= now) {
            this.sessions.delete(sessionId);
            cleanedCount++;
          }
        }

        // Cleanup blacklist
        for (const [hash, entry] of this.blacklist) {
          if (entry.expiry <= now) {
            this.blacklist.delete(hash);
          }
        }
      }

      if (cleanedCount > 0) {
        logger.info(`Cleaned up ${cleanedCount} expired sessions`);
      }

    } catch (error) {
      logger.error('Failed to cleanup expired sessions:', error);
    }
  }

  /**
   * Get session statistics
   */
  getStats() {
    return {
      ...this.stats,
      isInitialized: this.initialized,
      redisConnected: this.redis ? this.redis.status === 'ready' : false,
      config: {
        sessionTimeout: this.config.sessionTimeout,
        maxSessions: this.config.maxSessions,
        encryptionEnabled: this.config.enableEncryption,
        rotationEnabled: this.config.enableRotation
      }
    };
  }

  /**
   * Shutdown session manager
   */
  async shutdown() {
    try {
      logger.info('Shutting down session manager...');

      if (this.cleanupTimer) {
        clearInterval(this.cleanupTimer);
        this.cleanupTimer = null;
      }

      if (this.redis) {
        await this.redis.quit();
        this.redis = null;
      }

      this.initialized = false;

      await AuditLogger.logSystemEvent({
        type: 'SESSION_MANAGER_SHUTDOWN',
        stats: this.getStats(),
        timestamp: Date.now()
      });

      logger.info('Session manager shut down successfully');

    } catch (error) {
      logger.error('Error shutting down session manager:', error);
    }
  }
}

// Export singleton instance
module.exports = new SessionManager();
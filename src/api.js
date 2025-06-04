const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const { setupRoutes } = require('./routes');
const logger = require('./utils/logger');
const errorManager = require('./utils/errorManager');

// Import enhanced security modules
const SecurityValidator = require('./utils/securityValidator');
const SessionManager = require('./utils/sessionManager');
const AuditLogger = require('./utils/auditLogger');
const PermissionValidator = require('./utils/permissionValidator');
const advancedRateLimiter = require('./utils/advancedRateLimiter');

// Initialize Express app
const app = express();

// Security configuration
const SECURITY_CONFIG = {
  jwt: {
    algorithm: 'HS256',
    expiresIn: '7d',
    issuer: 'discord-ai-moderator',
    audience: 'discord-api'
  },
  session: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    rotateThreshold: 24 * 60 * 60 * 1000 // Rotate after 24 hours
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    skipSuccessfulRequests: false,
    standardHeaders: true,
    legacyHeaders: false
  }
};

// Setup API with enhanced security
function setupApi() {
  // Enhanced security middleware with CSP and additional protections
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "cross-origin" },
    referrerPolicy: { policy: ["no-referrer", "strict-origin-when-cross-origin"] },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    noSniff: true,
    xssFilter: true,
    frameguard: { action: 'deny' }
  }));
  
  // Request ID middleware for audit tracking
  app.use((req, res, next) => {
    req.requestId = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.requestId);
    next();
  });
  
  // Enhanced body parsing with security verification
  app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
      try {
        // Verify JSON is valid and not malicious
        const parsed = JSON.parse(buf);
        
        // Check for deeply nested objects (potential DoS)
        const depth = getObjectDepth(parsed);
        if (depth > 10) {
          throw new Error('JSON object too deeply nested');
        }
        
        // Check for excessively large arrays
        if (hasLargeArrays(parsed, 1000)) {
          throw new Error('JSON contains arrays that are too large');
        }
        
      } catch (e) {
        const error = new Error('Invalid or malicious JSON');
        error.status = 400;
        throw error;
      }
    }
  }));
  
  app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb',
    parameterLimit: 100 // Limit number of parameters
  }));
  
  // Enhanced input sanitization
  app.use(mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
      logger.warn(`Sanitized potentially malicious input in ${req.path}`, { 
        key, 
        ip: req.ip,
        userAgent: req.get('User-Agent')?.substring(0, 100),
        requestId: req.requestId
      });
      
      // Log security event for audit
      AuditLogger.logSecurityEvent({
        type: 'MALICIOUS_INPUT_SANITIZED',
        path: req.path,
        key,
        ip: req.ip,
        requestId: req.requestId,
        timestamp: Date.now()
      });
    }
  }));
  
  // CORS with enhanced security
  const corsOptions = {
    origin: (origin, callback) => {
      const allowedOrigins = process.env.CORS_ORIGINS ? 
        process.env.CORS_ORIGINS.split(',') : ['http://localhost:3000'];
      
      // Allow requests with no origin (mobile apps, etc.)
      if (!origin) return callback(null, true);
      
      // Validate origin format
      try {
        const url = new URL(origin);
        if (!['http:', 'https:'].includes(url.protocol)) {
          return callback(new Error('Invalid origin protocol'), false);
        }
      } catch {
        return callback(new Error('Invalid origin format'), false);
      }
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        AuditLogger.logSecurityEvent({
          type: 'CORS_VIOLATION',
          origin,
          allowedOrigins,
          timestamp: Date.now()
        });
        callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining'],
    maxAge: 86400, // 24 hours
    optionsSuccessStatus: 200
  };
  app.use(cors(corsOptions));
  
  // Advanced rate limiting with pattern detection
  app.use('/api', advancedRateLimiter.middleware({
    includeDetails: process.env.NODE_ENV === 'development'
  }));
  
  // Legacy rate limiting as fallback
  const legacyLimiter = rateLimit({
    ...SECURITY_CONFIG.rateLimit,
    keyGenerator: (req) => {
      // Enhanced IP extraction with validation
      const forwarded = req.headers['x-forwarded-for'];
      if (forwarded) {
        const ip = forwarded.split(',')[0].trim();
        // Validate IP format
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip) ||
            /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(ip)) {
          return ip;
        }
      }
      return req.ip || 'unknown';
    },
    handler: async (req, res, next, options) => {
      await AuditLogger.logSecurityEvent({
        type: 'RATE_LIMIT_EXCEEDED',
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent')?.substring(0, 100),
        requestId: req.requestId,
        timestamp: Date.now()
      });
      
      errorManager.handleError(
        new Error('Rate limit exceeded'),
        'api', 
        {
          operation: 'rateLimit',
          ip: req.ip,
          path: req.path,
          userAgent: req.get('User-Agent')?.substring(0, 100),
          requestId: req.requestId
        }
      );
      
      res.status(options.statusCode).json({
        error: 'Too many requests',
        retryAfter: Math.ceil(options.windowMs / 1000 / 60),
        requestId: req.requestId
      });
    }
  });
  
  // Speed limiting for expensive operations
  const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 10,
    delayMs: 500,
    maxDelayMs: 5000, // Maximum delay of 5 seconds
    skipFailedRequests: false,
    skipSuccessfulRequests: false
  });
  
  app.use('/api', legacyLimiter);
  app.use('/api', speedLimiter);
  
  // Enhanced input validation middleware
  const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const validationErrors = errors.array();
      
      logger.warn('Input validation failed', {
        path: req.path,
        errors: validationErrors,
        ip: req.ip,
        requestId: req.requestId
      });
      
      // Log security event for repeated validation failures
      AuditLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        path: req.path,
        errors: validationErrors.map(err => err.msg),
        ip: req.ip,
        requestId: req.requestId,
        timestamp: Date.now()
      });
      
      return res.status(400).json({ 
        error: 'Invalid input',
        details: validationErrors.map(err => ({
          field: err.param,
          message: err.msg,
          value: err.value ? '[REDACTED]' : undefined
        })),
        requestId: req.requestId
      });
    }
    next();
  };
  
  // Enhanced JWT authentication middleware with session management
  const authenticateToken = async (req, res, next) => {
    // Skip auth for public routes
    const publicRoutes = ['/api/health', '/api/login', '/api/register'];
    if (publicRoutes.includes(req.path)) {
      return next();
    }
    
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        await AuditLogger.logSecurityEvent({
          type: 'MISSING_AUTH_HEADER',
          path: req.path,
          ip: req.ip,
          requestId: req.requestId,
          timestamp: Date.now()
        });
        
        return res.status(401).json({ 
          error: 'Missing or invalid authorization header',
          message: 'Expected: Bearer <token>',
          requestId: req.requestId
        });
      }
      
      const token = authHeader.split(' ')[1];
      
      // Enhanced token format validation
      if (!token || token.length < 20 || token.length > 2000) {
        await AuditLogger.logSecurityEvent({
          type: 'INVALID_TOKEN_FORMAT',
          tokenLength: token?.length || 0,
          ip: req.ip,
          requestId: req.requestId,
          timestamp: Date.now()
        });
        
        return res.status(401).json({ 
          error: 'Invalid token format',
          requestId: req.requestId
        });
      }
      
      // Check token blacklist first
      if (await SessionManager.isTokenBlacklisted(token)) {
        await AuditLogger.logSecurityEvent({
          type: 'BLACKLISTED_TOKEN_USED',
          ip: req.ip,
          requestId: req.requestId,
          timestamp: Date.now()
        });
        
        return res.status(401).json({ 
          error: 'Token has been revoked',
          code: 'TOKEN_REVOKED',
          requestId: req.requestId
        });
      }
      
      // Verify and validate token
      const decoded = await SessionManager.verifyToken(token);
      
      // Enhanced payload validation
      if (!decoded.userId || !decoded.serverId || !decoded.sessionId) {
        throw new Error('Invalid token payload structure');
      }
      
      // Validate Discord IDs in token
      if (!SecurityValidator.validateDiscordId(decoded.userId, 'token')) {
        throw new Error('Invalid user ID in token');
      }
      
      if (!SecurityValidator.validateDiscordId(decoded.serverId, 'token')) {
        throw new Error('Invalid server ID in token');
      }
      
      // Check permissions for the requested resource
      const hasPermission = await PermissionValidator.checkPermissions(
        decoded.userId,
        decoded.serverId,
        req.method,
        req.path
      );
      
      if (!hasPermission) {
        await AuditLogger.logUnauthorizedAccess(decoded.userId, req);
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
          requestId: req.requestId
        });
      }
      
      // Attach validated user context with security info
      req.user = {
        ...decoded,
        sessionId: SessionManager.getSessionId(token),
        ip: req.ip,
        requestId: req.requestId
      };
      
      // Check if token needs refresh
      const refreshedToken = await SessionManager.refreshIfNeeded(token);
      if (refreshedToken) {
        res.setHeader('X-Refreshed-Token', refreshedToken);
        await AuditLogger.log({
          action: 'TOKEN_REFRESHED',
          userId: decoded.userId,
          sessionId: decoded.sessionId,
          timestamp: Date.now()
        });
      }
      
      next();
    } catch (error) {
      // Enhanced error logging with security context
      const errorInfo = {
        name: error.name,
        message: error.message,
        ip: req.ip,
        path: req.path,
        requestId: req.requestId,
        timestamp: Date.now()
      };
      
      await AuditLogger.logSecurityEvent({
        type: 'AUTHENTICATION_ERROR',
        error: errorInfo,
        timestamp: Date.now()
      });
      
      errorManager.handleError(error, 'api', {
        operation: 'auth',
        path: req.path,
        ip: req.ip,
        requestId: req.requestId,
        error: error.message
      });
      
      let message = 'Invalid token';
      let code = 'INVALID_TOKEN';
      
      if (error.name === 'TokenExpiredError') {
        message = 'Token expired';
        code = 'TOKEN_EXPIRED';
      } else if (error.name === 'JsonWebTokenError') {
        message = 'Invalid token format';
        code = 'INVALID_TOKEN_FORMAT';
      } else if (error.message.includes('Session not found')) {
        message = 'Session expired';
        code = 'SESSION_EXPIRED';
      }
      
      return res.status(401).json({ 
        error: message,
        code,
        requestId: req.requestId
      });
    }
  };
  
  app.use(authenticateToken);
  
  // Enhanced global error handler
  app.use(async (err, req, res, next) => {
    // Generate error ID for tracking
    const errorId = crypto.randomUUID();
    
    // Sanitize error for logging (remove sensitive data)
    const sanitizedError = {
      id: errorId,
      message: err.message,
      status: err.status,
      name: err.name,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      requestId: req.requestId
    };
    
    // Log security-relevant errors
    if (err.status === 401 || err.status === 403 || err.name === 'SecurityError') {
      await AuditLogger.logSecurityEvent({
        type: 'API_SECURITY_ERROR',
        error: sanitizedError,
        ip: req.ip,
        path: req.path,
        method: req.method,
        userAgent: req.get('User-Agent')?.substring(0, 100),
        timestamp: Date.now()
      });
    }
    
    errorManager.handleError(err, 'api', {
      operation: req.method,
      path: req.path,
      ip: req.ip,
      userId: req.user?.userId?.substring(0, 10) + '...' || 'anonymous',
      userAgent: req.get('User-Agent')?.substring(0, 100),
      requestId: req.requestId,
      errorId
    });
    
    // Never expose internal error details in production
    const statusCode = err.status || 500;
    const isClientError = statusCode >= 400 && statusCode < 500;
    const message = isClientError ? err.message : 'Internal Server Error';
    
    res.status(statusCode).json({
      error: message,
      errorId,
      timestamp: new Date().toISOString(),
      requestId: req.requestId,
      ...(process.env.NODE_ENV === 'development' && { details: sanitizedError })
    });
  });
  
  // Enhanced health check with comprehensive system status
  app.get('/api/health', async (req, res) => {
    try {
      const status = errorManager.getStatus();
      const securityStatus = await getSecurityStatus();
      
      const healthStatus = {
        status: status.degradedMode ? 'degraded' : 'healthy',
        timestamp: new Date().toISOString(),
        services: Object.fromEntries(
          Object.entries(status.serviceStatus).map(([service, data]) => [
            service, 
            {
              healthy: data.healthy,
              lastCheck: new Date(data.lastCheck).toISOString(),
              failures: data.failures,
              responseTime: data.responseTime || null
            }
          ])
        ),
        security: {
          rateLimiter: securityStatus.rateLimiter,
          authentication: securityStatus.authentication,
          monitoring: securityStatus.monitoring
        },
        uptime: Math.floor(status.uptime / 1000),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        requestId: req.requestId
      };
      
      const httpStatus = status.degradedMode ? 503 : 200;
      res.status(httpStatus).json(healthStatus);
    } catch (error) {
      logger.error('Health check failed:', error);
      res.status(500).json({
        status: 'error',
        error: 'Health check failed',
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      });
    }
  });
  
  // Security status endpoint (authenticated)
  app.get('/api/security/status', async (req, res) => {
    try {
      const securityReport = await generateSecurityReport(req.user);
      res.json({
        ...securityReport,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Security status check failed:', error);
      res.status(500).json({
        error: 'Failed to generate security report',
        requestId: req.requestId
      });
    }
  });
  
  // Setup API routes with enhanced validation
  setupRoutes(app, validateRequest);
  
  // 404 handler with security logging
  app.use('*', async (req, res) => {
    await AuditLogger.log({
      action: 'ROUTE_NOT_FOUND',
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent')?.substring(0, 100),
      requestId: req.requestId,
      timestamp: Date.now()
    });
    
    res.status(404).json({
      error: 'Not Found',
      message: 'The requested resource was not found',
      path: req.originalUrl,
      requestId: req.requestId
    });
  });
  
  // Start server with enhanced security
  const port = process.env.DASHBOARD_PORT || 3000;
  const host = process.env.DASHBOARD_HOST || '127.0.0.1'; // Secure default
  
  const server = app.listen(port, host, () => {
    logger.info(`API server listening on ${host}:${port}`);
  });
  
  // Enhanced server configuration
  server.timeout = parseInt(process.env.SERVER_TIMEOUT) || 30000;
  server.keepAliveTimeout = parseInt(process.env.KEEP_ALIVE_TIMEOUT) || 65000;
  server.headersTimeout = parseInt(process.env.HEADERS_TIMEOUT) || 66000;
  server.maxConnections = parseInt(process.env.MAX_CONNECTIONS) || 1000;
  
  // Enhanced graceful shutdown
  const shutdown = async (signal) => {
    logger.info(`${signal} received, shutting down API server gracefully`);
    
    // Stop accepting new requests
    server.close(async (err) => {
      if (err) {
        logger.error('Error during server shutdown:', err);
        process.exit(1);
      }
      
      try {
        // Cleanup security monitoring
        await AuditLogger.log({
          action: 'SERVER_SHUTDOWN',
          signal,
          timestamp: Date.now()
        });
        
        // Stop rate limiter
        advancedRateLimiter.shutdown();
        
        logger.info('API server closed gracefully');
        process.exit(0);
      } catch (error) {
        logger.error('Error during cleanup:', error);
        process.exit(1);
      }
    });
    
    // Force close after timeout
    setTimeout(() => {
      logger.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, parseInt(process.env.SHUTDOWN_TIMEOUT) || 10000);
  };
  
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  
  return server;
}

// Helper functions
function getObjectDepth(obj, depth = 0) {
  if (depth > 20) return depth; // Prevent infinite recursion
  if (obj === null || typeof obj !== 'object') return depth;
  
  let maxDepth = depth;
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const currentDepth = getObjectDepth(obj[key], depth + 1);
      maxDepth = Math.max(maxDepth, currentDepth);
    }
  }
  return maxDepth;
}

function hasLargeArrays(obj, maxSize = 1000, visited = new WeakSet()) {
  if (obj === null || typeof obj !== 'object') return false;
  if (visited.has(obj)) return false; // Prevent circular references
  
  visited.add(obj);
  
  if (Array.isArray(obj) && obj.length > maxSize) {
    return true;
  }
  
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      if (hasLargeArrays(obj[key], maxSize, visited)) {
        return true;
      }
    }
  }
  
  return false;
}

async function getSecurityStatus() {
  return {
    rateLimiter: {
      active: true,
      stats: advancedRateLimiter.getStats()
    },
    authentication: {
      sessionManager: true,
      tokenValidation: true
    },
    monitoring: {
      auditLogging: true,
      securityEvents: true
    }
  };
}

async function generateSecurityReport(user) {
  const report = {
    timestamp: new Date().toISOString(),
    user: {
      id: user.userId,
      serverId: user.serverId,
      sessionAge: Date.now() - (user.iat * 1000)
    },
    rateLimiting: advancedRateLimiter.generateReport(),
    recentSecurityEvents: await AuditLogger.getRecentSecurityEvents(24), // Last 24 hours
    systemHealth: errorManager.getStatus()
  };
  
  return report;
}

module.exports = {
  setupApi,
  authenticateToken: authenticateToken,
  SECURITY_CONFIG
};
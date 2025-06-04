const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./utils/logger');
const errorManager = require('./utils/errorManager');

// Import new security modules
const SecurityValidator = require('./utils/securityValidator');
const AuditLogger = require('./utils/auditLogger');
const PrivacyManager = require('./utils/privacyManager');

// Database setup function with enhanced security
async function setupDatabase() {
  const dbType = process.env.DB_TYPE || 'MONGODB';
  
  if (dbType === 'MONGODB') {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/discord-ai-moderator';
    
    // Enhanced URI validation
    if (!mongoUri.match(/^mongodb(\+srv)?:\/\/.+/)) {
      throw new Error('Invalid MongoDB URI format');
    }
    
    // Security: Validate that URI doesn't contain suspicious patterns
    const suspiciousPatterns = [
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /file:/i,
      /<script/i
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(mongoUri))) {
      throw new Error('Potentially malicious MongoDB URI detected');
    }
    
    mongoose.set('strictQuery', true);
    mongoose.set('sanitizeFilter', true); // Additional MongoDB injection protection
    
    // Enhanced connection options with security focus
    const connectionOptions = {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      family: 4,
      retryWrites: true,
      retryReads: true,
      compressors: ['zlib'],
      authSource: 'admin',
      // Security enhancements
      ssl: process.env.MONGODB_SSL === 'true',
      sslValidate: process.env.MONGODB_SSL_VALIDATE !== 'false',
      readPreference: 'secondary', // Distribute read load
      readConcern: { level: 'majority' }, // Ensure consistent reads
      writeConcern: { w: 'majority', j: true }, // Ensure durable writes
    };
    
    // Add SSL certificate if provided
    if (process.env.MONGODB_CA_CERT) {
      connectionOptions.sslCA = fs.readFileSync(process.env.MONGODB_CA_CERT);
    }
    
    // Connection event listeners with audit logging
    mongoose.connection.on('error', async (error) => {
      await AuditLogger.logSecurityEvent({
        type: 'DATABASE_CONNECTION_ERROR',
        error: error.message,
        timestamp: Date.now()
      });
      
      errorManager.handleError(error, 'database', {
        operation: 'connection',
        uri: mongoUri.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@')
      });
    });
    
    mongoose.connection.on('disconnected', async () => {
      logger.warn('MongoDB disconnected, attempting to reconnect');
      await AuditLogger.logSecurityEvent({
        type: 'DATABASE_DISCONNECTED',
        timestamp: Date.now()
      });
    });
    
    mongoose.connection.on('reconnected', async () => {
      logger.info('MongoDB reconnected successfully');
      await AuditLogger.logSecurityEvent({
        type: 'DATABASE_RECONNECTED',
        timestamp: Date.now()
      });
    });
    
    try {
      await mongoose.connect(mongoUri, connectionOptions);
      logger.info('Connected to MongoDB with enhanced security settings');
      
      // Log successful connection
      await AuditLogger.logSecurityEvent({
        type: 'DATABASE_CONNECTED',
        timestamp: Date.now(),
        connectionOptions: {
          ssl: connectionOptions.ssl,
          readConcern: connectionOptions.readConcern.level,
          writeConcern: connectionOptions.writeConcern.w
        }
      });
      
    } catch (error) {
      await AuditLogger.logSecurityEvent({
        type: 'DATABASE_CONNECTION_FAILED',
        error: error.message,
        timestamp: Date.now()
      });
      
      const result = await errorManager.handleError(error, 'database', {
        operation: 'connect',
        uri: mongoUri.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@'),
        retryFunction: async () => {
          return mongoose.connect(mongoUri, connectionOptions);
        }
      });
      
      if (!result || !result.success) {
        logger.error('Failed to connect to MongoDB after retries, application may not function correctly');
      }
    }
  } else if (dbType === 'SQLITE') {
    const dataDir = path.join(__dirname, '..', 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true, mode: 0o750 });
    }
    
    logger.info('Using SQLite database');
    await AuditLogger.logSecurityEvent({
      type: 'DATABASE_SQLITE_INITIALIZED',
      timestamp: Date.now()
    });
  } else {
    throw new Error(`Unknown database type: ${dbType}`);
  }
}

// Enhanced input validation and sanitization
function sanitizeInput(input) {
  if (typeof input === 'string') {
    // Remove potentially dangerous characters and patterns
    const cleaned = input
      .trim()
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Control characters
      .replace(/\$where/gi, '') // MongoDB $where injection
      .replace(/\$regex/gi, '') // MongoDB regex injection
      .substring(0, 10000); // Length limit
    
    return mongoSanitize.sanitize(cleaned);
  }
  return mongoSanitize.sanitize(input);
}

function validateObjectId(id) {
  try {
    return mongoose.Types.ObjectId.isValid(id) && /^[a-f\d]{24}$/i.test(id);
  } catch {
    return false;
  }
}

function validateServerId(serverId) {
  return SecurityValidator.validateDiscordId(serverId, 'server');
}

function validateUserId(userId) {
  return SecurityValidator.validateDiscordId(userId, 'user');
}

function validateChannelId(channelId) {
  return SecurityValidator.validateDiscordId(channelId, 'channel');
}

// Enhanced Server Configuration Schema
const ServerConfigSchema = new mongoose.Schema({
  serverId: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: validateServerId,
      message: 'Invalid server ID format'
    },
    index: true
  },
  enabled: { type: Boolean, default: true },
  channels: [{ 
    type: String,
    validate: {
      validator: validateChannelId,
      message: 'Invalid channel ID format'
    }
  }],
  rules: { 
    type: String, 
    default: 'Be respectful to others.',
    maxlength: [5000, 'Rules cannot exceed 5000 characters'],
    validate: {
      validator: function(v) {
        return v && v.trim().length > 0;
      },
      message: 'Rules cannot be empty'
    }
  },
  strictness: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    default: 'medium' 
  },
  notifications: {
    channel: { 
      type: String, 
      default: null,
      validate: {
        validator: function(v) {
          return v === null || validateChannelId(v);
        },
        message: 'Invalid notification channel ID format'
      }
    },
    sendAlerts: { type: Boolean, default: true }
  },
  // Enhanced security fields
  encryptedData: { type: String }, // For storing encrypted sensitive data
  dataHash: { type: String }, // For integrity verification
  lastModifiedBy: { type: String }, // Audit trail
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

// Pre-save middleware for encryption and integrity
ServerConfigSchema.pre('save', async function(next) {
  if (this.isModified('rules')) {
    // Create integrity hash
    this.dataHash = crypto.createHash('sha256')
      .update(JSON.stringify({
        rules: this.rules,
        strictness: this.strictness,
        enabled: this.enabled
      }))
      .digest('hex');
  }
  
  this.updatedAt = new Date();
  next();
});

// Enhanced User Data Schema with privacy features
const UserDataSchema = new mongoose.Schema({
  userId: { 
    type: String, 
    required: true,
    validate: {
      validator: validateUserId,
      message: 'Invalid user ID format'
    }
  },
  serverId: { 
    type: String, 
    required: true,
    validate: {
      validator: validateServerId,
      message: 'Invalid server ID format'
    }
  },
  isExempt: { type: Boolean, default: false },
  exemptUntil: { type: Date, default: null },
  joinedAt: { type: Date, default: Date.now },
  recentViolations: { 
    type: Number, 
    default: 0,
    min: [0, 'Recent violations cannot be negative'],
    max: [1000, 'Recent violations limit exceeded']
  },
  totalViolations: { 
    type: Number, 
    default: 0,
    min: [0, 'Total violations cannot be negative'],
    max: [10000, 'Total violations limit exceeded']
  },
  lastActionTaken: { type: Date },
  canPostInvites: { type: Boolean, default: false },
  // Privacy and security fields
  isAnonymized: { type: Boolean, default: false },
  anonymizedAt: { type: Date },
  consentStatus: { 
    type: String, 
    enum: ['pending', 'granted', 'denied', 'revoked'], 
    default: 'pending' 
  },
  dataRetentionExpiry: { type: Date },
  trustLevel: { type: Number, default: 0.5, min: 0, max: 1 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Enhanced indexes
UserDataSchema.index({ userId: 1, serverId: 1 }, { unique: true });
UserDataSchema.index({ serverId: 1, totalViolations: -1 });
UserDataSchema.index({ isAnonymized: 1, anonymizedAt: 1 });
UserDataSchema.index({ dataRetentionExpiry: 1 }, { expireAfterSeconds: 0 });

// Enhanced Violation Log Schema with security features
const ViolationLogSchema = new mongoose.Schema({
  serverId: { 
    type: String, 
    required: true,
    validate: {
      validator: validateServerId,
      message: 'Invalid server ID format'
    },
    index: true
  },
  userId: { 
    type: String, 
    required: true,
    validate: {
      validator: validateUserId,
      message: 'Invalid user ID format'
    }
  },
  messageId: { 
    type: String, 
    required: true,
    validate: {
      validator: (v) => SecurityValidator.validateDiscordId(v, 'message'),
      message: 'Invalid message ID format'
    }
  },
  channelId: { 
    type: String, 
    required: true,
    validate: {
      validator: validateChannelId,
      message: 'Invalid channel ID format'
    }
  },
  content: { 
    type: String, 
    required: true,
    maxlength: [4000, 'Content too long for logging']
  },
  // Enhanced content security
  contentHash: { type: String }, // SHA-256 hash of content for integrity
  isViolation: { type: Boolean, required: true },
  category: { 
    type: String,
    enum: ['Toxicity', 'Harassment', 'Spam', 'NSFW', 'Other', null],
    default: null
  },
  severity: { 
    type: String,
    enum: ['None', 'Mild', 'Moderate', 'Severe', null],
    default: null
  },
  confidence: { 
    type: Number,
    min: [0, 'Confidence cannot be negative'],
    max: [1, 'Confidence cannot exceed 1']
  },
  intent: { 
    type: String,
    enum: ['question', 'accidental', 'intentional', 'normal', null],
    default: null
  },
  actionTaken: { 
    type: String,
    enum: ['none', 'flag', 'warn', 'mute', 'kick', 'ban', 'delete'],
    default: 'none'
  },
  actionSource: { 
    type: String, 
    enum: ['pattern', 'AI', 'override', 'fallback'],
    required: true
  },
  processed: { type: Boolean, default: true },
  skipped: { type: Boolean, default: false },
  skipReason: { 
    type: String,
    maxlength: [200, 'Skip reason too long']
  },
  modelUsed: { 
    type: String,
    maxlength: [100, 'Model name too long']
  },
  provider: {
    type: String,
    enum: ['ANTHROPIC', 'OPENROUTER', null],
    default: null
  },
  tokensUsed: { 
    type: Number,
    min: [0, 'Tokens used cannot be negative'],
    max: [1000000, 'Tokens used seems excessive']
  },
  processingTimeMs: { 
    type: Number,
    min: [0, 'Processing time cannot be negative'],
    max: [300000, 'Processing time seems excessive (5 minutes)']
  },
  // Security and audit fields
  ipAddress: { type: String }, // Hashed IP for audit trail
  sessionId: { type: String },
  requestId: { type: String },
  createdAt: { type: Date, default: Date.now, index: true }
});

// Pre-save middleware for content integrity
ViolationLogSchema.pre('save', function(next) {
  if (this.content) {
    this.contentHash = crypto.createHash('sha256')
      .update(this.content)
      .digest('hex');
  }
  next();
});

// Enhanced indexes for security and performance
ViolationLogSchema.index({ serverId: 1, createdAt: -1 });
ViolationLogSchema.index({ userId: 1, createdAt: -1 });
ViolationLogSchema.index({ serverId: 1, isViolation: 1, createdAt: -1 });
ViolationLogSchema.index({ contentHash: 1 }); // For integrity verification
ViolationLogSchema.index({ requestId: 1 }); // For audit trail

// TTL index with configurable retention
const logRetentionDays = parseInt(process.env.LOG_RETENTION_DAYS) || 90;
ViolationLogSchema.index({ createdAt: 1 }, { 
  expireAfterSeconds: logRetentionDays * 24 * 60 * 60 
});

// Create models
const ServerConfig = mongoose.model('ServerConfig', ServerConfigSchema);
const UserData = mongoose.model('UserData', UserDataSchema);
const ViolationLog = mongoose.model('ViolationLog', ViolationLogSchema);

// Enhanced database operations with comprehensive security
async function getServerConfig(serverId, options = {}) {
  try {
    // Enhanced security validation
    const validatedId = SecurityValidator.validateDiscordId(serverId, 'getServerConfig');
    
    // Audit logging for sensitive operations
    await AuditLogger.log({
      action: 'SERVER_CONFIG_ACCESS',
      serverId: validatedId,
      timestamp: Date.now(),
      ip: options.ip,
      userId: options.userId
    });
    
    const sanitizedServerId = sanitizeInput(validatedId);
    let config = await ServerConfig.findOne({ serverId: sanitizedServerId }).lean();
    
    if (!config) {
      // Create default config with audit logging
      config = await ServerConfig.create({
        serverId: sanitizedServerId,
        enabled: false,
        channels: [],
        rules: 'Be respectful to others.',
        strictness: 'medium',
        notifications: {
          channel: null,
          sendAlerts: true
        },
        lastModifiedBy: options.userId || 'system'
      });
      
      await AuditLogger.log({
        action: 'SERVER_CONFIG_CREATED',
        serverId: validatedId,
        timestamp: Date.now(),
        userId: options.userId || 'system'
      });
    }
    
    // Verify data integrity if hash exists
    if (config.dataHash) {
      const expectedHash = crypto.createHash('sha256')
        .update(JSON.stringify({
          rules: config.rules,
          strictness: config.strictness,
          enabled: config.enabled
        }))
        .digest('hex');
      
      if (expectedHash !== config.dataHash) {
        await AuditLogger.logSecurityEvent({
          type: 'DATA_INTEGRITY_VIOLATION',
          collection: 'ServerConfig',
          documentId: config._id,
          expectedHash,
          actualHash: config.dataHash,
          timestamp: Date.now()
        });
        
        logger.warn('Data integrity check failed for server config', {
          serverId: validatedId,
          expectedHash,
          actualHash: config.dataHash
        });
      }
    }
    
    return config;
  } catch (error) {
    if (error.isSecurityError) {
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_VALIDATION_FAILED',
        operation: 'getServerConfig',
        error: error.message,
        serverId: serverId?.substring(0, 10) + '...',
        timestamp: Date.now()
      });
    }
    
    return errorManager.handleError(error, 'database', {
      operation: 'getServerConfig',
      serverId: serverId?.substring(0, 10) + '...',
      retryFunction: async () => {
        const validatedId = SecurityValidator.validateDiscordId(serverId, 'getServerConfig');
        const sanitizedServerId = sanitizeInput(validatedId);
        const config = await ServerConfig.findOne({ serverId: sanitizedServerId }).lean();
        if (!config) {
          return ServerConfig.create({
            serverId: sanitizedServerId,
            enabled: false,
            channels: [],
            rules: 'Be respectful to others.',
            strictness: 'medium',
            notifications: {
              channel: null,
              sendAlerts: true
            },
            lastModifiedBy: options.userId || 'system'
          });
        }
        return config;
      }
    });
  }
}

async function saveServerConfiguration(serverId, config, options = {}) {
  try {
    // Enhanced security validation
    const validatedId = SecurityValidator.validateDiscordId(serverId, 'saveServerConfiguration');
    
    if (!config || typeof config !== 'object') {
      throw SecurityValidator.createSecurityError('Invalid configuration object', {
        code: 'INVALID_CONFIG_TYPE'
      });
    }
    
    // Audit logging for configuration changes
    await AuditLogger.log({
      action: 'SERVER_CONFIG_MODIFICATION_ATTEMPT',
      serverId: validatedId,
      changes: Object.keys(config),
      timestamp: Date.now(),
      ip: options.ip,
      userId: options.userId
    });
    
    // Sanitize and validate configuration
    const sanitizedServerId = sanitizeInput(validatedId);
    const sanitizedConfig = {
      enabled: Boolean(config.enabled),
      channels: Array.isArray(config.channels) ? 
        config.channels
          .filter(id => SecurityValidator.validateDiscordId(id, 'channel'))
          .map(sanitizeInput) : [],
      rules: SecurityValidator.sanitizeRules(config.rules?.toString() || 'Be respectful to others.'),
      strictness: ['low', 'medium', 'high'].includes(config.strictness) ? config.strictness : 'medium',
      notifications: {
        channel: config.notifications?.channel && SecurityValidator.validateDiscordId(config.notifications.channel, 'channel') ? 
          sanitizeInput(config.notifications.channel) : null,
        sendAlerts: Boolean(config.notifications?.sendAlerts ?? true)
      },
      lastModifiedBy: options.userId || 'system',
      updatedAt: new Date()
    };
    
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const oldConfig = await ServerConfig.findOne({ serverId: sanitizedServerId }).session(session);
      
      const updatedConfig = await ServerConfig.findOneAndUpdate(
        { serverId: sanitizedServerId },
        sanitizedConfig,
        { 
          new: true, 
          upsert: true,
          session,
          runValidators: true
        }
      ).lean();
      
      await session.commitTransaction();
      session.endSession();
      
      // Log successful configuration change
      await AuditLogger.log({
        action: 'SERVER_CONFIG_UPDATED',
        serverId: validatedId,
        changes: this.getConfigChanges(oldConfig, sanitizedConfig),
        timestamp: Date.now(),
        userId: options.userId
      });
      
      return updatedConfig;
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    if (error.isSecurityError) {
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_VALIDATION_FAILED',
        operation: 'saveServerConfiguration',
        error: error.message,
        serverId: serverId?.substring(0, 10) + '...',
        timestamp: Date.now()
      });
    }
    
    return errorManager.handleError(error, 'database', {
      operation: 'saveServerConfiguration',
      serverId: serverId?.substring(0, 10) + '...',
      retryFunction: async () => {
        const validatedId = SecurityValidator.validateDiscordId(serverId, 'saveServerConfiguration');
        const sanitizedServerId = sanitizeInput(validatedId);
        const sanitizedConfig = {
          enabled: Boolean(config.enabled),
          channels: Array.isArray(config.channels) ? 
            config.channels
              .filter(id => SecurityValidator.validateDiscordId(id, 'channel'))
              .map(sanitizeInput) : [],
          rules: SecurityValidator.sanitizeRules(config.rules?.toString() || 'Be respectful to others.'),
          strictness: ['low', 'medium', 'high'].includes(config.strictness) ? config.strictness : 'medium',
          notifications: {
            channel: config.notifications?.channel && SecurityValidator.validateDiscordId(config.notifications.channel, 'channel') ? 
              sanitizeInput(config.notifications.channel) : null,
            sendAlerts: Boolean(config.notifications?.sendAlerts ?? true)
          },
          lastModifiedBy: options.userId || 'system',
          updatedAt: new Date()
        };
        
        return ServerConfig.findOneAndUpdate(
          { serverId: sanitizedServerId },
          sanitizedConfig,
          { 
            new: true, 
            upsert: true,
            runValidators: true
          }
        ).lean();
      }
    });
  }
}

async function getUserData(userId, serverId, options = {}) {
  try {
    // Enhanced security validation
    const validatedUserId = SecurityValidator.validateDiscordId(userId, 'getUserData');
    const validatedServerId = SecurityValidator.validateDiscordId(serverId, 'getUserData');
    
    const sanitizedUserId = sanitizeInput(validatedUserId);
    const sanitizedServerId = sanitizeInput(validatedServerId);
    
    let userData = await UserData.findOne({ 
      userId: sanitizedUserId, 
      serverId: sanitizedServerId 
    }).lean();
    
    if (!userData) {
      userData = await UserData.create({
        userId: sanitizedUserId,
        serverId: sanitizedServerId,
        isExempt: false,
        exemptUntil: null,
        joinedAt: new Date(),
        recentViolations: 0,
        totalViolations: 0,
        trustLevel: 0.5
      });
      
      await AuditLogger.log({
        action: 'USER_DATA_CREATED',
        userId: validatedUserId,
        serverId: validatedServerId,
        timestamp: Date.now()
      });
    }
    
    // Check if user data should be anonymized based on retention policy
    if (userData.dataRetentionExpiry && new Date() > userData.dataRetentionExpiry) {
      await PrivacyManager.anonymizeUserData(validatedUserId, { deleteOriginal: false });
    }
    
    return userData;
  } catch (error) {
    if (error.isSecurityError) {
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_VALIDATION_FAILED',
        operation: 'getUserData',
        error: error.message,
        userId: userId?.substring(0, 10) + '...',
        serverId: serverId?.substring(0, 10) + '...',
        timestamp: Date.now()
      });
    }
    
    return errorManager.handleError(error, 'database', {
      operation: 'getUserData',
      userId: userId?.substring(0, 10) + '...',
      serverId: serverId?.substring(0, 10) + '...',
      retryFunction: async () => {
        const validatedUserId = SecurityValidator.validateDiscordId(userId, 'getUserData');
        const validatedServerId = SecurityValidator.validateDiscordId(serverId, 'getUserData');
        const sanitizedUserId = sanitizeInput(validatedUserId);
        const sanitizedServerId = sanitizeInput(validatedServerId);
        
        const userData = await UserData.findOne({ 
          userId: sanitizedUserId, 
          serverId: sanitizedServerId 
        }).lean();
        
        if (!userData) {
          return UserData.create({
            userId: sanitizedUserId,
            serverId: sanitizedServerId,
            isExempt: false,
            exemptUntil: null,
            joinedAt: new Date(),
            recentViolations: 0,
            totalViolations: 0,
            trustLevel: 0.5
          });
        }
        return userData;
      },
      fallback: {
        isExempt: false,
        recentViolations: 0,
        totalViolations: 0,
        joinedRecently: false,
        trustLevel: 0.5
      }
    });
  }
}

async function logAction(action, options = {}) {
  try {
    if (!action || typeof action !== 'object') {
      throw SecurityValidator.createSecurityError('Invalid action object', {
        code: 'INVALID_ACTION_TYPE'
      });
    }
    
    // Enhanced validation using SecurityValidator
    const validatedServerId = SecurityValidator.validateDiscordId(action.serverId, 'logAction');
    const validatedUserId = SecurityValidator.validateDiscordId(action.userId, 'logAction');
    const validatedMessageId = SecurityValidator.validateDiscordId(action.messageId, 'logAction');
    const validatedChannelId = SecurityValidator.validateDiscordId(action.channelId, 'logAction');
    
    const sanitizedAction = {
      serverId: sanitizeInput(validatedServerId),
      userId: sanitizeInput(validatedUserId),
      messageId: sanitizeInput(validatedMessageId),
      channelId: sanitizeInput(validatedChannelId),
      content: SecurityValidator.sanitizeMessageContent(action.content?.toString() || ''),
      isViolation: Boolean(action.isViolation),
      category: ['Toxicity', 'Harassment', 'Spam', 'NSFW', 'Other'].includes(action.category) ? 
        action.category : null,
      severity: ['None', 'Mild', 'Moderate', 'Severe'].includes(action.severity) ? 
        action.severity : null,
      confidence: typeof action.confidence === 'number' && action.confidence >= 0 && action.confidence <= 1 ? 
        action.confidence : null,
      intent: ['question', 'accidental', 'intentional', 'normal'].includes(action.intent) ? 
        action.intent : null,
      actionTaken: ['none', 'flag', 'warn', 'mute', 'kick', 'ban', 'delete'].includes(action.actionTaken) ? 
        action.actionTaken : 'none',
      actionSource: ['pattern', 'AI', 'override', 'fallback'].includes(action.actionSource) ? 
        action.actionSource : 'pattern',
      processed: Boolean(action.processed ?? true),
      skipped: Boolean(action.skipped ?? false),
      skipReason: action.skipReason ? sanitizeInput(action.skipReason.toString().substring(0, 200)) : null,
      modelUsed: action.modelUsed ? sanitizeInput(action.modelUsed.toString().substring(0, 100)) : null,
      provider: ['ANTHROPIC', 'OPENROUTER'].includes(action.provider) ? action.provider : null,
      tokensUsed: typeof action.tokensUsed === 'number' && action.tokensUsed >= 0 ? 
        Math.min(action.tokensUsed, 1000000) : null,
      processingTimeMs: typeof action.processingTimeMs === 'number' && action.processingTimeMs >= 0 ? 
        Math.min(action.processingTimeMs, 300000) : null,
      // Enhanced security fields
      ipAddress: options.ip ? crypto.createHash('sha256').update(options.ip).digest('hex') : null,
      sessionId: options.sessionId,
      requestId: options.requestId || crypto.randomUUID()
    };
    
    const violationLog = await ViolationLog.create(sanitizedAction);
    
    // Log significant violations for audit
    if (sanitizedAction.isViolation && ['Moderate', 'Severe'].includes(sanitizedAction.severity)) {
      await AuditLogger.log({
        action: 'SIGNIFICANT_VIOLATION_LOGGED',
        serverId: validatedServerId,
        userId: validatedUserId,
        category: sanitizedAction.category,
        severity: sanitizedAction.severity,
        confidence: sanitizedAction.confidence,
        timestamp: Date.now()
      });
    }
    
    return violationLog;
  } catch (error) {
    if (error.isSecurityError) {
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_VALIDATION_FAILED',
        operation: 'logAction',
        error: error.message,
        timestamp: Date.now()
      });
    }
    
    return errorManager.handleError(error, 'database', {
      operation: 'logAction',
      actionType: action?.actionTaken || 'unknown',
      retryFunction: async () => ViolationLog.create(sanitizedAction)
    });
  }
}

// Helper function to compare config changes
function getConfigChanges(oldConfig, newConfig) {
  const changes = {};
  
  if (!oldConfig) return { type: 'created' };
  
  const fieldsToCheck = ['enabled', 'rules', 'strictness', 'channels'];
  
  for (const field of fieldsToCheck) {
    if (JSON.stringify(oldConfig[field]) !== JSON.stringify(newConfig[field])) {
      changes[field] = {
        from: oldConfig[field],
        to: newConfig[field]
      };
    }
  }
  
  return changes;
}

module.exports = {
  setupDatabase,
  ServerConfig,
  UserData,
  ViolationLog,
  getServerConfig,
  saveServerConfiguration,
  getUserData,
  logAction,
  sanitizeInput,
  validateObjectId,
  validateServerId,
  validateUserId,
  validateChannelId,
  getConfigChanges
};
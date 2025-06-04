const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const logger = require('./logger');

/**
 * Audit Log Schema for database storage
 */
const AuditLogSchema = new mongoose.Schema({
  eventId: { type: String, required: true, unique: true, index: true },
  type: { 
    type: String, 
    required: true, 
    enum: [
      'SECURITY_EVENT',
      'SYSTEM_EVENT', 
      'USER_ACTION',
      'ADMIN_ACTION',
      'API_ACCESS',
      'DATA_ACCESS',
      'AUTHENTICATION',
      'AUTHORIZATION',
      'ERROR_EVENT'
    ],
    index: true
  },
  category: { 
    type: String, 
    required: true,
    index: true
  },
  severity: { 
    type: String, 
    required: true, 
    enum: ['low', 'medium', 'high', 'critical'],
    index: true 
  },
  timestamp: { type: Date, required: true, index: true },
  sourceIP: { type: String, index: true },
  userId: { type: String, index: true },
  serverId: { type: String, index: true },
  sessionId: { type: String, index: true },
  requestId: { type: String, index: true },
  action: { type: String, required: true },
  resource: { type: String },
  success: { type: Boolean, default: true },
  details: { type: mongoose.Schema.Types.Mixed },
  userAgent: { type: String },
  referrer: { type: String },
  instanceId: { type: String, index: true },
  processId: { type: Number },
  memoryUsage: { type: Number },
  signature: { type: String }, // HMAC signature for integrity
  createdAt: { type: Date, default: Date.now }
});

// TTL index for automatic cleanup
const retentionDays = parseInt(process.env.AUDIT_RETENTION_DAYS) || 90;
AuditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: retentionDays * 24 * 60 * 60 });

// Compound indexes for common queries
AuditLogSchema.index({ type: 1, timestamp: -1 });
AuditLogSchema.index({ severity: 1, timestamp: -1 });
AuditLogSchema.index({ userId: 1, timestamp: -1 });
AuditLogSchema.index({ sourceIP: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', AuditLogSchema);

/**
 * Enhanced Audit Logger with comprehensive security logging
 */
class AuditLogger {
  constructor() {
    this.initialized = false;
    this.config = {
      enableFileLogging: false,
      enableDatabaseLogging: true,
      enableConsoleLogging: process.env.NODE_ENV === 'development',
      retentionDays: 90,
      maxFileSize: 100 * 1024 * 1024, // 100MB
      rotateFiles: true,
      compressionEnabled: true,
      encryptionEnabled: false,
      integrityChecking: true
    };
    this.logQueue = [];
    this.isProcessing = false;
    this.secretKey = null;
    this.logDir = path.join(__dirname, '..', '..', 'logs', 'audit');
    this.currentLogFile = null;
    this.fileWriteStream = null;
    this.errorCount = 0;
    this.maxErrors = 10;
  }
  
  /**
   * Initialize the audit logger
   */
  async initialize(options = {}) {
    try {
      this.config = { ...this.config, ...options };
      
      // Initialize secret key for HMAC signatures
      this.secretKey = process.env.AUDIT_SECRET_KEY || 
                      process.env.JWT_SECRET || 
                      crypto.randomBytes(32).toString('hex');
      
      if (this.secretKey.length < 32) {
        logger.warn('Audit secret key is too short, generating new one');
        this.secretKey = crypto.randomBytes(32).toString('hex');
      }
      
      // Create log directory if file logging is enabled
      if (this.config.enableFileLogging) {
        await this.initializeFileLogging();
      }
      
      // Start background processing
      this.startBackgroundProcessing();
      
      this.initialized = true;
      logger.info('Audit logger initialized successfully', {
        fileLogging: this.config.enableFileLogging,
        databaseLogging: this.config.enableDatabaseLogging,
        retentionDays: this.config.retentionDays
      });
      
      // Log initialization event
      await this.logSystemEvent({
        type: 'AUDIT_LOGGER_INITIALIZED',
        config: {
          fileLogging: this.config.enableFileLogging,
          databaseLogging: this.config.enableDatabaseLogging,
          retentionDays: this.config.retentionDays
        },
        timestamp: Date.now()
      });
      
    } catch (error) {
      logger.error('Failed to initialize audit logger:', error);
      throw error;
    }
  }
  
  /**
   * Initialize file logging system
   */
  async initializeFileLogging() {
    try {
      await fs.mkdir(this.logDir, { recursive: true, mode: 0o750 });
      
      // Generate log file name with timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      this.currentLogFile = path.join(this.logDir, `audit-${timestamp}.log`);
      
      // Create write stream
      this.fileWriteStream = require('fs').createWriteStream(this.currentLogFile, {
        flags: 'a',
        encoding: 'utf8',
        mode: 0o640
      });
      
      this.fileWriteStream.on('error', (error) => {
        logger.error('Audit log file write error:', error);
        this.errorCount++;
        if (this.errorCount > this.maxErrors) {
          this.config.enableFileLogging = false;
          logger.error('Disabling file logging due to excessive errors');
        }
      });
      
      logger.info('Audit file logging initialized', { logFile: this.currentLogFile });
      
    } catch (error) {
      logger.error('Failed to initialize file logging:', error);
      this.config.enableFileLogging = false;
    }
  }
  
  /**
   * Start background processing for log queue
   */
  startBackgroundProcessing() {
    setInterval(async () => {
      if (!this.isProcessing && this.logQueue.length > 0) {
        await this.processLogQueue();
      }
    }, 1000); // Process every second
    
    // Also process on process exit
    process.on('beforeExit', async () => {
      await this.processLogQueue();
    });
  }
  
  /**
   * Process the log queue
   */
  async processLogQueue() {
    if (this.isProcessing || this.logQueue.length === 0) return;
    
    this.isProcessing = true;
    
    try {
      const logsToProcess = [...this.logQueue];
      this.logQueue = [];
      
      // Process in batches
      const batchSize = 50;
      for (let i = 0; i < logsToProcess.length; i += batchSize) {
        const batch = logsToProcess.slice(i, i + batchSize);
        await this.processBatch(batch);
      }
      
    } catch (error) {
      logger.error('Error processing audit log queue:', error);
    } finally {
      this.isProcessing = false;
    }
  }
  
  /**
   * Process a batch of logs
   */
  async processBatch(logs) {
    const promises = [];
    
    for (const logEntry of logs) {
      // Database logging
      if (this.config.enableDatabaseLogging) {
        promises.push(this.saveToDatabase(logEntry));
      }
      
      // File logging
      if (this.config.enableFileLogging && this.fileWriteStream) {
        promises.push(this.saveToFile(logEntry));
      }
      
      // Console logging for development
      if (this.config.enableConsoleLogging) {
        this.logToConsole(logEntry);
      }
    }
    
    await Promise.allSettled(promises);
  }
  
  /**
   * Save log entry to database
   */
  async saveToDatabase(logEntry) {
    try {
      const auditLog = new AuditLog(logEntry);
      await auditLog.save();
    } catch (error) {
      logger.error('Failed to save audit log to database:', error);
      // Fallback to file logging if database fails
      if (this.config.enableFileLogging && this.fileWriteStream) {
        await this.saveToFile(logEntry);
      }
    }
  }
  
  /**
   * Save log entry to file
   */
  async saveToFile(logEntry) {
    try {
      if (!this.fileWriteStream) return;
      
      const logLine = JSON.stringify(logEntry) + '\n';
      
      return new Promise((resolve, reject) => {
        this.fileWriteStream.write(logLine, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
      
    } catch (error) {
      logger.error('Failed to save audit log to file:', error);
    }
  }
  
  /**
   * Log to console for development
   */
  logToConsole(logEntry) {
    const severity = logEntry.severity.toUpperCase();
    const timestamp = new Date(logEntry.timestamp).toISOString();
    const message = `[AUDIT:${severity}] ${timestamp} - ${logEntry.action}`;
    
    switch (logEntry.severity) {
      case 'critical':
        console.error(message, logEntry.details);
        break;
      case 'high':
        console.warn(message, logEntry.details);
        break;
      case 'medium':
        console.info(message, logEntry.details);
        break;
      default:
        console.log(message, logEntry.details);
    }
  }
  
  /**
   * Create HMAC signature for log integrity
   */
  createSignature(logEntry) {
    if (!this.config.integrityChecking || !this.secretKey) return null;
    
    const payload = JSON.stringify({
      eventId: logEntry.eventId,
      type: logEntry.type,
      action: logEntry.action,
      timestamp: logEntry.timestamp,
      userId: logEntry.userId,
      details: logEntry.details
    });
    
    return crypto
      .createHmac('sha256', this.secretKey)
      .update(payload)
      .digest('hex');
  }
  
  /**
   * Verify log entry signature
   */
  verifySignature(logEntry) {
    if (!this.config.integrityChecking || !logEntry.signature) return true;
    
    const expectedSignature = this.createSignature(logEntry);
    return crypto.timingSafeEqual(
      Buffer.from(logEntry.signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }
  
  /**
   * Create standardized log entry
   */
  createLogEntry(type, category, action, details = {}, options = {}) {
    const eventId = crypto.randomUUID();
    const timestamp = new Date();
    const processInfo = process.memoryUsage();
    
    const logEntry = {
      eventId,
      type,
      category,
      severity: this.determineSeverity(type, category, action, details),
      timestamp,
      action,
      details: this.sanitizeDetails(details),
      processId: process.pid,
      memoryUsage: processInfo.heapUsed,
      instanceId: options.instanceId || process.env.INSTANCE_ID,
      ...this.extractRequestInfo(options),
      success: options.success !== false
    };
    
    // Add integrity signature
    if (this.config.integrityChecking) {
      logEntry.signature = this.createSignature(logEntry);
    }
    
    return logEntry;
  }
  
  /**
   * Extract request information from options
   */
  extractRequestInfo(options) {
    const info = {};
    
    if (options.ip) info.sourceIP = this.hashIP(options.ip);
    if (options.userId) info.userId = options.userId;
    if (options.serverId) info.serverId = options.serverId;
    if (options.sessionId) info.sessionId = options.sessionId;
    if (options.requestId) info.requestId = options.requestId;
    if (options.userAgent) info.userAgent = options.userAgent.substring(0, 200);
    if (options.referrer) info.referrer = options.referrer.substring(0, 200);
    if (options.resource) info.resource = options.resource;
    
    return info;
  }
  
  /**
   * Hash IP address for privacy
   */
  hashIP(ip) {
    if (!ip) return null;
    return crypto.createHash('sha256').update(ip + this.secretKey).digest('hex').substring(0, 16);
  }
  
  /**
   * Determine log severity based on context
   */
  determineSeverity(type, category, action, details) {
    // Critical security events
    const criticalPatterns = [
      /SYSTEM_SHUTDOWN/,
      /EMERGENCY/,
      /DDOS_ATTACK/,
      /DATA_BREACH/,
      /UNAUTHORIZED_ACCESS/,
      /PRIVILEGE_ESCALATION/,
      /MASS_ATTACK/
    ];
    
    // High severity events
    const highPatterns = [
      /SECURITY_ALERT/,
      /AUTHENTICATION_FAILED/,
      /AUTHORIZATION_FAILED/,
      /SUSPICIOUS_ACTIVITY/,
      /MALICIOUS_INPUT/,
      /RATE_LIMIT_EXCEEDED/
    ];
    
    // Medium severity events
    const mediumPatterns = [
      /VALIDATION_FAILED/,
      /API_ERROR/,
      /CONFIGURATION_CHANGE/,
      /USER_CREATED/,
      /PASSWORD_CHANGED/
    ];
    
    const actionUpper = action.toUpperCase();
    
    if (criticalPatterns.some(pattern => pattern.test(actionUpper))) {
      return 'critical';
    }
    
    if (highPatterns.some(pattern => pattern.test(actionUpper))) {
      return 'high';
    }
    
    if (mediumPatterns.some(pattern => pattern.test(actionUpper))) {
      return 'medium';
    }
    
    // Check details for severity indicators
    if (details && typeof details === 'object') {
      if (details.severity) return details.severity;
      if (details.critical) return 'critical';
      if (details.error || details.failure) return 'high';
    }
    
    return 'low';
  }
  
  /**
   * Sanitize details to remove sensitive information
   */
  sanitizeDetails(details) {
    if (!details || typeof details !== 'object') return details;
    
    const sanitized = { ...details };
    const sensitiveKeys = [
      'password', 'token', 'secret', 'key', 'credential', 
      'authorization', 'cookie', 'session', 'apikey'
    ];
    
    function sanitizeObject(obj) {
      if (!obj || typeof obj !== 'object') return obj;
      
      for (const [key, value] of Object.entries(obj)) {
        const keyLower = key.toLowerCase();
        
        // Remove sensitive data
        if (sensitiveKeys.some(sensitive => keyLower.includes(sensitive))) {
          obj[key] = '[REDACTED]';
        } else if (typeof value === 'string' && value.length > 10000) {
          // Truncate very long strings
          obj[key] = value.substring(0, 10000) + '... [TRUNCATED]';
        } else if (typeof value === 'object' && value !== null) {
          obj[key] = sanitizeObject(value);
        }
      }
      
      return obj;
    }
    
    return sanitizeObject(sanitized);
  }
  
  /**
   * Log a security event
   */
  async logSecurityEvent(event) {
    if (!this.initialized) return;
    
    const logEntry = this.createLogEntry(
      'SECURITY_EVENT',
      event.type || 'UNKNOWN',
      event.type || 'SECURITY_EVENT',
      event,
      event.options || {}
    );
    
    this.logQueue.push(logEntry);
    
    // Process immediately for critical events
    if (logEntry.severity === 'critical') {
      await this.processLogQueue();
    }
  }
  
  /**
   * Log a system event
   */
  async logSystemEvent(event) {
    if (!this.initialized) return;
    
    const logEntry = this.createLogEntry(
      'SYSTEM_EVENT',
      event.type || 'SYSTEM',
      event.type || 'SYSTEM_EVENT',
      event,
      event.options || {}
    );
    
    this.logQueue.push(logEntry);
  }
  
  /**
   * Log a user action
   */
  async log(data) {
    if (!this.initialized) return;
    
    const logEntry = this.createLogEntry(
      'USER_ACTION',
      data.category || 'USER',
      data.action,
      data,
      data
    );
    
    this.logQueue.push(logEntry);
  }
  
  /**
   * Log an unauthorized access attempt
   */
  async logUnauthorizedAccess(userId, request) {
    await this.logSecurityEvent({
      type: 'UNAUTHORIZED_ACCESS',
      userId,
      path: request.path,
      method: request.method,
      ip: request.ip,
      userAgent: request.get('User-Agent'),
      timestamp: Date.now(),
      options: {
        ip: request.ip,
        userId,
        requestId: request.requestId,
        userAgent: request.get('User-Agent'),
        resource: request.path
      }
    });
  }
  
  /**
   * Get recent security events
   */
  async getRecentSecurityEvents(hours = 24) {
    if (!this.config.enableDatabaseLogging) return [];
    
    try {
      const since = new Date(Date.now() - hours * 60 * 60 * 1000);
      
      const events = await AuditLog.find({
        type: 'SECURITY_EVENT',
        timestamp: { $gte: since }
      })
      .sort({ timestamp: -1 })
      .limit(100)
      .lean();
      
      return events;
    } catch (error) {
      logger.error('Failed to get recent security events:', error);
      return [];
    }
  }
  
  /**
   * Get security events summary
   */
  async getSecurityEventsSummary(hours = 24) {
    if (!this.config.enableDatabaseLogging) return {};
    
    try {
      const since = new Date(Date.now() - hours * 60 * 60 * 1000);
      
      const summary = await AuditLog.aggregate([
        {
          $match: {
            type: 'SECURITY_EVENT',
            timestamp: { $gte: since }
          }
        },
        {
          $group: {
            _id: {
              category: '$category',
              severity: '$severity'
            },
            count: { $sum: 1 },
            latestEvent: { $max: '$timestamp' }
          }
        },
        {
          $group: {
            _id: '$_id.severity',
            categories: {
              $push: {
                category: '$_id.category',
                count: '$count',
                latestEvent: '$latestEvent'
              }
            },
            totalCount: { $sum: '$count' }
          }
        }
      ]);
      
      return summary.reduce((acc, item) => {
        acc[item._id] = {
          total: item.totalCount,
          categories: item.categories
        };
        return acc;
      }, {});
      
    } catch (error) {
      logger.error('Failed to get security events summary:', error);
      return {};
    }
  }
  
  /**
   * Clean up old logs
   */
  async cleanupOldLogs() {
    try {
      const cutoffDate = new Date(Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000);
      
      if (this.config.enableDatabaseLogging) {
        const result = await AuditLog.deleteMany({
          timestamp: { $lt: cutoffDate }
        });
        
        logger.info(`Cleaned up ${result.deletedCount} old audit logs from database`);
      }
      
      // Clean up old log files
      if (this.config.enableFileLogging) {
        await this.cleanupOldLogFiles(cutoffDate);
      }
      
    } catch (error) {
      logger.error('Failed to cleanup old audit logs:', error);
    }
  }
  
  /**
   * Clean up old log files
   */
  async cleanupOldLogFiles(cutoffDate) {
    try {
      const files = await fs.readdir(this.logDir);
      let deletedCount = 0;
      
      for (const file of files) {
        if (!file.startsWith('audit-') || !file.endsWith('.log')) continue;
        
        const filePath = path.join(this.logDir, file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
          deletedCount++;
        }
      }
      
      logger.info(`Cleaned up ${deletedCount} old audit log files`);
      
    } catch (error) {
      logger.error('Failed to cleanup old log files:', error);
    }
  }
  
  /**
   * Generate audit report
   */
  async generateAuditReport(options = {}) {
    if (!this.config.enableDatabaseLogging) {
      return { error: 'Database logging not enabled' };
    }
    
    try {
      const {
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
        endDate = new Date(),
        types = ['SECURITY_EVENT', 'SYSTEM_EVENT', 'USER_ACTION'],
        severities = ['low', 'medium', 'high', 'critical']
      } = options;
      
      const report = {
        period: {
          start: startDate.toISOString(),
          end: endDate.toISOString()
        },
        summary: {},
        topEvents: {},
        trends: {}
      };
      
      // Get summary by type and severity
      report.summary = await AuditLog.aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
            type: { $in: types },
            severity: { $in: severities }
          }
        },
        {
          $group: {
            _id: {
              type: '$type',
              severity: '$severity'
            },
            count: { $sum: 1 }
          }
        }
      ]);
      
      // Get top events by frequency
      report.topEvents = await AuditLog.aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
            type: { $in: types }
          }
        },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 },
            latestOccurrence: { $max: '$timestamp' }
          }
        },
        {
          $sort: { count: -1 }
        },
        {
          $limit: 20
        }
      ]);
      
      // Get daily trends
      report.trends = await AuditLog.aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate },
            type: { $in: types }
          }
        },
        {
          $group: {
            _id: {
              date: {
                $dateToString: {
                  format: "%Y-%m-%d",
                  date: "$timestamp"
                }
              },
              severity: '$severity'
            },
            count: { $sum: 1 }
          }
        },
        {
          $sort: { '_id.date': 1 }
        }
      ]);
      
      return report;
      
    } catch (error) {
      logger.error('Failed to generate audit report:', error);
      return { error: error.message };
    }
  }
  
  /**
   * Shutdown audit logger
   */
  async shutdown() {
    try {
      logger.info('Shutting down audit logger...');
      
      // Process remaining logs
      await this.processLogQueue();
      
      // Close file stream
      if (this.fileWriteStream) {
        this.fileWriteStream.end();
        this.fileWriteStream = null;
      }
      
      this.initialized = false;
      logger.info('Audit logger shut down successfully');
      
    } catch (error) {
      logger.error('Error shutting down audit logger:', error);
    }
  }
}

// Export singleton instance
module.exports = new AuditLogger();
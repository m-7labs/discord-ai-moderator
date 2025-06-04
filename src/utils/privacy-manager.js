const crypto = require('crypto');
const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');
const logger = require('./logger');
const AuditLogger = require('./auditLogger');

/**
 * Privacy Request Schema for tracking data requests
 */
const PrivacyRequestSchema = new mongoose.Schema({
  requestId: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  serverId: { type: String, index: true },
  requestType: { 
    type: String, 
    required: true, 
    enum: ['access', 'portability', 'deletion', 'rectification', 'restriction', 'objection'],
    index: true 
  },
  status: { 
    type: String, 
    required: true, 
    enum: ['pending', 'processing', 'completed', 'rejected', 'expired'],
    default: 'pending',
    index: true 
  },
  requestedAt: { type: Date, required: true, default: Date.now, index: true },
  processedAt: { type: Date },
  completedAt: { type: Date },
  expiresAt: { type: Date, index: true },
  requesterInfo: {
    ipAddress: String,
    userAgent: String,
    verificationMethod: String
  },
  processingNotes: [String],
  dataExportPath: String,
  verificationCode: String,
  adminUserId: String,
  createdAt: { type: Date, default: Date.now }
});

// TTL index for expired requests
PrivacyRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const PrivacyRequest = mongoose.model('PrivacyRequest', PrivacyRequestSchema);

/**
 * Anonymized Data Schema for storing anonymized user data
 */
const AnonymizedDataSchema = new mongoose.Schema({
  originalUserId: { type: String, required: true, index: true },
  anonymizedId: { type: String, required: true, unique: true, index: true },
  serverId: { type: String, required: true, index: true },
  dataType: { 
    type: String, 
    required: true, 
    enum: ['user_profile', 'violation_logs', 'message_content', 'analytics'],
    index: true 
  },
  anonymizedData: { type: mongoose.Schema.Types.Mixed },
  anonymizationMethod: { type: String, required: true },
  anonymizedAt: { type: Date, required: true, default: Date.now, index: true },
  retentionUntil: { type: Date, index: true },
  checksum: String
});

const AnonymizedData = mongoose.model('AnonymizedData', AnonymizedDataSchema);

/**
 * Data Retention Policy Schema
 */
const DataRetentionPolicySchema = new mongoose.Schema({
  policyId: { type: String, required: true, unique: true },
  serverId: { type: String, required: true, index: true },
  dataType: { type: String, required: true },
  retentionPeriod: { type: Number, required: true }, // days
  autoDelete: { type: Boolean, default: true },
  anonymizeBeforeDelete: { type: Boolean, default: true },
  legalBasis: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const DataRetentionPolicy = mongoose.model('DataRetentionPolicy', DataRetentionPolicySchema);

/**
 * Enhanced Privacy Manager with GDPR compliance
 */
class PrivacyManager {
  constructor() {
    this.initialized = false;
    this.config = {
      encryptionKey: null,
      dataRetentionDays: 365,
      anonymizationEnabled: true,
      exportFormat: 'json',
      maxExportSize: 100 * 1024 * 1024, // 100MB
      requestExpiry: 30 * 24 * 60 * 60 * 1000, // 30 days
      autoProcessing: false,
      complianceMode: 'strict'
    };
    this.encryptionAlgorithm = 'aes-256-gcm';
    this.anonymizationMethods = {
      'hash': this.hashAnonymization.bind(this),
      'generalize': this.generalizeData.bind(this),
      'suppress': this.suppressData.bind(this),
      'perturb': this.perturbData.bind(this)
    };
    this.exportDir = path.join(__dirname, '..', '..', 'exports');
    this.stats = {
      requestsReceived: 0,
      requestsProcessed: 0,
      dataExports: 0,
      deletions: 0,
      anonymizations: 0,
      errors: 0
    };
  }
  
  /**
   * Initialize Privacy Manager
   */
  async initialize(options = {}) {
    try {
      this.config = { ...this.config, ...options };
      
      // Initialize encryption key
      if (options.encryptionKey) {
        this.config.encryptionKey = Buffer.from(options.encryptionKey, 'hex');
      } else if (process.env.ENCRYPTION_KEY) {
        this.config.encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
      } else {
        this.config.encryptionKey = crypto.randomBytes(32);
        logger.warn('No encryption key provided, generated random key (not recommended for production)');
      }
      
      // Create export directory
      await fs.mkdir(this.exportDir, { recursive: true, mode: 0o750 });
      
      // Initialize default retention policies
      await this.initializeDefaultPolicies();
      
      // Start background tasks
      this.startBackgroundTasks();
      
      this.initialized = true;
      
      await AuditLogger.logSystemEvent({
        type: 'PRIVACY_MANAGER_INITIALIZED',
        config: {
          dataRetentionDays: this.config.dataRetentionDays,
          anonymizationEnabled: this.config.anonymizationEnabled,
          complianceMode: this.config.complianceMode
        },
        timestamp: Date.now()
      });
      
      logger.info('Privacy Manager initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize Privacy Manager:', error);
      throw error;
    }
  }
  
  /**
   * Initialize default data retention policies
   */
  async initializeDefaultPolicies() {
    const defaultPolicies = [
      {
        policyId: 'default_user_data',
        serverId: 'global',
        dataType: 'user_data',
        retentionPeriod: this.config.dataRetentionDays,
        autoDelete: true,
        anonymizeBeforeDelete: true,
        legalBasis: 'legitimate_interest'
      },
      {
        policyId: 'default_violation_logs',
        serverId: 'global',
        dataType: 'violation_logs',
        retentionPeriod: 90,
        autoDelete: false,
        anonymizeBeforeDelete: true,
        legalBasis: 'legitimate_interest'
      },
      {
        policyId: 'default_audit_logs',
        serverId: 'global',
        dataType: 'audit_logs',
        retentionPeriod: 365,
        autoDelete: true,
        anonymizeBeforeDelete: false,
        legalBasis: 'legal_obligation'
      }
    ];
    
    for (const policy of defaultPolicies) {
      await DataRetentionPolicy.findOneAndUpdate(
        { policyId: policy.policyId, serverId: policy.serverId },
        { ...policy, updatedAt: new Date() },
        { upsert: true }
      );
    }
  }
  
  /**
   * Start background tasks for data retention and cleanup
   */
  startBackgroundTasks() {
    // Daily compliance check
    setInterval(async () => {
      await this.runComplianceCheck();
    }, 24 * 60 * 60 * 1000); // Daily
    
    // Process pending requests every hour
    setInterval(async () => {
      await this.processPendingRequests();
    }, 60 * 60 * 1000); // Hourly
    
    // Cleanup expired exports daily
    setInterval(async () => {
      await this.cleanupExpiredExports();
    }, 24 * 60 * 60 * 1000); // Daily
  }
  
  /**
   * Handle data subject request
   */
  async handleDataRequest(userId, requestType, options = {}) {
    try {
      if (!this.initialized) {
        throw new Error('Privacy Manager not initialized');
      }
      
      const allowedTypes = ['access', 'portability', 'deletion', 'rectification', 'restriction', 'objection'];
      if (!allowedTypes.includes(requestType)) {
        throw new Error('Invalid request type');
      }
      
      // Generate request ID and verification code
      const requestId = crypto.randomUUID();
      const verificationCode = crypto.randomBytes(16).toString('hex');
      
      // Create privacy request
      const request = new PrivacyRequest({
        requestId,
        userId,
        serverId: options.serverId,
        requestType,
        expiresAt: new Date(Date.now() + this.config.requestExpiry),
        requesterInfo: {
          ipAddress: options.ipAddress ? this.hashIP(options.ipAddress) : null,
          userAgent: options.userAgent,
          verificationMethod: options.verificationMethod || 'discord_auth'
        },
        verificationCode,
        processingNotes: [`Request created via ${options.source || 'API'}`]
      });
      
      await request.save();
      this.stats.requestsReceived++;
      
      // Log the request
      await AuditLogger.log({
        action: 'DATA_REQUEST_CREATED',
        userId,
        requestId,
        requestType,
        serverId: options.serverId,
        timestamp: Date.now(),
        ip: options.ipAddress,
        userAgent: options.userAgent
      });
      
      // Auto-process if enabled
      if (this.config.autoProcessing && ['access', 'portability'].includes(requestType)) {
        await this.processDataRequest(requestId);
      }
      
      return {
        requestId,
        verificationCode,
        status: 'pending',
        expiresAt: request.expiresAt,
        estimatedCompletion: this.estimateCompletion(requestType)
      };
      
    } catch (error) {
      this.stats.errors++;
      logger.error('Failed to handle data request:', error);
      throw error;
    }
  }
  
  /**
   * Process a data request
   */
  async processDataRequest(requestId, adminUserId = null) {
    try {
      const request = await PrivacyRequest.findOne({ requestId });
      if (!request) {
        throw new Error('Request not found');
      }
      
      if (request.status !== 'pending') {
        throw new Error('Request is not in pending status');
      }
      
      // Update status to processing
      request.status = 'processing';
      request.processedAt = new Date();
      request.adminUserId = adminUserId;
      request.processingNotes.push(`Processing started by ${adminUserId || 'system'}`);
      await request.save();
      
      let result;
      
      switch (request.requestType) {
        case 'access':
          result = await this.generateDataReport(request);
          break;
        case 'portability':
          result = await this.exportUserData(request);
          break;
        case 'deletion':
          result = await this.deleteUserData(request);
          break;
        case 'rectification':
          result = await this.enableDataRectification(request);
          break;
        case 'restriction':
          result = await this.restrictDataProcessing(request);
          break;
        case 'objection':
          result = await this.handleProcessingObjection(request);
          break;
        default:
          throw new Error('Unsupported request type');
      }
      
      // Update request as completed
      request.status = 'completed';
      request.completedAt = new Date();
      request.processingNotes.push('Request completed successfully');
      
      if (result.exportPath) {
        request.dataExportPath = result.exportPath;
      }
      
      await request.save();
      this.stats.requestsProcessed++;
      
      await AuditLogger.log({
        action: 'DATA_REQUEST_COMPLETED',
        userId: request.userId,
        requestId,
        requestType: request.requestType,
        result: result.summary,
        timestamp: Date.now()
      });
      
      return result;
      
    } catch (error) {
      // Update request status to rejected
      try {
        await PrivacyRequest.findOneAndUpdate(
          { requestId },
          { 
            status: 'rejected',
            $push: { processingNotes: `Error: ${error.message}` }
          }
        );
      } catch (updateError) {
        logger.error('Failed to update request status:', updateError);
      }
      
      this.stats.errors++;
      logger.error('Failed to process data request:', error);
      throw error;
    }
  }
  
  /**
   * Generate comprehensive data report for access request
   */
  async generateDataReport(request) {
    const UserData = mongoose.model('UserData');
    const ViolationLog = mongoose.model('ViolationLog');
    const ServerConfig = mongoose.model('ServerConfig');
    
    // Collect all user data
    const userData = await UserData.findOne({ 
      userId: request.userId,
      serverId: request.serverId 
    }).lean();
    
    const violations = await ViolationLog.find({ 
      userId: request.userId,
      serverId: request.serverId 
    }).lean();
    
    const serverConfigs = await ServerConfig.find({
      serverId: request.serverId
    }).select('rules channels createdAt updatedAt').lean();
    
    // Format report
    const report = {
      generatedAt: new Date().toISOString(),
      requestId: request.requestId,
      userId: request.userId,
      serverId: request.serverId,
      userData: this.sanitizeForReport(userData),
      violations: violations.map(v => this.sanitizeForReport(v)),
      serverSettings: serverConfigs.map(c => ({
        hasCustomRules: !!c.rules && c.rules !== 'Be respectful to others.',
        monitoredChannels: c.channels ? c.channels.length : 0,
        configuredAt: c.createdAt,
        lastUpdated: c.updatedAt
      })),
      dataCategories: {
        personalData: !!userData,
        behavioralData: violations.length > 0,
        technicalData: true,
        usageData: violations.length > 0
      },
      dataProcessingPurposes: [
        'Community moderation',
        'Rule enforcement',
        'Analytics and improvement',
        'Legal compliance'
      ],
      retentionPeriods: await this.getApplicableRetentionPeriods(request.serverId),
      yourRights: {
        access: 'You can request access to your personal data',
        rectification: 'You can request correction of inaccurate data',
        erasure: 'You can request deletion of your data',
        restriction: 'You can request restriction of processing',
        portability: 'You can request your data in a portable format',
        objection: 'You can object to certain types of processing'
      }
    };
    
    // Encrypt sensitive data
    const encrypted = await this.encryptData(report);
    
    // Store encrypted report
    const exportPath = await this.storeDataExport(request.requestId, encrypted, 'access_report');
    
    return {
      exportPath,
      summary: {
        dataPoints: Object.keys(report.userData || {}).length,
        violations: violations.length,
        reportSize: JSON.stringify(report).length
      }
    };
  }
  
  /**
   * Export user data for portability request
   */
  async exportUserData(request) {
    const report = await this.generateDataReport(request);
    
    // Create portable format (JSON)
    const portableData = {
      exportedAt: new Date().toISOString(),
      format: 'JSON',
      version: '1.0',
      userId: request.userId,
      serverId: request.serverId,
      data: report
    };
    
    const exportPath = await this.storeDataExport(
      request.requestId, 
      portableData, 
      'data_export'
    );
    
    this.stats.dataExports++;
    
    return {
      exportPath,
      format: 'JSON',
      summary: {
        totalRecords: report.summary.dataPoints + report.summary.violations,
        exportSize: JSON.stringify(portableData).length
      }
    };
  }
  
  /**
   * Delete user data (right to erasure)
   */
  async deleteUserData(request) {
    const UserData = mongoose.model('UserData');
    const ViolationLog = mongoose.model('ViolationLog');
    
    let deletedRecords = 0;
    let anonymizedRecords = 0;
    
    // Check if data can be deleted or must be anonymized
    const retentionPolicies = await this.getApplicableRetentionPolicies(request.serverId);
    
    for (const policy of retentionPolicies) {
      if (policy.legalBasis === 'legal_obligation') {
        // Cannot delete data required for legal compliance, anonymize instead
        if (policy.dataType === 'violation_logs') {
          const count = await this.anonymizeUserViolationData(request.userId, request.serverId);
          anonymizedRecords += count;
        }
      } else {
        // Can delete data not required for legal compliance
        if (policy.dataType === 'user_data') {
          const result = await UserData.deleteMany({
            userId: request.userId,
            serverId: request.serverId
          });
          deletedRecords += result.deletedCount;
        }
      }
    }
    
    this.stats.deletions++;
    
    await AuditLogger.log({
      action: 'USER_DATA_DELETED',
      userId: request.userId,
      serverId: request.serverId,
      deletedRecords,
      anonymizedRecords,
      timestamp: Date.now()
    });
    
    return {
      summary: {
        deletedRecords,
        anonymizedRecords,
        message: anonymizedRecords > 0 ? 
          'Some data was anonymized instead of deleted due to legal requirements' :
          'All requested data has been deleted'
      }
    };
  }
  
  /**
   * Anonymize user data
   */
  async anonymizeUserData(userId, options = {}) {
    try {
      const UserData = mongoose.model('UserData');
      const ViolationLog = mongoose.model('ViolationLog');
      
      // Get user data
      const userData = await UserData.findOne({ 
        userId,
        serverId: options.serverId 
      });
      
      if (!userData) {
        return { message: 'No user data found' };
      }
      
      // Generate anonymized ID
      const anonymizedId = crypto.createHash('sha256')
        .update(userId + Date.now().toString())
        .digest('hex');
      
      // Anonymize user profile data
      const anonymizedUserData = {
        userId: anonymizedId,
        serverId: userData.serverId,
        joinedAt: userData.joinedAt,
        violations: {
          total: userData.totalViolations,
          recent: userData.recentViolations
        },
        isAnonymized: true,
        anonymizedAt: Date.now()
      };
      
      // Store anonymized data
      await AnonymizedData.create({
        originalUserId: userId,
        anonymizedId,
        serverId: userData.serverId,
        dataType: 'user_profile',
        anonymizedData: anonymizedUserData,
        anonymizationMethod: 'hash',
        checksum: this.calculateChecksum(anonymizedUserData)
      });
      
      // Anonymize violation logs
      const violationCount = await this.anonymizeUserViolationData(userId, userData.serverId);
      
      // Delete or update original based on options
      if (options.deleteOriginal !== false) {
        await UserData.deleteOne({ userId, serverId: userData.serverId });
      } else {
        userData.isAnonymized = true;
        userData.anonymizedAt = new Date();
        await userData.save();
      }
      
      this.stats.anonymizations++;
      
      await AuditLogger.log({
        action: 'USER_DATA_ANONYMIZED',
        userId,
        anonymizedId,
        violationCount,
        timestamp: Date.now()
      });
      
      return {
        anonymizedId,
        violationCount,
        message: 'User data successfully anonymized'
      };
      
    } catch (error) {
      logger.error('Failed to anonymize user data:', error);
      throw error;
    }
  }
  
  /**
   * Anonymize user violation data
   */
  async anonymizeUserViolationData(userId, serverId) {
    const ViolationLog = mongoose.model('ViolationLog');
    
    const violations = await ViolationLog.find({ userId, serverId });
    let count = 0;
    
    for (const violation of violations) {
      const anonymizedData = {
        serverId: violation.serverId,
        messageId: this.hashAnonymization(violation.messageId),
        channelId: this.hashAnonymization(violation.channelId),
        content: this.anonymizeContent(violation.content),
        isViolation: violation.isViolation,
        category: violation.category,
        severity: violation.severity,
        confidence: violation.confidence,
        actionTaken: violation.actionTaken,
        timestamp: violation.createdAt
      };
      
      await AnonymizedData.create({
        originalUserId: userId,
        anonymizedId: this.hashAnonymization(userId),
        serverId,
        dataType: 'violation_logs',
        anonymizedData,
        anonymizationMethod: 'hash_and_generalize',
        checksum: this.calculateChecksum(anonymizedData)
      });
      
      count++;
    }
    
    return count;
  }
  
  /**
   * Anonymization methods
   */
  hashAnonymization(value) {
    return crypto.createHash('sha256')
      .update(value + this.config.encryptionKey.toString('hex'))
      .digest('hex').substring(0, 16);
  }
  
  generalizeData(value, type) {
    switch (type) {
      case 'timestamp':
        // Generalize to day level
        return new Date(value).toISOString().split('T')[0];
      case 'confidence':
        // Round to nearest 0.1
        return Math.round(value * 10) / 10;
      default:
        return value;
    }
  }
  
  suppressData(value, suppressionRate = 0.1) {
    // Randomly suppress some data points
    return Math.random() < suppressionRate ? null : value;
  }
  
  perturbData(value, noise = 0.05) {
    if (typeof value === 'number') {
      const perturbation = (Math.random() - 0.5) * 2 * noise * value;
      return value + perturbation;
    }
    return value;
  }
  
  anonymizeContent(content) {
    if (!content || typeof content !== 'string') return '[REDACTED]';
    
    // Replace with content length and basic characteristics
    return `[MESSAGE: ${content.length} chars, ${content.split(' ').length} words]`;
  }
  
  /**
   * Encrypt data for secure storage
   */
  async encryptData(data) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(this.encryptionAlgorithm, this.config.encryptionKey, iv);
      
      const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(data), 'utf8'),
        cipher.final()
      ]);
      
      const authTag = cipher.getAuthTag();
      
      return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        algorithm: this.encryptionAlgorithm
      };
    } catch (error) {
      logger.error('Failed to encrypt data:', error);
      throw error;
    }
  }
  
  /**
   * Decrypt data
   */
  async decryptData(encryptedData) {
    try {
      const decipher = crypto.createDecipher(
        encryptedData.algorithm,
        this.config.encryptionKey,
        Buffer.from(encryptedData.iv, 'base64')
      );
      
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'base64'));
      
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedData.encrypted, 'base64')),
        decipher.final()
      ]);
      
      return JSON.parse(decrypted.toString('utf8'));
    } catch (error) {
      logger.error('Failed to decrypt data:', error);
      throw error;
    }
  }
  
  /**
   * Store data export securely
   */
  async storeDataExport(requestId, data, type) {
    try {
      const filename = `${type}_${requestId}_${Date.now()}.json`;
      const filepath = path.join(this.exportDir, filename);
      
      // Encrypt data before storage
      const encryptedData = await this.encryptData(data);
      
      await fs.writeFile(filepath, JSON.stringify(encryptedData, null, 2), {
        mode: 0o640
      });
      
      // Create access log
      await fs.writeFile(
        filepath + '.log',
        JSON.stringify({
          createdAt: new Date().toISOString(),
          requestId,
          type,
          fileSize: (await fs.stat(filepath)).size,
          checksum: this.calculateFileChecksum(filepath)
        }, null, 2)
      );
      
      return filepath;
    } catch (error) {
      logger.error('Failed to store data export:', error);
      throw error;
    }
  }
  
  /**
   * Calculate checksum for data integrity
   */
  calculateChecksum(data) {
    return crypto.createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
  }
  
  /**
   * Calculate file checksum
   */
  async calculateFileChecksum(filepath) {
    const content = await fs.readFile(filepath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }
  
  /**
   * Hash IP address for privacy
   */
  hashIP(ip) {
    return crypto.createHash('sha256')
      .update(ip + this.config.encryptionKey.toString('hex'))
      .digest('hex').substring(0, 16);
  }
  
  /**
   * Sanitize data for reporting
   */
  sanitizeForReport(data) {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = { ...data };
    const sensitiveFields = ['_id', '__v', 'encryptedData', 'signature'];
    
    for (const field of sensitiveFields) {
      delete sanitized[field];
    }
    
    return sanitized;
  }
  
  /**
   * Get applicable retention policies
   */
  async getApplicableRetentionPolicies(serverId) {
    return await DataRetentionPolicy.find({
      $or: [
        { serverId },
        { serverId: 'global' }
      ]
    }).sort({ serverId: -1 }); // Server-specific policies override global
  }
  
  /**
   * Get retention periods for report
   */
  async getApplicableRetentionPeriods(serverId) {
    const policies = await this.getApplicableRetentionPolicies(serverId);
    
    return policies.reduce((acc, policy) => {
      acc[policy.dataType] = {
        period: policy.retentionPeriod,
        autoDelete: policy.autoDelete,
        legalBasis: policy.legalBasis
      };
      return acc;
    }, {});
  }
  
  /**
   * Estimate completion time for requests
   */
  estimateCompletion(requestType) {
    const estimates = {
      access: '1-2 business days',
      portability: '2-3 business days',
      deletion: '3-5 business days',
      rectification: '5-7 business days',
      restriction: '1-2 business days',
      objection: '2-3 business days'
    };
    
    return estimates[requestType] || '3-5 business days';
  }
  
  /**
   * Enable data rectification
   */
  async enableDataRectification(request) {
    // This would typically involve providing a mechanism for users
    // to correct their data. For now, we'll log the request.
    
    await AuditLogger.log({
      action: 'DATA_RECTIFICATION_ENABLED',
      userId: request.userId,
      requestId: request.requestId,
      timestamp: Date.now()
    });
    
    return {
      summary: {
        message: 'Data rectification process initiated. You will be contacted with further instructions.'
      }
    };
  }
  
  /**
   * Restrict data processing
   */
  async restrictDataProcessing(request) {
    const UserData = mongoose.model('UserData');
    
    // Mark user data as restricted
    await UserData.findOneAndUpdate(
      { userId: request.userId, serverId: request.serverId },
      { 
        processingRestricted: true,
        restrictionDate: new Date(),
        restrictionReason: 'user_request'
      }
    );
    
    await AuditLogger.log({
      action: 'DATA_PROCESSING_RESTRICTED',
      userId: request.userId,
      serverId: request.serverId,
      timestamp: Date.now()
    });
    
    return {
      summary: {
        message: 'Data processing has been restricted as requested.'
      }
    };
  }
  
  /**
   * Handle processing objection
   */
  async handleProcessingObjection(request) {
    // Similar to restriction but for objection to processing
    
    await AuditLogger.log({
      action: 'PROCESSING_OBJECTION_HANDLED',
      userId: request.userId,
      requestId: request.requestId,
      timestamp: Date.now()
    });
    
    return {
      summary: {
        message: 'Your objection to data processing has been recorded and will be reviewed.'
      }
    };
  }
  
  /**
   * Process pending requests
   */
  async processPendingRequests() {
    if (!this.config.autoProcessing) return;
    
    try {
      const pendingRequests = await PrivacyRequest.find({
        status: 'pending',
        expiresAt: { $gt: new Date() }
      }).limit(10);
      
      for (const request of pendingRequests) {
        try {
          await this.processDataRequest(request.requestId);
        } catch (error) {
          logger.error(`Failed to auto-process request ${request.requestId}:`, error);
        }
      }
    } catch (error) {
      logger.error('Failed to process pending requests:', error);
    }
  }
  
  /**
   * Run compliance check
   */
  async runComplianceCheck() {
    try {
      logger.info('Running privacy compliance check...');
      
      const issues = [];
      
      // Check for data retention violations
      const policies = await DataRetentionPolicy.find({ autoDelete: true });
      
      for (const policy of policies) {
        const cutoffDate = new Date(Date.now() - policy.retentionPeriod * 24 * 60 * 60 * 1000);
        
        if (policy.dataType === 'user_data') {
          const UserData = mongoose.model('UserData');
          const expiredData = await UserData.countDocuments({
            createdAt: { $lt: cutoffDate },
            isAnonymized: { $ne: true }
          });
          
          if (expiredData > 0) {
            issues.push({
              type: 'retention_violation',
              dataType: policy.dataType,
              expiredRecords: expiredData,
              policy: policy.policyId
            });
          }
        }
      }
      
      // Check for unprocessed requests
      const expiredRequests = await PrivacyRequest.countDocuments({
        status: 'pending',
        expiresAt: { $lt: new Date() }
      });
      
      if (expiredRequests > 0) {
        issues.push({
          type: 'expired_requests',
          count: expiredRequests
        });
      }
      
      await AuditLogger.logSystemEvent({
        type: 'PRIVACY_COMPLIANCE_CHECK',
        issues,
        timestamp: Date.now()
      });
      
      if (issues.length > 0) {
        logger.warn('Privacy compliance issues found:', issues);
      } else {
        logger.info('Privacy compliance check passed');
      }
      
      return issues;
      
    } catch (error) {
      logger.error('Privacy compliance check failed:', error);
      throw error;
    }
  }
  
  /**
   * Cleanup expired exports
   */
  async cleanupExpiredExports() {
    try {
      const files = await fs.readdir(this.exportDir);
      const expiredFiles = [];
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const filepath = path.join(this.exportDir, file);
        const stats = await fs.stat(filepath);
        const age = Date.now() - stats.mtime.getTime();
        
        // Delete exports older than 30 days
        if (age > 30 * 24 * 60 * 60 * 1000) {
          await fs.unlink(filepath);
          
          // Also delete log file
          try {
            await fs.unlink(filepath + '.log');
          } catch (error) {
            // Log file might not exist
          }
          
          expiredFiles.push(file);
        }
      }
      
      if (expiredFiles.length > 0) {
        logger.info(`Cleaned up ${expiredFiles.length} expired data exports`);
      }
      
    } catch (error) {
      logger.error('Failed to cleanup expired exports:', error);
    }
  }
  
  /**
   * Get privacy statistics
   */
  getStats() {
    return {
      ...this.stats,
      isInitialized: this.initialized,
      config: {
        dataRetentionDays: this.config.dataRetentionDays,
        anonymizationEnabled: this.config.anonymizationEnabled,
        autoProcessing: this.config.autoProcessing,
        complianceMode: this.config.complianceMode
      }
    };
  }
  
  /**
   * Shutdown privacy manager
   */
  async shutdown() {
    try {
      logger.info('Shutting down Privacy Manager...');
      
      this.initialized = false;
      
      await AuditLogger.logSystemEvent({
        type: 'PRIVACY_MANAGER_SHUTDOWN',
        stats: this.getStats(),
        timestamp: Date.now()
      });
      
      logger.info('Privacy Manager shut down successfully');
      
    } catch (error) {
      logger.error('Error shutting down Privacy Manager:', error);
    }
  }
}

// Export singleton instance
module.exports = new PrivacyManager();
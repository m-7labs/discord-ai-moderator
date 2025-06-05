const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./utils/logger');
const errorManager = require('./utils/error-manager');

let db = null;

// Initialize SQLite database
function setupDatabase() {
  return new Promise((resolve, reject) => {
    try {
      const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'data', 'discord-ai-mod.db');
      
      // Ensure data directory exists
      const dataDir = path.dirname(dbPath);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      // Initialize database connection
      db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
          logger.error('Failed to connect to SQLite database', { error: err.message });
          reject(err);
          return;
        }

        // Enable WAL mode
        db.run("PRAGMA journal_mode = WAL");
        db.run("PRAGMA synchronous = NORMAL");
        db.run("PRAGMA cache_size = 10000");
        db.run("PRAGMA temp_store = memory");

        // Create tables
        createTables(() => {
          logger.info('SQLite database initialized successfully', { path: dbPath });
          resolve({ success: true, path: dbPath });
        });
      });
    } catch (error) {
      logger.error('Failed to initialize SQLite database', { error: error.message });
      reject(error);
    }
  });
}

// Create database tables
function createTables(callback) {
  const tables = [
    // Server Configuration Table
    `CREATE TABLE IF NOT EXISTS server_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id TEXT NOT NULL UNIQUE,
      enabled BOOLEAN DEFAULT 1,
      channels TEXT,
      rules TEXT,
      strictness INTEGER DEFAULT 5,
      custom_keywords TEXT,
      exempt_roles TEXT,
      moderator_roles TEXT,
      auto_action BOOLEAN DEFAULT 0,
      action_threshold INTEGER DEFAULT 3,
      notification_channel TEXT,
      log_channel TEXT,
      data_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT valid_strictness CHECK (strictness >= 1 AND strictness <= 10)
    )`,

    // User Data Table
    `CREATE TABLE IF NOT EXISTS user_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      server_id TEXT NOT NULL,
      is_exempt BOOLEAN DEFAULT 0,
      exempt_until DATETIME,
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      recent_violations INTEGER DEFAULT 0,
      total_violations INTEGER DEFAULT 0,
      last_violation_date DATETIME,
      is_anonymized BOOLEAN DEFAULT 0,
      anonymized_at DATETIME,
      data_retention_expiry DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, server_id)
    )`,

    // Violation Logs Table
    `CREATE TABLE IF NOT EXISTS violation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      channel_id TEXT NOT NULL,
      content TEXT,
      content_hash TEXT,
      is_violation BOOLEAN DEFAULT 0,
      category TEXT,
      severity TEXT,
      confidence_score REAL,
      explanation TEXT,
      suggested_action TEXT,
      action_taken TEXT,
      human_reviewed BOOLEAN DEFAULT 0,
      reviewer_id TEXT,
      review_notes TEXT,
      model_used TEXT,
      provider TEXT,
      tokens_used INTEGER,
      processing_time_ms INTEGER,
      ip_address_hash TEXT,
      session_id TEXT,
      request_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT valid_confidence CHECK (confidence_score >= 0 AND confidence_score <= 1),
      CONSTRAINT valid_provider CHECK (provider IN ('ANTHROPIC', 'OPENROUTER') OR provider IS NULL),
      CONSTRAINT valid_severity CHECK (severity IN ('Low', 'Moderate', 'Severe') OR severity IS NULL)
    )`
  ];

  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_server_configs_server_id ON server_configs(server_id)',
    'CREATE INDEX IF NOT EXISTS idx_user_data_server_user ON user_data(server_id, user_id)',
    'CREATE INDEX IF NOT EXISTS idx_user_data_server_violations ON user_data(server_id, total_violations DESC)',
    'CREATE INDEX IF NOT EXISTS idx_violation_logs_server_created ON violation_logs(server_id, created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_violation_logs_user_created ON violation_logs(user_id, created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_violation_logs_server_violation ON violation_logs(server_id, is_violation, created_at DESC)',
    'CREATE INDEX IF NOT EXISTS idx_violation_logs_content_hash ON violation_logs(content_hash)',
    'CREATE INDEX IF NOT EXISTS idx_violation_logs_request_id ON violation_logs(request_id)'
  ];

  let completed = 0;
  const total = tables.length + indexes.length;

  // Create tables first
  tables.forEach(sql => {
    db.run(sql, (err) => {
      if (err) {
        logger.error('Failed to create table', { error: err.message, sql });
      }
      completed++;
      if (completed === total) {
        logger.info('Database tables and indexes created successfully');
        callback();
      }
    });
  });

  // Then create indexes
  indexes.forEach(sql => {
    db.run(sql, (err) => {
      if (err) {
        logger.error('Failed to create index', { error: err.message, sql });
      }
      completed++;
      if (completed === total) {
        logger.info('Database tables and indexes created successfully');
        callback();
      }
    });
  });
}

// Server Configuration Operations
async function getServerConfig(serverId, options = {}) {
  return new Promise((resolve) => {
    try {
      // Simple validation
      if (!serverId || typeof serverId !== 'string') {
        resolve(null);
        return;
      }

      db.get('SELECT * FROM server_configs WHERE server_id = ?', [serverId], async (err, row) => {
        if (err) {
          logger.error('Failed to get server config', { error: err.message, serverId });
          resolve(null);
          return;
        }

        if (!row) {
          // Create default config
          const config = await createServerConfig(serverId);
          resolve(config);
          return;
        }

        // Parse JSON fields
        try {
          if (row.channels) row.channels = JSON.parse(row.channels);
          if (row.custom_keywords) row.custom_keywords = JSON.parse(row.custom_keywords);
          if (row.exempt_roles) row.exempt_roles = JSON.parse(row.exempt_roles);
          if (row.moderator_roles) row.moderator_roles = JSON.parse(row.moderator_roles);
        } catch (parseErr) {
          logger.error('Failed to parse server config JSON', { error: parseErr.message });
        }

        resolve(row);
      });
    } catch (error) {
      logger.error('Error in getServerConfig', { error: error.message });
      resolve(null);
    }
  });
}

async function createServerConfig(serverId, config = {}) {
  return new Promise((resolve) => {
    try {
      const defaultConfig = {
        server_id: serverId,
        enabled: config.enabled !== undefined ? config.enabled : true,
        channels: JSON.stringify(config.channels || []),
        rules: config.rules || 'Default moderation rules',
        strictness: config.strictness || 5,
        custom_keywords: JSON.stringify(config.customKeywords || []),
        exempt_roles: JSON.stringify(config.exemptRoles || []),
        moderator_roles: JSON.stringify(config.moderatorRoles || []),
        auto_action: config.autoAction || false,
        action_threshold: config.actionThreshold || 3,
        notification_channel: config.notificationChannel || null,
        log_channel: config.logChannel || null
      };

      // Create data hash for integrity
      defaultConfig.data_hash = crypto.createHash('sha256')
        .update(JSON.stringify({
          rules: defaultConfig.rules,
          strictness: defaultConfig.strictness,
          enabled: defaultConfig.enabled
        }))
        .digest('hex');

      const sql = `INSERT INTO server_configs (
        server_id, enabled, channels, rules, strictness, custom_keywords,
        exempt_roles, moderator_roles, auto_action, action_threshold,
        notification_channel, log_channel, data_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      const params = [
        defaultConfig.server_id,
        defaultConfig.enabled,
        defaultConfig.channels,
        defaultConfig.rules,
        defaultConfig.strictness,
        defaultConfig.custom_keywords,
        defaultConfig.exempt_roles,
        defaultConfig.moderator_roles,
        defaultConfig.auto_action,
        defaultConfig.action_threshold,
        defaultConfig.notification_channel,
        defaultConfig.log_channel,
        defaultConfig.data_hash
      ];

      db.run(sql, params, async function(err) {
        if (err) {
          logger.error('Failed to create server config', { error: err.message });
          resolve(null);
          return;
        }

        // Return the created config
        const createdConfig = await getServerConfig(serverId);
        resolve(createdConfig);
      });
    } catch (error) {
      logger.error('Error in createServerConfig', { error: error.message });
      resolve(null);
    }
  });
}

// Violation Logging
async function logViolation(action, options = {}) {
  return new Promise((resolve) => {
    try {
      if (!action.serverId || !action.userId) {
        resolve(null);
        return;
      }

      const sanitizedAction = {
        server_id: action.serverId,
        user_id: action.userId,
        message_id: action.messageId || '',
        channel_id: action.channelId || '',
        content: action.content ? action.content.substring(0, 2000) : null,
        is_violation: Boolean(action.isViolation),
        category: action.category || null,
        severity: action.severity || null,
        confidence_score: typeof action.confidenceScore === 'number' ? 
          Math.max(0, Math.min(1, action.confidenceScore)) : null,
        explanation: action.explanation ? action.explanation.substring(0, 1000) : null,
        suggested_action: action.suggestedAction || null,
        action_taken: action.actionTaken || null,
        human_reviewed: Boolean(action.humanReviewed),
        reviewer_id: action.reviewerId || null,
        review_notes: action.reviewNotes || null,
        model_used: action.modelUsed ? action.modelUsed.substring(0, 100) : null,
        provider: ['ANTHROPIC', 'OPENROUTER'].includes(action.provider) ? action.provider : null,
        tokens_used: typeof action.tokensUsed === 'number' && action.tokensUsed >= 0 ? 
          Math.min(action.tokensUsed, 1000000) : null,
        processing_time_ms: typeof action.processingTimeMs === 'number' && action.processingTimeMs >= 0 ? 
          Math.min(action.processingTimeMs, 300000) : null,
        ip_address_hash: options.ip ? crypto.createHash('sha256').update(options.ip).digest('hex') : null,
        session_id: options.sessionId || null,
        request_id: options.requestId || crypto.randomUUID()
      };

      // Create content hash if content exists
      if (sanitizedAction.content) {
        sanitizedAction.content_hash = crypto.createHash('sha256')
          .update(sanitizedAction.content)
          .digest('hex');
      }

      const sql = `INSERT INTO violation_logs (
        server_id, user_id, message_id, channel_id, content, content_hash,
        is_violation, category, severity, confidence_score, explanation,
        suggested_action, action_taken, human_reviewed, reviewer_id, review_notes,
        model_used, provider, tokens_used, processing_time_ms,
        ip_address_hash, session_id, request_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      const params = [
        sanitizedAction.server_id, sanitizedAction.user_id, sanitizedAction.message_id,
        sanitizedAction.channel_id, sanitizedAction.content, sanitizedAction.content_hash,
        sanitizedAction.is_violation, sanitizedAction.category, sanitizedAction.severity,
        sanitizedAction.confidence_score, sanitizedAction.explanation, sanitizedAction.suggested_action,
        sanitizedAction.action_taken, sanitizedAction.human_reviewed, sanitizedAction.reviewer_id,
        sanitizedAction.review_notes, sanitizedAction.model_used, sanitizedAction.provider,
        sanitizedAction.tokens_used, sanitizedAction.processing_time_ms, sanitizedAction.ip_address_hash,
        sanitizedAction.session_id, sanitizedAction.request_id
      ];

      db.run(sql, params, function(err) {
        if (err) {
          logger.error('Failed to log violation', { error: err.message });
          resolve(null);
          return;
        }

        resolve({ id: this.lastID, ...sanitizedAction });
      });
    } catch (error) {
      logger.error('Error in logViolation', { error: error.message });
      resolve(null);
    }
  });
}

// User Data Operations
async function getUserData(userId, serverId) {
  return new Promise((resolve) => {
    try {
      db.get('SELECT * FROM user_data WHERE user_id = ? AND server_id = ?', [userId, serverId], (err, row) => {
        if (err) {
          logger.error('Failed to get user data', { error: err.message });
          resolve(null);
          return;
        }
        resolve(row);
      });
    } catch (error) {
      logger.error('Error in getUserData', { error: error.message });
      resolve(null);
    }
  });
}

// Get violation logs with pagination
async function getViolationLogs(serverId, options = {}) {
  return new Promise((resolve) => {
    try {
      const limit = Math.min(options.limit || 50, 1000);
      const offset = options.offset || 0;
      
      let whereClause = 'WHERE server_id = ?';
      const params = [serverId];
      
      if (options.userId) {
        whereClause += ' AND user_id = ?';
        params.push(options.userId);
      }
      
      if (options.isViolation !== undefined) {
        whereClause += ' AND is_violation = ?';
        params.push(options.isViolation ? 1 : 0);
      }
      
      params.push(limit, offset);
      
      const sql = `SELECT * FROM violation_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
      
      db.all(sql, params, (err, rows) => {
        if (err) {
          logger.error('Failed to get violation logs', { error: err.message });
          resolve([]);
          return;
        }
        resolve(rows || []);
      });
    } catch (error) {
      logger.error('Error in getViolationLogs', { error: error.message });
      resolve([]);
    }
  });
}

// Database health check
function checkDatabaseHealth() {
  return new Promise((resolve) => {
    if (!db) {
      resolve(false);
      return;
    }
    
    db.get('SELECT 1 as health', (err, row) => {
      if (err) {
        logger.error('Database health check failed', { error: err.message });
        resolve(false);
        return;
      }
      resolve(row && row.health === 1);
    });
  });
}

// Close database connection
function closeDatabase() {
  return new Promise((resolve) => {
    if (db) {
      db.close((err) => {
        if (err) {
          logger.error('Error closing database', { error: err.message });
        } else {
          logger.info('Database connection closed');
        }
        db = null;
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// Cleanup old logs (run periodically)
function cleanupOldLogs() {
  return new Promise((resolve) => {
    try {
      const retentionDays = parseInt(process.env.LOG_RETENTION_DAYS) || 90;
      const sql = `DELETE FROM violation_logs WHERE created_at < datetime('now', '-${retentionDays} days')`;
      
      db.run(sql, function(err) {
        if (err) {
          logger.error('Failed to cleanup old logs', { error: err.message });
        } else if (this.changes > 0) {
          logger.info(`Cleaned up ${this.changes} old violation logs`);
        }
        resolve();
      });
    } catch (error) {
      logger.error('Error in cleanupOldLogs', { error: error.message });
      resolve();
    }
  });
}

module.exports = {
  setupDatabase,
  getServerConfig,
  createServerConfig,
  logViolation,
  getUserData,
  getViolationLogs,
  checkDatabaseHealth,
  closeDatabase,
  cleanupOldLogs
};
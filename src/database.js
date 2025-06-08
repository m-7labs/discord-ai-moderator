const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./utils/logger');
const _errorManager = require('./utils/error-manager');
const AdaptiveQueryOptimizer = require('./utils/adaptive-query-optimizer');
const TieredCache = require('./utils/tiered-cache');

let db = null;
let dbAsync = null;
let queryOptimizer = null;

// Create tiered cache instances
const configCache = new TieredCache({
  namespace: 'server-config',
  l1Capacity: 500,        // L1 cache size (most recently used configs)
  l2TTL: 300000,          // 5 minutes for L2 cache
  l1WritePolicy: 'write-through',
  statsInterval: 600000   // Log stats every 10 minutes
});

const userCache = new TieredCache({
  namespace: 'user-data',
  l1Capacity: 1000,       // L1 cache size (most recently used users)
  l2TTL: 60000,           // 1 minute for L2 cache
  l1WritePolicy: 'write-back',
  l1WriteBackInterval: 10000, // Write back every 10 seconds
  statsInterval: 600000   // Log stats every 10 minutes
});

// Async wrapper for SQLite operations
class AsyncDatabase {
  constructor(database) {
    if (!database) {
      throw new Error('Database instance is required');
    }
    this.db = database;
    this.statements = new Map();
    this.stmtUsageCount = new Map(); // Track usage for potential cleanup
  }

  run(sql, params = []) {
    if (!sql) {
      return Promise.reject(new Error('SQL query is required'));
    }

    return new Promise((resolve, reject) => {
      try {
        this.db.run(sql, params, function (err) {
          if (err) {
            logger.error('SQL run error', { error: err.message, sql });
            reject(err);
          } else {
            resolve({ lastID: this.lastID, changes: this.changes });
          }
        });
      } catch (error) {
        logger.error('Unexpected error in run', { error: error.message, sql });
        reject(error);
      }
    });
  }

  get(sql, params = []) {
    if (!sql) {
      return Promise.reject(new Error('SQL query is required'));
    }

    return new Promise((resolve, reject) => {
      try {
        this.db.get(sql, params, (err, row) => {
          if (err) {
            logger.error('SQL get error', { error: err.message, sql });
            reject(err);
          } else {
            resolve(row);
          }
        });
      } catch (error) {
        logger.error('Unexpected error in get', { error: error.message, sql });
        reject(error);
      }
    });
  }

  all(sql, params = []) {
    if (!sql) {
      return Promise.reject(new Error('SQL query is required'));
    }

    return new Promise((resolve, reject) => {
      try {
        this.db.all(sql, params, (err, rows) => {
          if (err) {
            logger.error('SQL all error', { error: err.message, sql });
            reject(err);
          } else {
            resolve(rows || []);
          }
        });
      } catch (error) {
        logger.error('Unexpected error in all', { error: error.message, sql });
        reject(error);
      }
    });
  }

  prepare(key, sql) {
    if (!key || !sql) {
      throw new Error('Statement key and SQL query are required');
    }

    try {
      if (!this.statements.has(key)) {
        this.statements.set(key, this.db.prepare(sql));
        this.stmtUsageCount.set(key, 0);
      }

      // Increment usage count
      this.stmtUsageCount.set(key, this.stmtUsageCount.get(key) + 1);

      return this.statements.get(key);
    } catch (error) {
      logger.error('Error preparing statement', { error: error.message, key, sql });
      throw error;
    }
  }

  async runPrepared(key, sql, params = []) {
    if (!key || !sql) {
      return Promise.reject(new Error('Statement key and SQL query are required'));
    }

    try {
      const stmt = this.prepare(key, sql);

      return new Promise((resolve, reject) => {
        stmt.run(params, function (err) {
          if (err) {
            logger.error('Prepared statement run error', { error: err.message, key });
            reject(err);
          } else {
            resolve({ lastID: this.lastID, changes: this.changes });
          }
        });
      });
    } catch (error) {
      logger.error('Error in runPrepared', { error: error.message, key });
      return Promise.reject(error);
    } finally {
      this.checkStatementCleanup(key);
    }
  }

  async getPrepared(key, sql, params = []) {
    if (!key || !sql) {
      return Promise.reject(new Error('Statement key and SQL query are required'));
    }

    try {
      const stmt = this.prepare(key, sql);

      return new Promise((resolve, reject) => {
        stmt.get(params, (err, row) => {
          if (err) {
            logger.error('Prepared statement get error', { error: err.message, key });
            reject(err);
          } else {
            resolve(row);
          }
        });
      });
    } catch (error) {
      logger.error('Error in getPrepared', { error: error.message, key });
      return Promise.reject(error);
    } finally {
      this.checkStatementCleanup(key);
    }
  }

  // Check if statement should be cleaned up (after high usage)
  checkStatementCleanup(key) {
    const CLEANUP_THRESHOLD = 1000; // Cleanup after 1000 uses

    if (this.stmtUsageCount.get(key) > CLEANUP_THRESHOLD) {
      try {
        this.finalizeStatement(key);
        // Re-prepare on next use
        this.stmtUsageCount.set(key, 0);
      } catch (error) {
        logger.error('Error in statement cleanup', { error: error.message, key });
      }
    }
  }

  // Finalize a specific prepared statement
  finalizeStatement(key) {
    if (this.statements.has(key)) {
      try {
        this.statements.get(key).finalize();
        this.statements.delete(key);
      } catch (error) {
        logger.error('Error finalizing statement', { error: error.message, key });
      }
    }
  }

  close() {
    try {
      // Finalize all prepared statements
      for (const [key, stmt] of this.statements.entries()) {
        try {
          stmt.finalize();
        } catch (error) {
          logger.error('Error finalizing statement during close', { error: error.message, key });
        }
      }
      this.statements.clear();
      this.stmtUsageCount.clear();
    } catch (error) {
      logger.error('Error in database close', { error: error.message });
    }
  }
}

// Initialize SQLite database
function setupDatabase() {
  return new Promise((resolve, reject) => {
    try {
      const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'data', 'discord-ai-mod.db');

      // Ensure data directory exists
      const dataDir = path.dirname(dbPath);

      // Create directory directly with recursive option
      // This is safer than checking existence first, as it avoids race conditions
      // and doesn't require using existsSync with a dynamic path
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        fs.mkdirSync(dataDir, { recursive: true });
      } catch (dirError) {
        // Only throw if it's not an "already exists" error
        if (dirError.code !== 'EEXIST') {
          logger.error('Failed to create data directory', { error: dirError.message, path: dataDir });
          throw dirError;
        }
      }

      // Initialize database connection
      db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, async (err) => {
        if (err) {
          logger.error('Failed to connect to SQLite database', { error: err.message });
          reject(err);
          return;
        }

        // Create async wrapper
        dbAsync = new AsyncDatabase(db);

        // Initialize query optimizer
        queryOptimizer = new AdaptiveQueryOptimizer({
          highLoadThreshold: 0.6,
          criticalLoadThreshold: 0.85,
          defaultQueryLimit: 1000,
          highLoadQueryLimit: 500,
          criticalLoadQueryLimit: 100,
          slowQueryThreshold: 300, // ms
          enableQueryCache: true
        });

        // Enable optimizations
        await dbAsync.run("PRAGMA journal_mode = WAL");
        await dbAsync.run("PRAGMA synchronous = NORMAL");
        await dbAsync.run("PRAGMA cache_size = 10000");
        await dbAsync.run("PRAGMA temp_store = memory");
        await dbAsync.run("PRAGMA mmap_size = 268435456"); // 256MB memory-mapped I/O
        await dbAsync.run("PRAGMA page_size = 4096");
        await dbAsync.run("PRAGMA optimize");

        // Create tables
        await createTables();

        logger.info('SQLite database initialized successfully', { path: dbPath });
        resolve({ success: true, path: dbPath });
      });
    } catch (error) {
      logger.error('Failed to initialize SQLite database', { error: error.message });
      reject(error);
    }
  });
}

// Create database tables
async function createTables() {
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

  try {
    // Create tables first
    for (const sql of tables) {
      try {
        await dbAsync.run(sql);
      } catch (err) {
        logger.error('Failed to create table', { error: err.message });
      }
    }

    // Then create indexes
    for (const sql of indexes) {
      try {
        await dbAsync.run(sql);
      } catch (err) {
        logger.error('Failed to create index', { error: err.message });
      }
    }

    logger.info('Database tables and indexes created successfully');
  } catch (error) {
    logger.error('Error creating database structure', { error: error.message });
    throw error;
  }
}

// Server Configuration Operations
async function getServerConfig(serverId, _options = {}) {
  try {
    // Enhanced validation
    if (!serverId || typeof serverId !== 'string' || serverId.trim() === '') {
      logger.warn('Invalid server ID provided to getServerConfig', { serverId });
      return null;
    }

    // Sanitize server ID (remove any potential SQL injection characters)
    const sanitizedServerId = serverId.replace(/[^\w-]/g, '');
    if (sanitizedServerId !== serverId) {
      logger.warn('Server ID contained invalid characters', { original: serverId, sanitized: sanitizedServerId });
    }

    // Check cache first - using direct key without namespace prefix (handled by TieredCache)
    const cacheKey = `config:${sanitizedServerId}`;
    const cached = configCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const row = await dbAsync.getPrepared(
      'getServerConfig',
      'SELECT * FROM server_configs WHERE server_id = ?',
      [sanitizedServerId]
    );

    if (!row) {
      // Create default config
      logger.info('No configuration found, creating default', { serverId: sanitizedServerId });
      const config = await createServerConfig(sanitizedServerId);
      return config;
    }

    // Parse JSON fields with validation - handle each field explicitly to avoid object injection
    const parsedRow = { ...row };

    // Safely parse channels
    try {
      parsedRow.channels = parsedRow.channels ?
        (Array.isArray(JSON.parse(parsedRow.channels)) ? JSON.parse(parsedRow.channels) : []) :
        [];
    } catch (parseErr) {
      logger.error('Failed to parse channels JSON', {
        error: parseErr.message,
        serverId: sanitizedServerId
      });
      parsedRow.channels = [];
    }

    // Safely parse custom_keywords
    try {
      parsedRow.custom_keywords = parsedRow.custom_keywords ?
        (Array.isArray(JSON.parse(parsedRow.custom_keywords)) ? JSON.parse(parsedRow.custom_keywords) : []) :
        [];
    } catch (parseErr) {
      logger.error('Failed to parse custom_keywords JSON', {
        error: parseErr.message,
        serverId: sanitizedServerId
      });
      parsedRow.custom_keywords = [];
    }

    // Safely parse exempt_roles
    try {
      parsedRow.exempt_roles = parsedRow.exempt_roles ?
        (Array.isArray(JSON.parse(parsedRow.exempt_roles)) ? JSON.parse(parsedRow.exempt_roles) : []) :
        [];
    } catch (parseErr) {
      logger.error('Failed to parse exempt_roles JSON', {
        error: parseErr.message,
        serverId: sanitizedServerId
      });
      parsedRow.exempt_roles = [];
    }

    // Safely parse moderator_roles
    try {
      parsedRow.moderator_roles = parsedRow.moderator_roles ?
        (Array.isArray(JSON.parse(parsedRow.moderator_roles)) ? JSON.parse(parsedRow.moderator_roles) : []) :
        [];
    } catch (parseErr) {
      logger.error('Failed to parse moderator_roles JSON', {
        error: parseErr.message,
        serverId: sanitizedServerId
      });
      parsedRow.moderator_roles = [];
    }

    // Validate numeric fields
    parsedRow.strictness = Number.isInteger(parsedRow.strictness) &&
      parsedRow.strictness >= 1 &&
      parsedRow.strictness <= 10 ?
      parsedRow.strictness : 5;

    parsedRow.action_threshold = Number.isInteger(parsedRow.action_threshold) &&
      parsedRow.action_threshold >= 1 ?
      parsedRow.action_threshold : 3;

    // Validate boolean fields
    parsedRow.enabled = Boolean(parsedRow.enabled);
    parsedRow.auto_action = Boolean(parsedRow.auto_action);

    // Verify data integrity with hash
    const expectedHash = crypto.createHash('sha256')
      .update(JSON.stringify({
        rules: parsedRow.rules,
        strictness: parsedRow.strictness,
        enabled: parsedRow.enabled
      }))
      .digest('hex');

    if (parsedRow.data_hash !== expectedHash) {
      logger.warn('Server config data hash mismatch', {
        serverId: sanitizedServerId,
        expected: expectedHash,
        actual: parsedRow.data_hash
      });
      // We'll still use the data but log the integrity issue
    }

    // Cache the result
    configCache.set(cacheKey, parsedRow);

    return parsedRow;
  } catch (error) {
    logger.error('Error in getServerConfig', { error: error.message, serverId });
    return null;
  }
}

async function createServerConfig(serverId, config = {}) {
  try {
    // Enhanced validation
    if (!serverId || typeof serverId !== 'string' || serverId.trim() === '') {
      logger.warn('Invalid server ID provided to createServerConfig', { serverId });
      return null;
    }

    // Sanitize server ID
    const sanitizedServerId = serverId.replace(/[^\w-]/g, '');
    if (sanitizedServerId !== serverId) {
      logger.warn('Server ID contained invalid characters', { original: serverId, sanitized: sanitizedServerId });
    }

    // Validate and sanitize input config
    const validatedConfig = {
      server_id: sanitizedServerId,
      enabled: typeof config.enabled === 'boolean' ? config.enabled : true,
      channels: Array.isArray(config.channels) ? config.channels : [],
      rules: typeof config.rules === 'string' && config.rules.trim() !== '' ?
        config.rules.substring(0, 2000) : 'Default moderation rules',
      strictness: Number.isInteger(config.strictness) &&
        config.strictness >= 1 &&
        config.strictness <= 10 ?
        config.strictness : 5,
      customKeywords: Array.isArray(config.customKeywords) ? config.customKeywords : [],
      exemptRoles: Array.isArray(config.exemptRoles) ? config.exemptRoles : [],
      moderatorRoles: Array.isArray(config.moderatorRoles) ? config.moderatorRoles : [],
      autoAction: typeof config.autoAction === 'boolean' ? config.autoAction : false,
      actionThreshold: Number.isInteger(config.actionThreshold) &&
        config.actionThreshold >= 1 ?
        config.actionThreshold : 3,
      notificationChannel: config.notificationChannel || null,
      logChannel: config.logChannel || null
    };

    // Safely stringify JSON fields
    const defaultConfig = {
      server_id: validatedConfig.server_id,
      enabled: validatedConfig.enabled,
      channels: JSON.stringify(validatedConfig.channels),
      rules: validatedConfig.rules,
      strictness: validatedConfig.strictness,
      custom_keywords: JSON.stringify(validatedConfig.customKeywords),
      exempt_roles: JSON.stringify(validatedConfig.exemptRoles),
      moderator_roles: JSON.stringify(validatedConfig.moderatorRoles),
      auto_action: validatedConfig.autoAction,
      action_threshold: validatedConfig.actionThreshold,
      notification_channel: validatedConfig.notificationChannel,
      log_channel: validatedConfig.logChannel
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

    await dbAsync.runPrepared('createServerConfig', sql, params);

    // Clear cache for this server
    configCache.delete(`config:${sanitizedServerId}`);

    // Return the created config
    const createdConfig = await getServerConfig(sanitizedServerId);
    return createdConfig;
  } catch (error) {
    logger.error('Error in createServerConfig', { error: error.message, serverId });
    return null;
  }
}

// Violation Logging
async function logViolation(action, options = {}) {
  try {
    // Enhanced validation
    if (!action || typeof action !== 'object') {
      logger.warn('Invalid action object provided to logViolation');
      return null;
    }

    if (!action.serverId || typeof action.serverId !== 'string' || action.serverId.trim() === '') {
      logger.warn('Invalid server ID provided to logViolation', { serverId: action.serverId });
      return null;
    }

    if (!action.userId || typeof action.userId !== 'string' || action.userId.trim() === '') {
      logger.warn('Invalid user ID provided to logViolation', { userId: action.userId });
      return null;
    }

    // Sanitize server and user IDs
    const sanitizedServerId = action.serverId.replace(/[^\w-]/g, '');
    const sanitizedUserId = action.userId.replace(/[^\w-]/g, '');

    if (sanitizedServerId !== action.serverId || sanitizedUserId !== action.userId) {
      logger.warn('IDs contained invalid characters', {
        originalServerId: action.serverId,
        sanitizedServerId,
        originalUserId: action.userId,
        sanitizedUserId
      });
    }

    // Validate and sanitize all fields
    const sanitizedAction = {
      server_id: sanitizedServerId,
      user_id: sanitizedUserId,
      message_id: action.messageId ? String(action.messageId).substring(0, 100) : '',
      channel_id: action.channelId ? String(action.channelId).substring(0, 100) : '',
      content: action.content ? String(action.content).substring(0, 2000) : null,
      is_violation: Boolean(action.isViolation),
      category: action.category ? String(action.category).substring(0, 100) : null,
      severity: ['Low', 'Moderate', 'Severe'].includes(action.severity) ? action.severity : null,
      confidence_score: typeof action.confidenceScore === 'number' ?
        Math.max(0, Math.min(1, action.confidenceScore)) : null,
      explanation: action.explanation ? String(action.explanation).substring(0, 1000) : null,
      suggested_action: action.suggestedAction ? String(action.suggestedAction).substring(0, 100) : null,
      action_taken: action.actionTaken ? String(action.actionTaken).substring(0, 100) : null,
      human_reviewed: Boolean(action.humanReviewed),
      reviewer_id: action.reviewerId ? String(action.reviewerId).substring(0, 100) : null,
      review_notes: action.reviewNotes ? String(action.reviewNotes).substring(0, 500) : null,
      model_used: action.modelUsed ? String(action.modelUsed).substring(0, 100) : null,
      provider: ['ANTHROPIC', 'OPENROUTER'].includes(action.provider) ? action.provider : null,
      tokens_used: typeof action.tokensUsed === 'number' && action.tokensUsed >= 0 ?
        Math.min(action.tokensUsed, 1000000) : null,
      processing_time_ms: typeof action.processingTimeMs === 'number' && action.processingTimeMs >= 0 ?
        Math.min(action.processingTimeMs, 300000) : null,
      ip_address_hash: options.ip ? crypto.createHash('sha256').update(String(options.ip)).digest('hex') : null,
      session_id: options.sessionId ? String(options.sessionId).substring(0, 100) : null,
      request_id: options.requestId ? String(options.requestId).substring(0, 100) : crypto.randomUUID()
    };

    // Create content hash if content exists
    if (sanitizedAction.content) {
      try {
        sanitizedAction.content_hash = crypto.createHash('sha256')
          .update(sanitizedAction.content)
          .digest('hex');
      } catch (hashError) {
        logger.error('Error creating content hash', { error: hashError.message });
        sanitizedAction.content_hash = null;
      }
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
      sanitizedAction.is_violation ? 1 : 0, sanitizedAction.category, sanitizedAction.severity,
      sanitizedAction.confidence_score, sanitizedAction.explanation, sanitizedAction.suggested_action,
      sanitizedAction.action_taken, sanitizedAction.human_reviewed ? 1 : 0, sanitizedAction.reviewer_id,
      sanitizedAction.review_notes, sanitizedAction.model_used, sanitizedAction.provider,
      sanitizedAction.tokens_used, sanitizedAction.processing_time_ms, sanitizedAction.ip_address_hash,
      sanitizedAction.session_id, sanitizedAction.request_id
    ];

    const result = await dbAsync.runPrepared('logViolation', sql, params);
    return { id: result.lastID, ...sanitizedAction };
  } catch (error) {
    logger.error('Error in logViolation', { error: error.message });
    return null;
  }
}

// User Data Operations
async function getUserData(userId, serverId) {
  try {
    // Input validation
    if (!userId || typeof userId !== 'string' || userId.trim() === '') {
      logger.warn('Invalid user ID provided to getUserData', { userId });
      return null;
    }

    if (!serverId || typeof serverId !== 'string' || serverId.trim() === '') {
      logger.warn('Invalid server ID provided to getUserData', { serverId });
      return null;
    }

    // Sanitize inputs
    const sanitizedUserId = userId.replace(/[^\w-]/g, '');
    const sanitizedServerId = serverId.replace(/[^\w-]/g, '');

    if (sanitizedUserId !== userId || sanitizedServerId !== serverId) {
      logger.warn('IDs contained invalid characters', {
        originalUserId: userId,
        sanitizedUserId,
        originalServerId: serverId,
        sanitizedServerId
      });
    }

    // Check cache first - using direct key without namespace prefix (handled by TieredCache)
    const cacheKey = `user:${sanitizedUserId}:${sanitizedServerId}`;
    const cached = userCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const row = await dbAsync.getPrepared(
      'getUserData',
      'SELECT * FROM user_data WHERE user_id = ? AND server_id = ?',
      [sanitizedUserId, sanitizedServerId]
    );

    // Cache the result if found
    if (row) {
      // Validate date fields
      if (row.exempt_until && !(row.exempt_until instanceof Date) && isNaN(new Date(row.exempt_until).getTime())) {
        row.exempt_until = null;
      }

      if (row.last_violation_date && !(row.last_violation_date instanceof Date) &&
        isNaN(new Date(row.last_violation_date).getTime())) {
        row.last_violation_date = null;
      }

      // Ensure numeric fields are valid
      row.recent_violations = Number.isInteger(row.recent_violations) && row.recent_violations >= 0 ?
        row.recent_violations : 0;
      row.total_violations = Number.isInteger(row.total_violations) && row.total_violations >= 0 ?
        row.total_violations : 0;

      // Ensure boolean fields are valid
      row.is_exempt = Boolean(row.is_exempt);
      row.is_anonymized = Boolean(row.is_anonymized);

      userCache.set(cacheKey, row);
    }

    return row;
  } catch (error) {
    logger.error('Error in getUserData', { error: error.message, userId, serverId });
    return null;
  }
}

// Get violation logs with pagination
async function getViolationLogs(serverId, options = {}) {
  try {
    // Input validation
    if (!serverId || typeof serverId !== 'string' || serverId.trim() === '') {
      logger.warn('Invalid server ID provided to getViolationLogs', { serverId });
      return [];
    }

    // Sanitize server ID
    const sanitizedServerId = serverId.replace(/[^\w-]/g, '');
    if (sanitizedServerId !== serverId) {
      logger.warn('Server ID contained invalid characters', {
        original: serverId,
        sanitized: sanitizedServerId
      });
    }

    // Validate and sanitize options
    const sanitizedOptions = {
      limit: typeof options.limit === 'number' && options.limit > 0 ?
        Math.min(options.limit, 1000) : 50,
      offset: typeof options.offset === 'number' && options.offset >= 0 ?
        options.offset : 0
    };

    // Build query with parameterized values only
    let whereClause = 'WHERE server_id = ?';
    const params = [sanitizedServerId];

    if (options.userId) {
      // Sanitize user ID if provided
      const sanitizedUserId = String(options.userId).replace(/[^\w-]/g, '');
      if (sanitizedUserId !== options.userId) {
        logger.warn('User ID contained invalid characters', {
          original: options.userId,
          sanitized: sanitizedUserId
        });
      }

      whereClause += ' AND user_id = ?';
      params.push(sanitizedUserId);
    }

    if (options.isViolation !== undefined) {
      whereClause += ' AND is_violation = ?';
      params.push(options.isViolation ? 1 : 0);
    }

    params.push(sanitizedOptions.limit, sanitizedOptions.offset);

    const sql = `SELECT * FROM violation_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;

    // Use the query optimizer to execute the query
    const rows = await queryOptimizer.executeQuery(dbAsync, sql, params, {
      skipOptimization: options.skipOptimization,
      skipCache: options.skipCache
    });

    // Validate returned data
    return (rows || []).map(row => {
      // Ensure boolean fields are valid
      row.is_violation = Boolean(row.is_violation);
      row.human_reviewed = Boolean(row.human_reviewed);

      // Ensure numeric fields are valid
      if (typeof row.confidence_score === 'number') {
        row.confidence_score = Math.max(0, Math.min(1, row.confidence_score));
      }

      return row;
    });
  } catch (error) {
    logger.error('Error in getViolationLogs', { error: error.message, serverId });
    return [];
  }
}

// Database health check
async function checkDatabaseHealth() {
  try {
    // Check if database and async wrapper are initialized
    if (!db || !dbAsync) {
      logger.warn('Database health check failed: Database not initialized');
      return false;
    }

    // Execute a simple query to verify database is responsive
    const row = await dbAsync.get('SELECT 1 as health');

    // Verify the result is as expected
    const isHealthy = row && row.health === 1;

    if (!isHealthy) {
      logger.warn('Database health check failed: Unexpected response', { response: row });
    }

    return isHealthy;
  } catch (error) {
    logger.error('Database health check failed', {
      error: error.message,
      stack: error.stack
    });
    return false;
  }
}

// Close database connection
async function closeDatabase() {
  try {
    logger.info('Closing database connection...');

    // Shutdown caches properly to ensure data persistence and cleanup
    if (configCache) {
      try {
        configCache.shutdown();
        logger.debug('Config cache shutdown');
      } catch (cacheError) {
        logger.error('Error shutting down config cache', { error: cacheError.message });
      }
    }

    if (userCache) {
      try {
        userCache.shutdown();
        logger.debug('User cache shutdown');
      } catch (cacheError) {
        logger.error('Error shutting down user cache', { error: cacheError.message });
      }
    }

    // Shutdown query optimizer
    if (queryOptimizer) {
      try {
        queryOptimizer.shutdown();
        logger.debug('Query optimizer shutdown');
      } catch (optimizerError) {
        logger.error('Error shutting down query optimizer', { error: optimizerError.message });
      }
    }

    // Close async wrapper to finalize prepared statements
    if (dbAsync) {
      try {
        dbAsync.close();
        logger.debug('Database async wrapper closed');
      } catch (asyncError) {
        logger.error('Error closing async database wrapper', { error: asyncError.message });
      }
    }

    // Close the actual database connection
    if (db) {
      await new Promise((resolve) => {
        db.close((err) => {
          if (err) {
            logger.error('Error closing SQLite database', { error: err.message });
          } else {
            logger.info('SQLite database connection closed successfully');
          }
          resolve();
        });
      });
    } else {
      logger.warn('No database connection to close');
    }

    // Clear references
    db = null;
    dbAsync = null;
    queryOptimizer = null;

    logger.info('Database shutdown complete');
  } catch (error) {
    logger.error('Error during database shutdown', {
      error: error.message,
      stack: error.stack
    });

    // Force clear references even on error
    db = null;
    dbAsync = null;
    queryOptimizer = null;
  }
}

// Cleanup old logs (run periodically)
async function cleanupOldLogs() {
  try {
    // Validate database is available
    if (!db || !dbAsync) {
      logger.warn('Cannot cleanup logs: Database not initialized');
      return;
    }

    // Get retention period from environment with validation
    let retentionDays = 90; // Default 90 days

    if (process.env.LOG_RETENTION_DAYS) {
      const parsedDays = parseInt(process.env.LOG_RETENTION_DAYS, 10);
      if (!isNaN(parsedDays) && parsedDays > 0) {
        retentionDays = parsedDays;
      } else {
        logger.warn('Invalid LOG_RETENTION_DAYS value, using default', {
          provided: process.env.LOG_RETENTION_DAYS,
          default: retentionDays
        });
      }
    }

    logger.info('Running log cleanup', { retentionDays });

    // Use parameterized query for safety
    const sql = `DELETE FROM violation_logs WHERE created_at < datetime('now', ? || ' days')`;
    const params = [`-${retentionDays}`];

    const result = await dbAsync.run(sql, params);

    if (result.changes > 0) {
      logger.info(`Cleaned up ${result.changes} old violation logs`, { retentionDays });
    } else {
      logger.info('No old logs to clean up', { retentionDays });
    }

    // Optimize database after deletion
    if (result.changes > 1000) {
      logger.info('Running VACUUM after large cleanup');
      await dbAsync.run('VACUUM');
    }
  } catch (error) {
    logger.error('Error in cleanupOldLogs', {
      error: error.message,
      stack: error.stack
    });
  }
}

// Export new logAction function that matches the usage in moderator.js
async function logAction(action, options = {}) {
  return logViolation(action, options);
}

module.exports = {
  setupDatabase,
  getServerConfig,
  createServerConfig,
  logViolation,
  logAction, // Alias for logViolation used in moderator.js
  getUserData,
  getViolationLogs,
  checkDatabaseHealth,
  closeDatabase,
  cleanupOldLogs,
  configCache,
  userCache,
  getQueryOptimizerStats: () => queryOptimizer ? queryOptimizer.getStats() : null,
  getCacheStats: () => ({
    configCache: configCache ? configCache.getStats() : null,
    userCache: userCache ? userCache.getStats() : null
  })
};
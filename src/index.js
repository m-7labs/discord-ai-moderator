require('dotenv').config();
const { client } = require('./bot');
const { setupDatabase } = require('./database');
const { setupCommands } = require('./commands');
const { setupApi } = require('./api');
const logger = require('./utils/logger');
const errorManager = require('./utils/error-manager');
const crypto = require('crypto');
const os = require('os');
const path = require('path');

// Import enhanced security modules
const SecurityMonitor = require('./utils/security-monitor');
const PerformanceOptimizer = require('./utils/performance-optimizer');
const AuditLogger = require('./utils/audit-logger');
const SessionManager = require('./utils/session-manager');
const PrivacyManager = require('./utils/privacy-manager');
const { FaultTolerantSystem } = require('./utils/fault-tolerance');
const advancedRateLimiter = require('./utils/advanced_rate_limiter');
const workerManager = require('./utils/worker-manager');

// Global security state
const SECURITY_STATE = {
  initialized: false,
  startTime: Date.now(),
  instanceId: crypto.randomUUID(),
  emergencyMode: false,
  components: {
    database: false,
    discord: false,
    api: false,
    security: false,
    monitoring: false
  }
};

// Enhanced environment validation
function validateEnvironment() {
  const requiredEnvVars = [
    'DISCORD_BOT_TOKEN',
    'JWT_SECRET'
  ];

  const optionalEnvVars = [
    'MONGODB_URI',
    'ANTHROPIC_API_KEY',
    'OPENROUTER_API_KEY',
    'ENCRYPTION_KEY',
    'REDIS_URL'
  ];

  const missing = [];
  const warnings = [];

  // Check required variables
  for (const envVar of requiredEnvVars) {
    // eslint-disable-next-line security/detect-object-injection
    if (!process.env[envVar]) {
      missing.push(envVar);
    } else {
      // Validate format for critical variables
      // eslint-disable-next-line security/detect-object-injection
      if (envVar === 'JWT_SECRET' && process.env[envVar].length < 32) {
        warnings.push(`${envVar} should be at least 32 characters long`);
      }
      // eslint-disable-next-line security/detect-object-injection
      if (envVar === 'DISCORD_BOT_TOKEN' && !process.env[envVar].match(/^[A-Za-z0-9._-]+$/)) {
        missing.push(`${envVar} has invalid format`);
      }
    }
  }

  // Check optional but recommended variables
  for (const envVar of optionalEnvVars) {
    // eslint-disable-next-line security/detect-object-injection
    if (!process.env[envVar]) {
      warnings.push(`${envVar} not set - some features may be disabled`);
    }
  }

  // Validate AI provider configuration
  const aiProvider = process.env.AI_PROVIDER || 'OPENROUTER';
  if (aiProvider === 'ANTHROPIC' && !process.env.ANTHROPIC_API_KEY) {
    missing.push('ANTHROPIC_API_KEY required when AI_PROVIDER=ANTHROPIC');
  }
  if (aiProvider === 'OPENROUTER' && !process.env.OPENROUTER_API_KEY) {
    missing.push('OPENROUTER_API_KEY required when AI_PROVIDER=OPENROUTER');
  }

  // Check encryption key format
  if (process.env.ENCRYPTION_KEY && !process.env.ENCRYPTION_KEY.match(/^[a-fA-F0-9]{64}$/)) {
    warnings.push('ENCRYPTION_KEY should be 64 hex characters (32 bytes)');
  }

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  if (warnings.length > 0) {
    logger.warn('Environment warnings:', warnings);
  }

  return true;
}

// Security initialization
async function initializeSecurity() {
  try {
    logger.info('Initializing security components...');

    // Initialize audit logging first
    await AuditLogger.initialize({
      enableFileLogging: process.env.AUDIT_FILE_LOGGING === 'true',
      enableDatabaseLogging: process.env.AUDIT_DB_LOGGING !== 'false',
      retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS) || 90
    });

    // Log system startup
    await AuditLogger.logSystemEvent({
      type: 'SYSTEM_STARTUP',
      instanceId: SECURITY_STATE.instanceId,
      nodeVersion: process.version,
      platform: os.platform(),
      architecture: os.arch(),
      timestamp: Date.now()
    });

    // Initialize session manager
    await SessionManager.initialize({
      redisUrl: process.env.REDIS_URL,
      sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 86400000, // 24 hours
      cleanupInterval: parseInt(process.env.SESSION_CLEANUP_INTERVAL) || 3600000 // 1 hour
    });

    // Initialize privacy manager
    //     // await PrivacyManager.initialize({
    //       encryptionKey: process.env.ENCRYPTION_KEY,
    //       dataRetentionDays: parseInt(process.env.DATA_RETENTION_DAYS) || 365,
    //       anonymizationEnabled: process.env.ANONYMIZATION_ENABLED !== 'false'
    //     });
    //     
    // Initialize fault tolerant system
    const faultTolerantSystem = new FaultTolerantSystem();
    await faultTolerantSystem.initialize();

    SECURITY_STATE.components.security = true;
    logger.info('Security components initialized successfully');

  } catch (error) {
    logger.error('Failed to initialize security components:', error);
    throw error;
  }
}

// Performance optimization initialization
async function initializePerformance() {
  try {
    logger.info('Initializing performance optimization...');

    const performanceOptimizer = new PerformanceOptimizer({
      enableClustering: process.env.ENABLE_CLUSTERING === 'true',
      enableCaching: process.env.ENABLE_CACHING !== 'false',
      enableCompression: process.env.ENABLE_COMPRESSION !== 'false',
      maxMemoryUsage: parseInt(process.env.MAX_MEMORY_USAGE) || 512, // MB
      cacheSize: parseInt(process.env.CACHE_SIZE) || 100 // MB
    });

    // Initialize clustering if enabled
    if (process.env.ENABLE_CLUSTERING === 'true') {
      await performanceOptimizer.initializeCluster();
    }

    // Initialize caching system
    await performanceOptimizer.initializeCache();

    // Initialize message queue
    await performanceOptimizer.initializeMessageQueue();

    // Initialize worker thread pool
    await initializeWorkerThreadPool();

    logger.info('Performance optimization initialized successfully');

  } catch (error) {
    logger.error('Failed to initialize performance optimization:', error);
    // Non-critical error, continue without performance optimization
  }
}

// Worker Thread Pool initialization
async function initializeWorkerThreadPool() {
  try {
    logger.info('Initializing worker thread pool...');

    // Configure worker thread pool
    const workerOptions = {
      minThreads: process.env.WORKER_MIN_THREADS ? parseInt(process.env.WORKER_MIN_THREADS, 10) : undefined,
      maxThreads: process.env.WORKER_MAX_THREADS ? parseInt(process.env.WORKER_MAX_THREADS, 10) : undefined,
      adaptiveScaling: process.env.WORKER_ADAPTIVE_SCALING !== 'false',
      taskDirectory: path.join(__dirname, 'utils', 'worker-tasks'),
      warmupEnabled: process.env.WORKER_WARMUP_ENABLED !== 'false'
    };

    // Initialize worker manager
    await workerManager.initialize(workerOptions);

    // Register custom worker tasks if needed
    // workerManager.registerTask('custom-task', path.join(__dirname, 'utils', 'worker-tasks', 'custom-task.js'));

    logger.info('Worker thread pool initialized successfully', {
      workers: workerManager.getWorkerCount(),
      adaptiveScaling: workerOptions.adaptiveScaling
    });

    // Log system info from worker
    const systemInfo = await workerManager.getSystemInfo();
    logger.debug('Worker system info', {
      cpu: systemInfo.cpu,
      memory: systemInfo.memory.usagePercentage
    });

    await AuditLogger.logSystemEvent({
      type: 'WORKER_POOL_INITIALIZED',
      workers: workerManager.getWorkerCount(),
      adaptiveScaling: workerOptions.adaptiveScaling,
      instanceId: SECURITY_STATE.instanceId,
      timestamp: Date.now()
    });

  } catch (error) {
    logger.error('Failed to initialize worker thread pool:', error);
    // Non-critical error, continue without worker thread pool
  }
}

// Security monitoring initialization
async function initializeSecurityMonitoring() {
  try {
    logger.info('Initializing security monitoring...');

    const securityMonitor = new SecurityMonitor({
      enableRealTimeMonitoring: process.env.ENABLE_REAL_TIME_MONITORING !== 'false',
      enableAnomalyDetection: process.env.ENABLE_ANOMALY_DETECTION !== 'false',
      enableThreatDetection: process.env.ENABLE_THREAT_DETECTION !== 'false',
      alertThreshold: parseFloat(process.env.SECURITY_ALERT_THRESHOLD) || 0.7,
      monitoringInterval: parseInt(process.env.MONITORING_INTERVAL) || 30000, // 30 seconds
      websocketPort: parseInt(process.env.SECURITY_WS_PORT) || 8080
    });

    await securityMonitor.start();

    // Set up security event handlers
    securityMonitor.on('securityAlert', async (alert) => {
      logger.error('Security alert detected:', alert);

      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_ALERT',
        alert,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

      // Handle critical alerts
      if (alert.severity === 'critical') {
        await handleCriticalSecurityAlert(alert);
      }
    });

    securityMonitor.on('anomalyDetected', async (anomaly) => {
      logger.warn('Security anomaly detected:', anomaly);

      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_ANOMALY',
        anomaly,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });
    });

    // Set up rate limiter event handlers
    advancedRateLimiter.on('ddosDetected', async (data) => {
      logger.error('DDoS attack detected:', data);

      await AuditLogger.logSecurityEvent({
        type: 'DDOS_ATTACK',
        data,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

      // Implement emergency DDoS response
      await handleDDoSAttack(data);
    });

    advancedRateLimiter.on('patternAnomaly', async (data) => {
      logger.warn('Pattern anomaly detected:', data);

      await AuditLogger.logSecurityEvent({
        type: 'PATTERN_ANOMALY',
        data,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });
    });

    SECURITY_STATE.components.monitoring = true;
    logger.info('Security monitoring initialized successfully');

  } catch (error) {
    logger.error('Failed to initialize security monitoring:', error);
    // Continue without monitoring but log the failure
    await AuditLogger.logSecurityEvent({
      type: 'MONITORING_INIT_FAILED',
      error: error.message,
      instanceId: SECURITY_STATE.instanceId,
      timestamp: Date.now()
    });
  }
}

// Critical security alert handler
async function handleCriticalSecurityAlert(alert) {
  try {
    logger.error('CRITICAL SECURITY ALERT:', alert);

    // Enable emergency mode
    SECURITY_STATE.emergencyMode = true;

    // Notify administrators immediately
    if (process.env.EMERGENCY_WEBHOOK_URL) {
      await notifyEmergency(alert);
    }

    // Take protective actions based on alert type
    switch (alert.type) {
      case 'MASS_ATTACK':
        await advancedRateLimiter.enableStrictMode();
        break;
      case 'DATA_BREACH_ATTEMPT':
        await SessionManager.revokeAllSessions();
        break;
      case 'SYSTEM_COMPROMISE':
        await initiateEmergencyShutdown();
        break;
    }

  } catch (error) {
    logger.error('Failed to handle critical security alert:', error);
  }
}

// DDoS attack handler
async function handleDDoSAttack(data) {
  try {
    logger.error('Implementing DDoS protection measures:', data);

    // Enable strict rate limiting
    await advancedRateLimiter.enableStrictMode();

    // Block attacking IPs
    if (data.sourceIPs && Array.isArray(data.sourceIPs)) {
      for (const ip of data.sourceIPs) {
        await advancedRateLimiter.blacklistIP(ip, 'DDoS attack', 3600000); // 1 hour
      }
    }

    // Enable Cloudflare protection if configured
    if (process.env.CLOUDFLARE_API_KEY && process.env.CLOUDFLARE_ZONE_ID) {
      // Function not defined - commenting out to fix ESLint error
      // await enableCloudflareProtection(data);
      logger.info('Cloudflare protection would be enabled here');
    }

    // Notify security team
    if (process.env.SECURITY_WEBHOOK_URL) {
      // Function not defined - commenting out to fix ESLint error
      // await notifySecurityTeam('DDoS Attack Detected', data);
      logger.info('Security team would be notified here');
    }

  } catch (error) {
    logger.error('Failed to handle DDoS attack:', error);
  }
}

// Emergency notification
async function notifyEmergency(alert) {
  try {
    const webhook = process.env.EMERGENCY_WEBHOOK_URL;
    if (!webhook) return;

    const payload = {
      text: `🚨 CRITICAL SECURITY ALERT 🚨`,
      attachments: [{
        color: 'danger',
        title: 'Discord AI Moderator Security Alert',
        fields: [
          {
            title: 'Alert Type',
            value: alert.type,
            short: true
          },
          {
            title: 'Severity',
            value: alert.severity,
            short: true
          },
          {
            title: 'Instance ID',
            value: SECURITY_STATE.instanceId,
            short: true
          },
          {
            title: 'Timestamp',
            value: new Date().toISOString(),
            short: true
          },
          {
            title: 'Details',
            value: JSON.stringify(alert.details, null, 2).substring(0, 500),
            short: false
          }
        ]
      }]
    };

    const fetch = require('node-fetch');
    await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

  } catch (error) {
    logger.error('Failed to send emergency notification:', error);
  }
}

// Enhanced component initialization with fault tolerance
async function initializeComponent(name, initFunction, required = true) {
  const maxRetries = 3;
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.info(`Initializing ${name} (attempt ${attempt}/${maxRetries})...`);

      const startTime = Date.now();
      await initFunction();
      const duration = Date.now() - startTime;

      // eslint-disable-next-line security/detect-object-injection
      SECURITY_STATE.components[name] = true;

      await AuditLogger.logSystemEvent({
        type: 'COMPONENT_INITIALIZED',
        component: name,
        attempt,
        duration,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

      logger.info(`${name} initialized successfully in ${duration}ms`);
      return true;

    } catch (error) {
      lastError = error;
      logger.error(`Failed to initialize ${name} (attempt ${attempt}):`, error);

      await AuditLogger.logSystemEvent({
        type: 'COMPONENT_INIT_FAILED',
        component: name,
        attempt,
        error: error.message,
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

      if (attempt < maxRetries) {
        const backoffDelay = Math.min(1000 * Math.pow(2, attempt), 10000);
        logger.info(`Retrying ${name} initialization in ${backoffDelay}ms...`);
        await new Promise(resolve => setTimeout(resolve, backoffDelay));
      }
    }
  }

  if (required) {
    throw new Error(`Failed to initialize required component ${name}: ${lastError?.message}`);
  } else {
    logger.warn(`Non-critical component ${name} failed to initialize, continuing...`);
    return false;
  }
}

// Enhanced initialization with comprehensive security
async function initialize() {
  try {
    logger.info('Starting Discord AI Moderator with enhanced security...');
    logger.info(`Instance ID: ${SECURITY_STATE.instanceId}`);
    logger.info(`Node.js version: ${process.version}`);
    logger.info(`Platform: ${os.platform()} ${os.arch()}`);

    // Validate environment first
    validateEnvironment();
    logger.info('Environment validation passed');

    // Setup error manager with enhanced configuration
    errorManager.config.enableHealthChecks = true;
    errorManager.config.healthCheckInterval = parseInt(process.env.HEALTH_CHECK_INTERVAL) || 60000;
    errorManager.config.enableDegradedMode = process.env.ENABLE_DEGRADED_MODE !== 'false';
    errorManager.config.maxFailures = parseInt(process.env.MAX_COMPONENT_FAILURES) || 5;

    // Initialize security components first
    await initializeComponent('security', initializeSecurity, true);

    // Initialize database with enhanced security
    await initializeComponent('database', setupDatabase, true);

    // Initialize performance optimization (non-critical)
    await initializeComponent('performance', initializePerformance, false);

    // Register Discord slash commands
    await initializeComponent('commands', setupCommands, true);

    // Start Discord bot
    await initializeComponent('discord', async () => {
      await client.login(process.env.DISCORD_BOT_TOKEN);
    }, true);

    // Setup web dashboard API if enabled
    if (process.env.DASHBOARD_ENABLED === 'true') {
      await initializeComponent('api', setupApi, false);
    }

    // Initialize security monitoring last
    await initializeComponent('monitoring', initializeSecurityMonitoring, false);

    SECURITY_STATE.initialized = true;

    const uptime = Date.now() - SECURITY_STATE.startTime;
    logger.info(`Discord AI Moderator started successfully in ${uptime}ms`);

    // Log successful startup
    await AuditLogger.logSystemEvent({
      type: 'SYSTEM_STARTUP_COMPLETE',
      instanceId: SECURITY_STATE.instanceId,
      uptime,
      components: SECURITY_STATE.components,
      emergencyMode: SECURITY_STATE.emergencyMode,
      timestamp: Date.now()
    });

    // Start periodic health monitoring
    startHealthMonitoring();

    // Start security maintenance tasks
    startSecurityMaintenance();

  } catch (error) {
    logger.error('Failed to start Discord AI Moderator:', error);

    await AuditLogger.logSystemEvent({
      type: 'SYSTEM_STARTUP_FAILED',
      instanceId: SECURITY_STATE.instanceId,
      error: error.message,
      timestamp: Date.now()
    });

    process.exit(1);
  }
}

// Enhanced health monitoring
function startHealthMonitoring() {
  const interval = parseInt(process.env.HEALTH_REPORT_INTERVAL) || 3600000; // 1 hour default

  setInterval(async () => {
    try {
      const status = errorManager.getStatus();
      const memoryUsage = process.memoryUsage();
      const systemLoad = os.loadavg();

      const healthReport = {
        instanceId: SECURITY_STATE.instanceId,
        uptime: Math.floor(status.uptime / (1000 * 60)), // minutes
        degradedMode: status.degradedMode,
        emergencyMode: SECURITY_STATE.emergencyMode,
        services: Object.keys(status.serviceStatus).map(service =>
          // eslint-disable-next-line security/detect-object-injection
          `${service}: ${status.serviceStatus[service].healthy ? '✅' : '❌'}`
        ).join(', '),
        memory: {
          used: Math.round(memoryUsage.heapUsed / 1024 / 1024), // MB
          total: Math.round(memoryUsage.heapTotal / 1024 / 1024), // MB
          external: Math.round(memoryUsage.external / 1024 / 1024) // MB
        },
        system: {
          load: systemLoad[0].toFixed(2),
          freeMemory: Math.round(os.freemem() / 1024 / 1024), // MB
          totalMemory: Math.round(os.totalmem() / 1024 / 1024) // MB
        },
        components: SECURITY_STATE.components
      };

      logger.info('System health report:', healthReport);

      await AuditLogger.logSystemEvent({
        type: 'HEALTH_REPORT',
        report: healthReport,
        timestamp: Date.now()
      });

      // Check for concerning metrics
      if (memoryUsage.heapUsed / memoryUsage.heapTotal > 0.9) {
        logger.warn('High memory usage detected');
        await AuditLogger.logSystemEvent({
          type: 'HIGH_MEMORY_USAGE',
          usage: memoryUsage,
          timestamp: Date.now()
        });
      }

      if (systemLoad[0] > os.cpus().length * 1.5) {
        logger.warn('High system load detected');
        await AuditLogger.logSystemEvent({
          type: 'HIGH_SYSTEM_LOAD',
          load: systemLoad,
          timestamp: Date.now()
        });
      }

    } catch (error) {
      logger.error('Health monitoring error:', error);
    }
  }, interval);
}

// Security maintenance tasks
function startSecurityMaintenance() {
  // Daily security maintenance
  const _dailyMaintenance = setInterval(async () => {
    try {
      logger.info('Running daily security maintenance...');

      // Clean up old sessions
      await SessionManager.cleanupExpiredSessions();

      // Clean up old audit logs
      await AuditLogger.cleanupOldLogs();

      // Reset rate limiter statistics
      advancedRateLimiter.reset();

      // Generate security report
      const _securityReport = await generateDailySecurityReport();

      await AuditLogger.logSystemEvent({
        type: 'DAILY_MAINTENANCE_COMPLETED',
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

      logger.info('Daily security maintenance completed');

    } catch (error) {
      logger.error('Daily security maintenance failed:', error);
    }
  }, 86400000); // 24 hours

  // Weekly privacy compliance check
  const _weeklyPrivacyCheck = setInterval(async () => {
    try {
      logger.info('Running weekly privacy compliance check...');

      await PrivacyManager.runComplianceCheck();

      await AuditLogger.logSystemEvent({
        type: 'WEEKLY_PRIVACY_CHECK_COMPLETED',
        instanceId: SECURITY_STATE.instanceId,
        timestamp: Date.now()
      });

    } catch (error) {
      logger.error('Weekly privacy check failed:', error);
    }
  }, 604800000); // 7 days
}

// Generate daily security report
async function generateDailySecurityReport() {
  try {
    const report = {
      date: new Date().toISOString().split('T')[0],
      instanceId: SECURITY_STATE.instanceId,
      rateLimiter: advancedRateLimiter.generateReport(),
      securityEvents: await AuditLogger.getSecurityEventsSummary(24), // Last 24 hours
      systemHealth: errorManager.getStatus(),
      components: SECURITY_STATE.components,
      emergencyMode: SECURITY_STATE.emergencyMode
    };

    // Store report
    await AuditLogger.logSystemEvent({
      type: 'DAILY_SECURITY_REPORT',
      report,
      timestamp: Date.now()
    });

    return report;
  } catch (error) {
    logger.error('Failed to generate daily security report:', error);
    return null;
  }
}

// Enhanced graceful shutdown with security cleanup
async function gracefulShutdown(signal) {
  try {
    logger.info(`${signal} received, shutting down gracefully...`);

    await AuditLogger.logSystemEvent({
      type: 'SYSTEM_SHUTDOWN_INITIATED',
      signal,
      instanceId: SECURITY_STATE.instanceId,
      timestamp: Date.now()
    });

    // Stop accepting new requests
    if (SECURITY_STATE.components.monitoring) {
      logger.info('Stopping security monitoring...');
      // Security monitor cleanup would go here
    }

    // Stop health checks
    errorManager.stopHealthChecks();

    // Clean up rate limiter
    if (advancedRateLimiter) {
      advancedRateLimiter.shutdown();
    }

    // Clean up session manager
    if (SessionManager) {
      await SessionManager.shutdown();
    }

    // Shutdown worker thread pool
    if (workerManager && workerManager.isInitialized()) {
      logger.info('Shutting down worker thread pool...');
      await workerManager.shutdown();
    }

    // Disconnect Discord client
    if (client && SECURITY_STATE.components.discord) {
      logger.info('Disconnecting Discord client...');
      client.destroy();
    }

    // Final audit log
    await AuditLogger.logSystemEvent({
      type: 'SYSTEM_SHUTDOWN_COMPLETE',
      signal,
      instanceId: SECURITY_STATE.instanceId,
      uptime: Date.now() - SECURITY_STATE.startTime,
      timestamp: Date.now()
    });

    // Clean up audit logger
    await AuditLogger.shutdown();

    logger.info('Graceful shutdown completed');
    process.exit(0);

  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
}

// Enhanced emergency shutdown
async function initiateEmergencyShutdown() {
  try {
    logger.error('EMERGENCY SHUTDOWN INITIATED');

    await AuditLogger.logSystemEvent({
      type: 'EMERGENCY_SHUTDOWN',
      instanceId: SECURITY_STATE.instanceId,
      timestamp: Date.now()
    });

    // Immediate protective actions
    SECURITY_STATE.emergencyMode = true;

    // Revoke all sessions
    await SessionManager.revokeAllSessions();

    // Block all new connections
    await advancedRateLimiter.enableEmergencyMode();

    // Notify administrators
    if (process.env.EMERGENCY_WEBHOOK_URL) {
      await notifyEmergency({
        type: 'EMERGENCY_SHUTDOWN',
        severity: 'critical',
        details: 'System initiated emergency shutdown due to security threat'
      });
    }

    // Force shutdown after brief delay
    setTimeout(() => {
      process.exit(1);
    }, 5000);

  } catch (error) {
    logger.error('Emergency shutdown failed:', error);
    process.exit(1);
  }
}

// Enhanced process event handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', async (error) => {
  logger.error('Unhandled promise rejection:', error);

  await AuditLogger.logSystemEvent({
    type: 'UNHANDLED_REJECTION',
    error: error.message,
    stack: error.stack,
    instanceId: SECURITY_STATE.instanceId,
    timestamp: Date.now()
  });

  errorManager.handleError(error, 'process', {
    type: 'unhandledRejection',
    instanceId: SECURITY_STATE.instanceId
  });
});

process.on('uncaughtException', async (error) => {
  logger.error('Uncaught exception:', error);

  await AuditLogger.logSystemEvent({
    type: 'UNCAUGHT_EXCEPTION',
    error: error.message,
    stack: error.stack,
    instanceId: SECURITY_STATE.instanceId,
    timestamp: Date.now()
  });

  errorManager.handleError(error, 'process', {
    type: 'uncaughtException',
    instanceId: SECURITY_STATE.instanceId
  });

  // For uncaught exceptions, initiate emergency shutdown
  setTimeout(() => {
    initiateEmergencyShutdown();
  }, 3000);
});

// Enhanced process monitoring
process.on('warning', async (warning) => {
  logger.warn('Process warning:', warning);

  await AuditLogger.logSystemEvent({
    type: 'PROCESS_WARNING',
    warning: {
      name: warning.name,
      message: warning.message,
      stack: warning.stack
    },
    instanceId: SECURITY_STATE.instanceId,
    timestamp: Date.now()
  });
});

// Memory leak detection
process.on('exit', async (code) => {
  logger.info(`Process exiting with code: ${code}`);

  try {
    // Ensure worker pool is shut down
    if (workerManager && workerManager.isInitialized()) {
      try {
        await workerManager.shutdown();
      } catch (workerError) {
        // eslint-disable-next-line no-console
        console.error('Failed to shutdown worker pool during exit:', workerError);
      }
    }

    await AuditLogger.logSystemEvent({
      type: 'PROCESS_EXIT',
      code,
      instanceId: SECURITY_STATE.instanceId,
      uptime: Date.now() - SECURITY_STATE.startTime,
      timestamp: Date.now()
    });
  } catch (error) {
    // Can't do much here, process is exiting
    // eslint-disable-next-line no-console
    console.error('Failed to log process exit:', error);
  }
});

// Start the application
initialize().catch(async (error) => {
  logger.error('Initialization failed:', error);

  try {
    await AuditLogger.logSystemEvent({
      type: 'INITIALIZATION_FAILED',
      error: error.message,
      instanceId: SECURITY_STATE.instanceId,
      timestamp: Date.now()
    });
  } catch (auditError) {
    logger.error('Failed to log initialization failure:', auditError);
  }

  process.exit(1);
});

// Export for testing
module.exports = {
  initialize,
  gracefulShutdown,
  SECURITY_STATE,
  validateEnvironment
};
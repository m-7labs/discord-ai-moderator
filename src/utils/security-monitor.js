const EventEmitter = require('events');
const WebSocket = require('ws');
const crypto = require('crypto');
const os = require('os');
const logger = require('./logger');
const AuditLogger = require('./audit-logger');

/**
 * Enhanced Security Monitor with real-time threat detection
 */
class SecurityMonitor extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = {
      enableRealTimeMonitoring: options.enableRealTimeMonitoring !== false,
      enableAnomalyDetection: options.enableAnomalyDetection !== false,
      enableThreatDetection: options.enableThreatDetection !== false,
      alertThreshold: options.alertThreshold || 0.7,
      monitoringInterval: options.monitoringInterval || 30000, // 30 seconds
      websocketPort: options.websocketPort || 8080,
      maxAlerts: options.maxAlerts || 1000,
      retentionPeriod: options.retentionPeriod || 24 * 60 * 60 * 1000, // 24 hours
      anomalyWindow: options.anomalyWindow || 300000, // 5 minutes
      threatWindow: options.threatWindow || 600000 // 10 minutes
    };

    // Security metrics storage
    this.metrics = new Map();
    this.alerts = new Map();
    this.patterns = new Map();
    this.threats = new Map();
    this.connections = new Set();

    // Monitoring state
    this.isRunning = false;
    this.intervalId = null;
    this.wss = null;

    // Thresholds for different security events
    this.thresholds = {
      failedLogins: { count: 5, window: 300000 }, // 5 per 5 minutes
      errorRate: { percentage: 0.05, window: 60000 }, // 5% per minute
      requestRate: { count: 1000, window: 60000 }, // 1000 per minute
      suspiciousPatterns: { score: 0.7, window: 600000 }, // 10 minutes
      resourceUsage: {
        cpu: 0.8,
        memory: 0.8,
        connections: 1000
      },
      ddosIndicators: {
        requestSpike: 5.0, // 5x normal rate
        errorSpike: 10.0,  // 10x normal error rate
        uniqueIPs: 100     // 100+ unique IPs in short time
      }
    };

    // Machine learning models for anomaly detection
    this.models = {
      requestPattern: new RequestPatternModel(),
      userBehavior: new UserBehaviorModel(),
      systemHealth: new SystemHealthModel()
    };

    // Statistics
    this.stats = {
      alertsGenerated: 0,
      threatsDetected: 0,
      anomaliesFound: 0,
      monitoringCycles: 0,
      startTime: Date.now(),
      lastUpdate: Date.now()
    };
  }

  /**
   * Start security monitoring
   */
  async start() {
    try {
      if (this.isRunning) {
        logger.warn('Security monitor is already running');
        return;
      }

      logger.info('Starting security monitor...');

      // Initialize WebSocket server for real-time alerts
      if (this.config.enableRealTimeMonitoring) {
        await this.initializeWebSocketServer();
      }

      // Start monitoring intervals
      this.startMonitoringIntervals();

      // Initialize baseline metrics
      await this.initializeBaselines();

      this.isRunning = true;
      this.stats.startTime = Date.now();

      await AuditLogger.logSystemEvent({
        type: 'SECURITY_MONITOR_STARTED',
        config: this.config,
        timestamp: Date.now()
      });

      logger.info('Security monitor started successfully');

    } catch (error) {
      logger.error('Failed to start security monitor:', error);
      throw error;
    }
  }

  /**
   * Initialize WebSocket server for real-time monitoring
   */
  async initializeWebSocketServer() {
    try {
      this.wss = new WebSocket.Server({
        port: this.config.websocketPort,
        verifyClient: (_info) => {
          // Add authentication here if needed
          return true;
        }
      });

      this.wss.on('connection', (ws, _req) => {
        const connectionId = crypto.randomUUID();
        this.connections.add({ id: connectionId, ws, connectedAt: Date.now() });

        logger.info('New monitoring client connected', { connectionId });

        // Send current status
        this.sendToClient(ws, {
          type: 'status',
          data: {
            isRunning: this.isRunning,
            stats: this.stats,
            activeAlerts: this.getActiveAlerts()
          }
        });

        ws.on('close', () => {
          this.connections.delete(connectionId);
          logger.info('Monitoring client disconnected', { connectionId });
        });

        ws.on('error', (error) => {
          logger.error('WebSocket error:', error);
          this.connections.delete(connectionId);
        });
      });

      this.wss.on('error', (error) => {
        logger.error('WebSocket server error:', error);
      });

      logger.info(`Security monitoring WebSocket server listening on port ${this.config.websocketPort}`);

    } catch (error) {
      logger.error('Failed to initialize WebSocket server:', error);
      throw error;
    }
  }

  /**
   * Start monitoring intervals
   */
  startMonitoringIntervals() {
    // Main monitoring loop
    this.intervalId = setInterval(async () => {
      await this.runMonitoringCycle();
    }, this.config.monitoringInterval);

    // Cleanup expired data every hour
    setInterval(() => {
      this.cleanupExpiredData();
    }, 3600000);

    // Generate hourly security reports
    setInterval(async () => {
      await this.generateSecurityReport();
    }, 3600000);
  }

  /**
   * Initialize baseline metrics for anomaly detection
   */
  async initializeBaselines() {
    try {
      // Collect initial system metrics
      const systemMetrics = await this.collectSystemMetrics();

      // Initialize models with baseline data
      this.models.systemHealth.initialize(systemMetrics);

      // Set initial patterns
      this.patterns.set('baseline', {
        requestRate: 0,
        errorRate: 0,
        cpuUsage: systemMetrics.cpu,
        memoryUsage: systemMetrics.memory,
        timestamp: Date.now()
      });

      logger.info('Security monitoring baselines initialized');

    } catch (error) {
      logger.error('Failed to initialize baselines:', error);
    }
  }

  /**
   * Run a complete monitoring cycle
   */
  async runMonitoringCycle() {
    try {
      this.stats.monitoringCycles++;
      this.stats.lastUpdate = Date.now();

      // Collect current metrics
      const metrics = await this.collectAllMetrics();

      // Store metrics
      this.storeMetrics(metrics);

      // Detect anomalies
      if (this.config.enableAnomalyDetection) {
        await this.detectAnomalies(metrics);
      }

      // Detect threats
      if (this.config.enableThreatDetection) {
        await this.detectThreats(metrics);
      }

      // Update models
      this.updateModels(metrics);

      // Broadcast to connected clients
      this.broadcast({
        type: 'metrics',
        data: metrics,
        timestamp: Date.now()
      });

    } catch (error) {
      logger.error('Error in monitoring cycle:', error);
    }
  }

  /**
   * Collect all security metrics
   */
  async collectAllMetrics() {
    const systemMetrics = await this.collectSystemMetrics();
    const applicationMetrics = await this.collectApplicationMetrics();
    const securityMetrics = await this.collectSecurityMetrics();
    const networkMetrics = await this.collectNetworkMetrics();

    return {
      timestamp: Date.now(),
      system: systemMetrics,
      application: applicationMetrics,
      security: securityMetrics,
      network: networkMetrics
    };
  }

  /**
   * Collect system metrics
   */
  async collectSystemMetrics() {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = await this.getCPUUsage();
    const loadAvg = os.loadavg();

    return {
      cpu: cpuUsage,
      memory: {
        used: memoryUsage.heapUsed,
        total: memoryUsage.heapTotal,
        external: memoryUsage.external,
        percentage: memoryUsage.heapUsed / memoryUsage.heapTotal
      },
      load: {
        avg1: loadAvg[0],
        avg5: loadAvg[1],
        avg15: loadAvg[2]
      },
      uptime: process.uptime(),
      freemem: os.freemem(),
      totalmem: os.totalmem()
    };
  }

  /**
   * Collect application metrics
   */
  async collectApplicationMetrics() {
    // This would integrate with your application metrics
    // For now, we'll return mock data that you can replace
    return {
      requests: this.getRequestCount(),
      errors: this.getErrorCount(),
      responseTime: this.getAverageResponseTime(),
      activeConnections: this.getActiveConnections(),
      databaseConnections: this.getDatabaseConnections(),
      cacheHitRate: this.getCacheHitRate()
    };
  }

  /**
   * Collect security-specific metrics
   */
  async collectSecurityMetrics() {
    return {
      failedLogins: this.getFailedLoginCount(),
      suspiciousRequests: this.getSuspiciousRequestCount(),
      blockedIPs: this.getBlockedIPCount(),
      rateLimit: {
        violations: this.getRateLimitViolations(),
        blocked: this.getRateLimitBlocked()
      },
      authentication: {
        active_sessions: this.getActiveSessionCount(),
        expired_sessions: this.getExpiredSessionCount(),
        revoked_sessions: this.getRevokedSessionCount()
      },
      threats: {
        detected: this.threats.size,
        resolved: this.getResolvedThreatCount(),
        active: this.getActiveThreatCount()
      }
    };
  }

  /**
   * Collect network metrics
   */
  async collectNetworkMetrics() {
    return {
      connections: {
        total: this.getTotalConnections(),
        active: this.getActiveConnections(),
        idle: this.getIdleConnections()
      },
      bandwidth: {
        inbound: this.getInboundBandwidth(),
        outbound: this.getOutboundBandwidth()
      },
      packets: {
        sent: this.getPacketsSent(),
        received: this.getPacketsReceived(),
        dropped: this.getPacketsDropped()
      }
    };
  }

  /**
   * Store metrics with timestamp
   */
  storeMetrics(metrics) {
    this.metrics.set(metrics.timestamp, metrics);

    // Keep only recent metrics
    const cutoff = Date.now() - this.config.retentionPeriod;
    for (const [timestamp] of this.metrics) {
      if (timestamp < cutoff) {
        this.metrics.delete(timestamp);
      }
    }
  }

  /**
   * Detect anomalies in metrics
   */
  async detectAnomalies(metrics) {
    const anomalies = [];

    // CPU usage anomaly
    if (metrics.system.cpu > this.thresholds.resourceUsage.cpu) {
      anomalies.push({
        type: 'HIGH_CPU_USAGE',
        severity: 'medium',
        value: metrics.system.cpu,
        threshold: this.thresholds.resourceUsage.cpu,
        details: {
          current: metrics.system.cpu,
          normal_range: '< 80%'
        }
      });
    }

    // Memory usage anomaly
    if (metrics.system.memory.percentage > this.thresholds.resourceUsage.memory) {
      anomalies.push({
        type: 'HIGH_MEMORY_USAGE',
        severity: 'medium',
        value: metrics.system.memory.percentage,
        threshold: this.thresholds.resourceUsage.memory,
        details: {
          used: metrics.system.memory.used,
          total: metrics.system.memory.total
        }
      });
    }

    // Request rate anomaly
    const requestRate = this.calculateRequestRate(metrics);
    const normalRequestRate = this.getNormalRequestRate();

    if (requestRate > normalRequestRate * this.thresholds.ddosIndicators.requestSpike) {
      anomalies.push({
        type: 'REQUEST_RATE_SPIKE',
        severity: 'high',
        value: requestRate,
        threshold: normalRequestRate * this.thresholds.ddosIndicators.requestSpike,
        details: {
          current_rate: requestRate,
          normal_rate: normalRequestRate,
          spike_factor: requestRate / normalRequestRate
        }
      });
    }

    // Error rate anomaly
    const errorRate = this.calculateErrorRate(metrics);
    const normalErrorRate = this.getNormalErrorRate();

    if (errorRate > normalErrorRate * this.thresholds.ddosIndicators.errorSpike) {
      anomalies.push({
        type: 'ERROR_RATE_SPIKE',
        severity: 'high',
        value: errorRate,
        threshold: normalErrorRate * this.thresholds.ddosIndicators.errorSpike,
        details: {
          current_rate: errorRate,
          normal_rate: normalErrorRate,
          spike_factor: errorRate / normalErrorRate
        }
      });
    }

    // Machine learning-based anomalies
    const mlAnomalies = await this.detectMLAnomalies(metrics);
    anomalies.push(...mlAnomalies);

    // Process detected anomalies
    for (const anomaly of anomalies) {
      await this.handleAnomaly(anomaly, metrics);
    }

    return anomalies;
  }

  /**
   * Detect threats using pattern analysis
   */
  async detectThreats(metrics) {
    const threats = [];

    // DDoS attack detection
    const ddosThreat = await this.detectDDoSAttack(metrics);
    if (ddosThreat) threats.push(ddosThreat);

    // Brute force attack detection
    const bruteForceThreat = await this.detectBruteForceAttack(metrics);
    if (bruteForceThreat) threats.push(bruteForceThreat);

    // Scanning activity detection
    const scanningThreat = await this.detectScanningActivity(metrics);
    if (scanningThreat) threats.push(scanningThreat);

    // Data exfiltration detection
    const exfiltrationThreat = await this.detectDataExfiltration(metrics);
    if (exfiltrationThreat) threats.push(exfiltrationThreat);

    // Process detected threats
    for (const threat of threats) {
      await this.handleThreat(threat, metrics);
    }

    return threats;
  }

  /**
   * Detect DDoS attacks
   */
  async detectDDoSAttack(metrics) {
    const recentMetrics = this.getRecentMetrics(this.config.threatWindow);

    // Calculate attack indicators
    const requestSpike = this.calculateRequestSpike(recentMetrics);
    const uniqueIPs = this.getUniqueIPCount(recentMetrics);
    const errorSpike = this.calculateErrorSpike(recentMetrics);

    const ddosScore = this.calculateDDoSScore({
      requestSpike,
      uniqueIPs,
      errorSpike,
      systemLoad: metrics.system.load.avg1
    });

    if (ddosScore > this.config.alertThreshold) {
      return {
        type: 'DDOS_ATTACK',
        severity: 'critical',
        score: ddosScore,
        indicators: {
          requestSpike,
          uniqueIPs,
          errorSpike,
          systemLoad: metrics.system.load.avg1
        },
        details: {
          duration: this.config.threatWindow,
          affectedSystems: ['api', 'database'],
          mitigationSuggestions: [
            'Enable rate limiting',
            'Block suspicious IPs',
            'Scale infrastructure'
          ]
        }
      };
    }

    return null;
  }

  /**
   * Detect brute force attacks
   */
  async detectBruteForceAttack(metrics) {
    const failedLogins = metrics.security.failedLogins;
    const threshold = this.thresholds.failedLogins;

    if (failedLogins > threshold.count) {
      return {
        type: 'BRUTE_FORCE_ATTACK',
        severity: 'high',
        value: failedLogins,
        threshold: threshold.count,
        details: {
          failed_attempts: failedLogins,
          time_window: threshold.window,
          targeted_accounts: this.getTargetedAccounts(),
          source_ips: this.getAttackSourceIPs()
        }
      };
    }

    return null;
  }

  /**
   * Handle detected anomaly
   */
  async handleAnomaly(anomaly, metrics) {
    try {
      this.stats.anomaliesFound++;

      const alertId = crypto.randomUUID();
      const alert = {
        id: alertId,
        type: 'anomaly',
        anomaly,
        metrics,
        timestamp: Date.now(),
        status: 'active',
        acknowledged: false
      };

      this.alerts.set(alertId, alert);

      // Log the anomaly
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_ANOMALY_DETECTED',
        anomaly,
        metrics: this.sanitizeMetrics(metrics),
        alertId,
        timestamp: Date.now()
      });

      // Emit event for external handling
      this.emit('anomalyDetected', {
        alert,
        anomaly,
        metrics
      });

      // Broadcast to connected clients
      this.broadcast({
        type: 'anomaly',
        data: alert
      });

      logger.warn('Security anomaly detected:', {
        type: anomaly.type,
        severity: anomaly.severity,
        alertId
      });

    } catch (error) {
      logger.error('Failed to handle anomaly:', error);
    }
  }

  /**
   * Handle detected threat
   */
  async handleThreat(threat, metrics) {
    try {
      this.stats.threatsDetected++;

      const threatId = crypto.randomUUID();
      const threatAlert = {
        id: threatId,
        type: 'threat',
        threat,
        metrics,
        timestamp: Date.now(),
        status: 'active',
        mitigated: false
      };

      this.threats.set(threatId, threatAlert);

      // Log the threat
      await AuditLogger.logSecurityEvent({
        type: 'SECURITY_THREAT_DETECTED',
        threat,
        metrics: this.sanitizeMetrics(metrics),
        threatId,
        timestamp: Date.now()
      });

      // Emit event for external handling
      this.emit('threatDetected', {
        alert: threatAlert,
        threat,
        metrics
      });

      // Immediate response for critical threats
      if (threat.severity === 'critical') {
        await this.handleCriticalThreat(threat, threatAlert);
      }

      // Broadcast to connected clients
      this.broadcast({
        type: 'threat',
        data: threatAlert
      });

      logger.error('Security threat detected:', {
        type: threat.type,
        severity: threat.severity,
        threatId
      });

    } catch (error) {
      logger.error('Failed to handle threat:', error);
    }
  }

  /**
   * Handle critical security threats
   */
  async handleCriticalThreat(threat, threatAlert) {
    try {
      logger.error('CRITICAL SECURITY THREAT DETECTED:', threat);

      // Emit critical security alert
      this.emit('securityAlert', {
        type: threat.type,
        severity: 'critical',
        threat,
        alert: threatAlert,
        timestamp: Date.now()
      });

      // Auto-mitigation for known threat types
      switch (threat.type) {
        case 'DDOS_ATTACK':
          await this.mitigateDDoSAttack(threat);
          break;
        case 'BRUTE_FORCE_ATTACK':
          await this.mitigateBruteForceAttack(threat);
          break;
        case 'DATA_EXFILTRATION':
          await this.mitigateDataExfiltration(threat);
          break;
      }

      // Log critical threat response
      await AuditLogger.logSecurityEvent({
        type: 'CRITICAL_THREAT_RESPONSE',
        threat,
        threatId: threatAlert.id,
        timestamp: Date.now()
      });

    } catch (error) {
      logger.error('Failed to handle critical threat:', error);
    }
  }

  /**
   * Calculate DDoS attack score
   */
  calculateDDoSScore(indicators) {
    const weights = {
      requestSpike: 0.4,
      uniqueIPs: 0.3,
      errorSpike: 0.2,
      systemLoad: 0.1
    };

    const scores = {
      requestSpike: Math.min(1, indicators.requestSpike / 10),
      uniqueIPs: Math.min(1, indicators.uniqueIPs / 1000),
      errorSpike: Math.min(1, indicators.errorSpike / 5),
      systemLoad: Math.min(1, indicators.systemLoad / 4)
    };

    return Object.keys(weights).reduce((total, key) => {
      // eslint-disable-next-line security/detect-object-injection
      return total + (scores[key] * weights[key]);
    }, 0);
  }

  /**
   * Machine learning-based anomaly detection
   */
  async detectMLAnomalies(metrics) {
    const anomalies = [];

    try {
      // Request pattern anomalies
      const requestAnomalies = await this.models.requestPattern.detect(metrics);
      anomalies.push(...requestAnomalies);

      // User behavior anomalies
      const behaviorAnomalies = await this.models.userBehavior.detect(metrics);
      anomalies.push(...behaviorAnomalies);

      // System health anomalies
      const healthAnomalies = await this.models.systemHealth.detect(metrics);
      anomalies.push(...healthAnomalies);

    } catch (error) {
      logger.error('ML anomaly detection failed:', error);
    }

    return anomalies;
  }

  /**
   * Update machine learning models
   */
  updateModels(metrics) {
    try {
      this.models.requestPattern.update(metrics);
      this.models.userBehavior.update(metrics);
      this.models.systemHealth.update(metrics);
    } catch (error) {
      logger.error('Failed to update ML models:', error);
    }
  }

  /**
   * Get recent metrics within time window
   */
  getRecentMetrics(timeWindow) {
    const cutoff = Date.now() - timeWindow;
    const recentMetrics = [];

    for (const [timestamp, metrics] of this.metrics) {
      if (timestamp >= cutoff) {
        recentMetrics.push(metrics);
      }
    }

    return recentMetrics.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Broadcast message to all connected clients
   */
  broadcast(message) {
    if (!this.wss) return;

    const messageStr = JSON.stringify(message);

    this.wss.clients.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(messageStr);
        } catch (error) {
          logger.error('Failed to send WebSocket message:', error);
        }
      }
    });
  }

  /**
   * Send message to specific client
   */
  sendToClient(ws, message) {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(message));
      } catch (error) {
        logger.error('Failed to send message to client:', error);
      }
    }
  }

  /**
   * Get active alerts
   */
  getActiveAlerts() {
    const activeAlerts = [];

    for (const [_id, alert] of this.alerts) {
      if (alert.status === 'active' && !alert.acknowledged) {
        activeAlerts.push(alert);
      }
    }

    return activeAlerts;
  }

  /**
   * Clean up expired data
   */
  cleanupExpiredData() {
    const now = Date.now();
    const cutoff = now - this.config.retentionPeriod;

    // Clean up old metrics
    for (const [timestamp] of this.metrics) {
      if (timestamp < cutoff) {
        this.metrics.delete(timestamp);
      }
    }

    // Clean up old alerts
    for (const [id, alert] of this.alerts) {
      if (alert.timestamp < cutoff) {
        this.alerts.delete(id);
      }
    }

    // Clean up old threats
    for (const [id, threat] of this.threats) {
      if (threat.timestamp < cutoff) {
        this.threats.delete(id);
      }
    }

    logger.debug('Security monitor data cleanup completed');
  }

  /**
   * Generate security report
   */
  async generateSecurityReport() {
    try {
      const report = {
        timestamp: Date.now(),
        period: 'hourly',
        stats: this.stats,
        metrics: {
          system: await this.collectSystemMetrics(),
          application: await this.collectApplicationMetrics(),
          security: await this.collectSecurityMetrics()
        },
        alerts: {
          total: this.alerts.size,
          active: this.getActiveAlerts().length,
          byType: this.getAlertsByType(),
          bySeverity: this.getAlertsBySeverity()
        },
        threats: {
          total: this.threats.size,
          active: this.getActiveThreats().length,
          byType: this.getThreatsByType(),
          mitigated: this.getMitigatedThreats().length
        }
      };

      await AuditLogger.logSystemEvent({
        type: 'SECURITY_HOURLY_REPORT',
        report,
        timestamp: Date.now()
      });

      this.broadcast({
        type: 'report',
        data: report
      });

    } catch (error) {
      logger.error('Failed to generate security report:', error);
    }
  }

  /**
   * Sanitize metrics for logging (remove sensitive data)
   */
  sanitizeMetrics(metrics) {
    return {
      timestamp: metrics.timestamp,
      system: {
        cpu: metrics.system.cpu,
        memory: metrics.system.memory.percentage,
        load: metrics.system.load.avg1
      },
      application: {
        requests: metrics.application.requests,
        errors: metrics.application.errors,
        responseTime: metrics.application.responseTime
      },
      security: {
        failedLogins: metrics.security.failedLogins,
        suspiciousRequests: metrics.security.suspiciousRequests,
        blockedIPs: metrics.security.blockedIPs
      }
    };
  }

  // Placeholder methods for metric collection (to be implemented based on your specific application)

  getCPUUsage() {
    // This would implement actual CPU usage calculation
    return Math.random() * 100;
  }

  getRequestCount() { return Math.floor(Math.random() * 1000); }
  getErrorCount() { return Math.floor(Math.random() * 50); }
  getAverageResponseTime() { return Math.random() * 1000; }
  getActiveConnections() { return Math.floor(Math.random() * 100); }
  getDatabaseConnections() { return Math.floor(Math.random() * 50); }
  getCacheHitRate() { return Math.random(); }
  getFailedLoginCount() { return Math.floor(Math.random() * 10); }
  getSuspiciousRequestCount() { return Math.floor(Math.random() * 20); }
  getBlockedIPCount() { return Math.floor(Math.random() * 30); }
  getRateLimitViolations() { return Math.floor(Math.random() * 15); }
  getRateLimitBlocked() { return Math.floor(Math.random() * 10); }
  getActiveSessionCount() { return Math.floor(Math.random() * 200); }
  getExpiredSessionCount() { return Math.floor(Math.random() * 50); }
  getRevokedSessionCount() { return Math.floor(Math.random() * 10); }
  getResolvedThreatCount() { return Math.floor(Math.random() * 5); }
  getActiveThreatCount() { return Math.floor(Math.random() * 3); }
  getTotalConnections() { return Math.floor(Math.random() * 500); }
  getIdleConnections() { return Math.floor(Math.random() * 100); }
  getInboundBandwidth() { return Math.random() * 1000000; }
  getOutboundBandwidth() { return Math.random() * 1000000; }
  getPacketsSent() { return Math.floor(Math.random() * 10000); }
  getPacketsReceived() { return Math.floor(Math.random() * 10000); }
  getPacketsDropped() { return Math.floor(Math.random() * 100); }

  calculateRequestRate(metrics) { return metrics.application.requests / 60; }
  calculateErrorRate(metrics) { return metrics.application.errors / metrics.application.requests; }
  getNormalRequestRate() { return 100; }
  getNormalErrorRate() { return 0.01; }
  calculateRequestSpike(_metrics) { return 1.5; }
  calculateErrorSpike(_metrics) { return 2.0; }
  getUniqueIPCount(_metrics) { return 50; }
  getTargetedAccounts() { return ['admin', 'user1', 'user2']; }
  getAttackSourceIPs() { return ['192.168.1.100', '10.0.0.50']; }
  getAlertsByType() { return { anomaly: 10, threat: 5 }; }
  getAlertsBySeverity() { return { low: 8, medium: 5, high: 2, critical: 0 }; }
  getActiveThreats() { return Array.from(this.threats.values()).filter(t => t.status === 'active'); }
  getThreatsByType() { return { ddos: 1, brute_force: 2, scanning: 1 }; }
  getMitigatedThreats() { return Array.from(this.threats.values()).filter(t => t.mitigated); }

  async mitigateDDoSAttack(threat) {
    logger.info('Mitigating DDoS attack:', threat.type);
  }

  async mitigateBruteForceAttack(threat) {
    logger.info('Mitigating brute force attack:', threat.type);
  }

  async mitigateDataExfiltration(threat) {
    logger.info('Mitigating data exfiltration:', threat.type);
  }

  async detectScanningActivity(_metrics) { return null; }
  async detectDataExfiltration(_metrics) { return null; }

  /**
   * Stop security monitoring
   */
  async stop() {
    try {
      if (!this.isRunning) {
        logger.warn('Security monitor is not running');
        return;
      }

      logger.info('Stopping security monitor...');

      // Clear intervals
      if (this.intervalId) {
        clearInterval(this.intervalId);
        this.intervalId = null;
      }

      // Close WebSocket server
      if (this.wss) {
        this.wss.close();
        this.wss = null;
      }

      this.isRunning = false;

      await AuditLogger.logSystemEvent({
        type: 'SECURITY_MONITOR_STOPPED',
        stats: this.stats,
        timestamp: Date.now()
      });

      logger.info('Security monitor stopped successfully');

    } catch (error) {
      logger.error('Failed to stop security monitor:', error);
      throw error;
    }
  }

  /**
   * Get monitoring statistics
   */
  getStats() {
    return {
      ...this.stats,
      isRunning: this.isRunning,
      connectedClients: this.wss ? this.wss.clients.size : 0,
      config: this.config,
      uptime: Date.now() - this.stats.startTime
    };
  }
}

/**
 * Simple machine learning models for anomaly detection
 */
class RequestPatternModel {
  constructor() {
    this.patterns = [];
    this.baseline = null;
  }

  initialize(metrics) {
    this.baseline = metrics;
  }

  async detect(_metrics) {
    // Simple pattern-based detection
    return [];
  }

  update(metrics) {
    this.patterns.push(metrics);
    if (this.patterns.length > 100) {
      this.patterns.shift();
    }
  }
}

class UserBehaviorModel {
  constructor() {
    this.behaviors = new Map();
  }

  async detect(_metrics) {
    return [];
  }

  update(_metrics) {
    // Update user behavior patterns
  }
}

class SystemHealthModel {
  constructor() {
    this.healthHistory = [];
  }

  initialize(metrics) {
    this.healthHistory.push(metrics);
  }

  async detect(_metrics) {
    return [];
  }

  update(metrics) {
    this.healthHistory.push(metrics);
    if (this.healthHistory.length > 1000) {
      this.healthHistory.shift();
    }
  }
}

module.exports = SecurityMonitor;
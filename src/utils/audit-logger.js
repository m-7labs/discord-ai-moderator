const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const logger = require('./logger');

class AuditLogger {
  constructor() {
    this.logPath = path.join(process.cwd(), 'logs', 'audit');
  }

  async log(event) {
    try {
      // Simple file-based logging for now
      const logEntry = {
        eventId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        ...event
      };

      logger.info('Audit event', logEntry);
      return logEntry;
    } catch (error) {
      logger.error('Failed to log audit event', { error: error.message });
    }
  }

  async logSecurityEvent(event) {
    return this.log({ type: 'SECURITY_EVENT', ...event });
  }

  async logSystemEvent(event) {
    return this.log({ type: 'SYSTEM_EVENT', ...event });
  }

  async initialize() {
    // Simple initialization - just ensure log directory exists
    try {
      const logDir = path.dirname(this.logPath);
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      await fs.mkdir(logDir, { recursive: true });
      logger.info('AuditLogger initialized');
      return true;
    } catch (error) {
      logger.error('Failed to initialize AuditLogger', { error: error.message });
      return false;
    }
  }
}

module.exports = new AuditLogger();
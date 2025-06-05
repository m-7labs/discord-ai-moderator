const crypto = require('crypto');
const logger = require('./logger');

class PrivacyManager {
  constructor() {
    this.anonymizationKey = process.env.ANONYMIZATION_KEY || 'default-key';
  }

  // Anonymize user data
  anonymizeUserId(userId) {
    try {
      return crypto.createHash('sha256')
        .update(userId + this.anonymizationKey)
        .digest('hex')
        .substring(0, 16);
    } catch (error) {
      logger.error('Failed to anonymize user ID', { error: error.message });
      return null;
    }
  }

  // Anonymize IP addresses
  anonymizeIP(ip) {
    try {
      return crypto.createHash('sha256')
        .update(ip + this.anonymizationKey)
        .digest('hex')
        .substring(0, 12);
    } catch (error) {
      logger.error('Failed to anonymize IP', { error: error.message });
      return null;
    }
  }

  // Check if data should be retained
  shouldRetainData(createdAt, retentionDays = 90) {
    const retentionMs = retentionDays * 24 * 60 * 60 * 1000;
    const age = Date.now() - new Date(createdAt).getTime();
    return age < retentionMs;
  }

  // Simple GDPR compliance check
  isGDPRCompliant(data) {
    // Basic compliance check - can be expanded
    return data && typeof data === 'object';
  }
}

module.exports = new PrivacyManager();
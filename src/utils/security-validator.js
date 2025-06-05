// Enhanced security validator
class SecurityValidator {
  static validateDiscordId(id, context = 'general') {
    if (!id || typeof id !== 'string') return false;
    // Discord IDs are 17-19 digit snowflakes
    return /^\d{17,19}$/.test(id);
  }

  static validateUserId(userId) {
    return this.validateDiscordId(userId, 'user');
  }

  static validateServerId(serverId) {
    return this.validateDiscordId(serverId, 'server');
  }

  static validateChannelId(channelId) {
    return this.validateDiscordId(channelId, 'channel');
  }

  static validateMessageId(messageId) {
    return this.validateDiscordId(messageId, 'message');
  }

  static sanitizeMessageContent(content) {
    if (!content) return '';
    return String(content).trim().substring(0, 2000); // Discord message limit
  }

  static sanitizeInput(input) {
    if (!input) return '';
    return String(input).trim().replace(/[<>]/g, ''); // Basic XSS prevention
  }

  static validatePermissionLevel(level) {
    const validLevels = ['admin', 'moderator', 'user'];
    return validLevels.includes(level);
  }

  static validateStrictness(strictness) {
    const num = parseInt(strictness);
    return !isNaN(num) && num >= 1 && num <= 10;
  }

  static createSecurityError(message, metadata = {}) {
    const error = new Error(message);
    error.isSecurityError = true;
    error.metadata = metadata;
    return error;
  }

  static validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static validateUrl(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  static validateJson(str) {
    try {
      JSON.parse(str);
      return true;
    } catch {
      return false;
    }
  }

  static validateApiKey(key) {
    if (!key || typeof key !== 'string') return false;
    return key.length >= 20 && key.length <= 200;
  }

  static validateIpAddress(ip) {
    if (!ip || typeof ip !== 'string') return false;
    // Basic IPv4/IPv6 validation
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  static sanitizeFilename(filename) {
    if (!filename) return 'unnamed';
    return filename.replace(/[^a-zA-Z0-9.-]/g, '_').substring(0, 100);
  }

  static validateArrayLength(arr, maxLength = 100) {
    return Array.isArray(arr) && arr.length <= maxLength;
  }

  static validateStringLength(str, maxLength = 1000) {
    return typeof str === 'string' && str.length <= maxLength;
  }
}

module.exports = SecurityValidator;
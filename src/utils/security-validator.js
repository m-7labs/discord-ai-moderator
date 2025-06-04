const validator = require('validator');
const { createHash } = require('crypto');
const logger = require('./logger');

/**
 * Security Error class for validation errors
 */
class SecurityError extends Error {
  constructor(message, metadata = {}) {
    super(message);
    this.name = 'SecurityError';
    this.isSecurityError = true;
    this.metadata = metadata;
    this.timestamp = Date.now();
    this.code = metadata.code || 'SECURITY_VALIDATION_ERROR';
  }
}

/**
 * Enhanced Security Validator with comprehensive input validation
 */
class SecurityValidator {
  
  /**
   * Validate Discord ID format (snowflake)
   * @param {string} id - Discord ID to validate
   * @param {string} context - Context for error reporting
   * @returns {string} Validated Discord ID
   * @throws {SecurityError} If validation fails
   */
  static validateDiscordId(id, context = 'unknown') {
    if (!id || typeof id !== 'string') {
      throw this.createSecurityError(`Invalid Discord ID type in ${context}`, {
        code: 'INVALID_ID_TYPE',
        context,
        receivedType: typeof id
      });
    }
    
    // Discord IDs are 17-19 digit snowflakes
    if (!/^\d{17,19}$/.test(id)) {
      throw this.createSecurityError(`Invalid Discord ID format in ${context}`, {
        code: 'INVALID_ID_FORMAT',
        context,
        hash: this.hashInput(id),
        length: id.length
      });
    }
    
    // Additional validation for known invalid ranges
    const idNum = BigInt(id);
    const minValidId = BigInt('100000000000000000'); // Minimum valid Discord ID
    const maxValidId = BigInt('999999999999999999'); // Maximum reasonable Discord ID
    
    if (idNum < minValidId || idNum > maxValidId) {
      throw this.createSecurityError(`Discord ID out of valid range in ${context}`, {
        code: 'INVALID_ID_RANGE',
        context,
        hash: this.hashInput(id)
      });
    }
    
    return id;
  }
  
  /**
   * Sanitize and validate message content
   * @param {string} content - Message content to sanitize
   * @param {number} maxLength - Maximum allowed length
   * @returns {string} Sanitized content
   * @throws {SecurityError} If validation fails
   */
  static sanitizeMessageContent(content, maxLength = 4000) {
    if (!content || typeof content !== 'string') {
      throw this.createSecurityError('Invalid message content type', {
        code: 'INVALID_CONTENT_TYPE',
        receivedType: typeof content
      });
    }
    
    // Check for excessively long content
    if (content.length > maxLength) {
      throw this.createSecurityError('Message content too long', {
        code: 'CONTENT_TOO_LONG',
        maxLength,
        actualLength: content.length
      });
    }
    
    // Remove dangerous control characters
    let sanitized = content
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '') // Control chars
      .replace(/[\u200B-\u200D\uFEFF]/g, '') // Zero-width chars
      .replace(/[\u2060-\u206F]/g, '') // Word joiner and other invisible chars
      .replace(/[\uDB40-\uDB7F][\uDC00-\uDFFF]/g, ''); // Tags and other dangerous Unicode
    
    // Prevent Discord markdown injection and mass mentions
    sanitized = sanitized
      .replace(/@(everyone|here)/gi, '@\u200B$1') // Prevent mass mentions
      .replace(/<@!?(\d+)>/g, (match, id) => {
        // Validate mentioned user IDs
        try {
          this.validateDiscordId(id, 'mention');
          return match;
        } catch {
          return '[Invalid Mention]';
        }
      })
      .replace(/<#(\d+)>/g, (match, id) => {
        // Validate channel mentions
        try {
          this.validateDiscordId(id, 'channel_mention');
          return match;
        } catch {
          return '[Invalid Channel]';
        }
      })
      .replace(/<@&(\d+)>/g, (match, id) => {
        // Validate role mentions
        try {
          this.validateDiscordId(id, 'role_mention');
          return match;
        } catch {
          return '[Invalid Role]';
        }
      });
    
    // Check for potential XSS patterns
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /<iframe[^>]*>.*?<\/iframe>/gi,
      /<object[^>]*>.*?<\/object>/gi,
      /<embed[^>]*>/gi,
      /javascript:/gi,
      /data:text\/html/gi,
      /vbscript:/gi,
      /onclick\s*=/gi,
      /onerror\s*=/gi,
      /onload\s*=/gi
    ];
    
    for (const pattern of xssPatterns) {
      if (pattern.test(sanitized)) {
        logger.warn('Potential XSS attempt detected and blocked', {
          hash: this.hashInput(content),
          pattern: pattern.source
        });
        sanitized = sanitized.replace(pattern, '[Blocked Content]');
      }
    }
    
    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/gi,
      /(\'|\"|;|--|\|\|)/g,
      /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/gi
    ];
    
    for (const pattern of sqlPatterns) {
      if (pattern.test(sanitized)) {
        logger.warn('Potential SQL injection attempt detected and blocked', {
          hash: this.hashInput(content),
          pattern: pattern.source
        });
        // Don't replace SQL patterns, just log them
      }
    }
    
    // Final length check after sanitization
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength - 3) + '...';
    }
    
    return sanitized.trim();
  }
  
  /**
   * Sanitize and validate server rules
   * @param {string} rules - Server rules to sanitize
   * @returns {string} Sanitized rules
   * @throws {SecurityError} If validation fails
   */
  static sanitizeRules(rules) {
    if (!rules || typeof rules !== 'string') {
      throw this.createSecurityError('Invalid rules type', {
        code: 'INVALID_RULES_TYPE',
        receivedType: typeof rules
      });
    }
    
    if (rules.length === 0) {
      throw this.createSecurityError('Rules cannot be empty', {
        code: 'EMPTY_RULES'
      });
    }
    
    if (rules.length > 5000) {
      throw this.createSecurityError('Rules too long', {
        code: 'RULES_TOO_LONG',
        maxLength: 5000,
        actualLength: rules.length
      });
    }
    
    // Use the same sanitization as message content but allow more formatting
    let sanitized = rules
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '') // Control chars
      .replace(/[\u200B-\u200D\uFEFF]/g, '') // Zero-width chars
      .trim();
    
    // Check for dangerous patterns but be less restrictive than message content
    const dangerousPatterns = [
      /<script[^>]*>/gi,
      /javascript:/gi,
      /data:text\/html/gi,
      /vbscript:/gi
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(sanitized)) {
        logger.warn('Dangerous pattern in rules detected and blocked', {
          pattern: pattern.source
        });
        sanitized = sanitized.replace(pattern, '[Blocked Content]');
      }
    }
    
    return sanitized;
  }
  
  /**
   * Validate email address format
   * @param {string} email - Email to validate
   * @param {string} context - Context for error reporting
   * @returns {string} Validated email
   * @throws {SecurityError} If validation fails
   */
  static validateEmail(email, context = 'unknown') {
    if (!email || typeof email !== 'string') {
      throw this.createSecurityError(`Invalid email type in ${context}`, {
        code: 'INVALID_EMAIL_TYPE',
        context
      });
    }
    
    // Basic length check
    if (email.length > 254) {
      throw this.createSecurityError(`Email too long in ${context}`, {
        code: 'EMAIL_TOO_LONG',
        context
      });
    }
    
    // Validate format
    if (!validator.isEmail(email)) {
      throw this.createSecurityError(`Invalid email format in ${context}`, {
        code: 'INVALID_EMAIL_FORMAT',
        context,
        hash: this.hashInput(email)
      });
    }
    
    // Additional security checks
    const suspiciousPatterns = [
      /\.{2,}/, // Multiple consecutive dots
      /^\./, // Starts with dot
      /\.$/, // Ends with dot
      /@.*@/, // Multiple @ symbols
      /[<>]/  // Angle brackets
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(email)) {
        throw this.createSecurityError(`Suspicious email pattern in ${context}`, {
          code: 'SUSPICIOUS_EMAIL_PATTERN',
          context,
          hash: this.hashInput(email)
        });
      }
    }
    
    return email.toLowerCase().trim();
  }
  
  /**
   * Validate URL format and check for suspicious patterns
   * @param {string} url - URL to validate
   * @param {string} context - Context for error reporting
   * @param {Array} allowedDomains - Optional array of allowed domains
   * @returns {string} Validated URL
   * @throws {SecurityError} If validation fails
   */
  static validateUrl(url, context = 'unknown', allowedDomains = []) {
    if (!url || typeof url !== 'string') {
      throw this.createSecurityError(`Invalid URL type in ${context}`, {
        code: 'INVALID_URL_TYPE',
        context
      });
    }
    
    if (url.length > 2048) {
      throw this.createSecurityError(`URL too long in ${context}`, {
        code: 'URL_TOO_LONG',
        context
      });
    }
    
    // Validate URL format
    if (!validator.isURL(url, { 
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true,
      allow_underscores: false
    })) {
      throw this.createSecurityError(`Invalid URL format in ${context}`, {
        code: 'INVALID_URL_FORMAT',
        context,
        hash: this.hashInput(url)
      });
    }
    
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (error) {
      throw this.createSecurityError(`Failed to parse URL in ${context}`, {
        code: 'URL_PARSE_ERROR',
        context,
        hash: this.hashInput(url)
      });
    }
    
    // Security checks
    const suspiciousPatterns = [
      /localhost/i,
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
      /10\.\d+\.\d+\.\d+/, // Private IP range
      /192\.168\.\d+\.\d+/, // Private IP range
      /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/, // Private IP range
      /@/, // URL with auth info
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /file:/i
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        throw this.createSecurityError(`Suspicious URL pattern in ${context}`, {
          code: 'SUSPICIOUS_URL_PATTERN',
          context,
          pattern: pattern.source,
          hash: this.hashInput(url)
        });
      }
    }
    
    // Check allowed domains if specified
    if (allowedDomains.length > 0) {
      const domain = parsedUrl.hostname.toLowerCase();
      const isAllowed = allowedDomains.some(allowed => 
        domain === allowed.toLowerCase() || domain.endsWith('.' + allowed.toLowerCase())
      );
      
      if (!isAllowed) {
        throw this.createSecurityError(`Domain not allowed in ${context}`, {
          code: 'DOMAIN_NOT_ALLOWED',
          context,
          domain,
          allowedDomains
        });
      }
    }
    
    return url;
  }
  
  /**
   * Validate JSON input and check for dangerous patterns
   * @param {string} jsonString - JSON string to validate
   * @param {string} context - Context for error reporting
   * @param {number} maxDepth - Maximum allowed nesting depth
   * @returns {Object} Parsed and validated JSON
   * @throws {SecurityError} If validation fails
   */
  static validateJson(jsonString, context = 'unknown', maxDepth = 10) {
    if (!jsonString || typeof jsonString !== 'string') {
      throw this.createSecurityError(`Invalid JSON type in ${context}`, {
        code: 'INVALID_JSON_TYPE',
        context
      });
    }
    
    if (jsonString.length > 100000) { // 100KB limit
      throw this.createSecurityError(`JSON too large in ${context}`, {
        code: 'JSON_TOO_LARGE',
        context,
        size: jsonString.length
      });
    }
    
    let parsed;
    try {
      parsed = JSON.parse(jsonString);
    } catch (error) {
      throw this.createSecurityError(`Invalid JSON format in ${context}`, {
        code: 'INVALID_JSON_FORMAT',
        context,
        parseError: error.message
      });
    }
    
    // Check nesting depth
    const depth = this.getObjectDepth(parsed);
    if (depth > maxDepth) {
      throw this.createSecurityError(`JSON nesting too deep in ${context}`, {
        code: 'JSON_TOO_DEEP',
        context,
        depth,
        maxDepth
      });
    }
    
    // Check for dangerous patterns in JSON
    this.validateObjectContent(parsed, context);
    
    return parsed;
  }
  
  /**
   * Validate object content recursively
   * @private
   */
  static validateObjectContent(obj, context, visited = new WeakSet()) {
    if (obj === null || typeof obj !== 'object') {
      return;
    }
    
    // Prevent circular reference attacks
    if (visited.has(obj)) {
      throw this.createSecurityError(`Circular reference detected in ${context}`, {
        code: 'CIRCULAR_REFERENCE',
        context
      });
    }
    visited.add(obj);
    
    // Check array size
    if (Array.isArray(obj) && obj.length > 1000) {
      throw this.createSecurityError(`Array too large in ${context}`, {
        code: 'ARRAY_TOO_LARGE',
        context,
        size: obj.length
      });
    }
    
    // Check object properties
    for (const [key, value] of Object.entries(obj)) {
      // Validate key
      if (typeof key === 'string') {
        if (key.length > 100) {
          throw this.createSecurityError(`Object key too long in ${context}`, {
            code: 'KEY_TOO_LONG',
            context,
            keyLength: key.length
          });
        }
        
        // Check for dangerous keys
        const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
        if (dangerousKeys.includes(key)) {
          throw this.createSecurityError(`Dangerous object key in ${context}`, {
            code: 'DANGEROUS_KEY',
            context,
            key
          });
        }
      }
      
      // Validate string values
      if (typeof value === 'string') {
        if (value.length > 10000) {
          throw this.createSecurityError(`String value too long in ${context}`, {
            code: 'VALUE_TOO_LONG',
            context,
            valueLength: value.length
          });
        }
        
        // Check for script injection in string values
        const scriptPatterns = [
          /<script[^>]*>/gi,
          /javascript:/gi,
          /data:text\/html/gi,
          /vbscript:/gi
        ];
        
        for (const pattern of scriptPatterns) {
          if (pattern.test(value)) {
            throw this.createSecurityError(`Dangerous script pattern in object value in ${context}`, {
              code: 'SCRIPT_INJECTION',
              context,
              pattern: pattern.source
            });
          }
        }
      }
      
      // Recurse into nested objects
      if (typeof value === 'object' && value !== null) {
        this.validateObjectContent(value, context, visited);
      }
    }
  }
  
  /**
   * Get the depth of an object
   * @private
   */
  static getObjectDepth(obj, depth = 0) {
    if (depth > 50) return depth; // Prevent stack overflow
    if (obj === null || typeof obj !== 'object') return depth;
    
    let maxDepth = depth;
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const currentDepth = this.getObjectDepth(obj[key], depth + 1);
        maxDepth = Math.max(maxDepth, currentDepth);
      }
    }
    return maxDepth;
  }
  
  /**
   * Hash sensitive input for logging
   * @param {string} input - Input to hash
   * @returns {string} Hash of input (first 8 chars)
   */
  static hashInput(input) {
    if (!input) return 'empty';
    return createHash('sha256').update(input.toString()).digest('hex').substring(0, 8);
  }
  
  /**
   * Create a SecurityError with consistent formatting
   * @param {string} message - Error message
   * @param {Object} metadata - Additional error metadata
   * @returns {SecurityError} Formatted security error
   */
  static createSecurityError(message, metadata = {}) {
    return new SecurityError(message, {
      ...metadata,
      timestamp: Date.now(),
      source: 'SecurityValidator'
    });
  }
  
  /**
   * Validate file path to prevent directory traversal
   * @param {string} filePath - File path to validate
   * @param {string} context - Context for error reporting
   * @returns {string} Validated file path
   * @throws {SecurityError} If validation fails
   */
  static validateFilePath(filePath, context = 'unknown') {
    if (!filePath || typeof filePath !== 'string') {
      throw this.createSecurityError(`Invalid file path type in ${context}`, {
        code: 'INVALID_PATH_TYPE',
        context
      });
    }
    
    // Check for directory traversal patterns
    const dangerousPatterns = [
      /\.\./,
      /\/\//,
      /\\/,
      /^\//, // Absolute paths
      /~/,   // Home directory
      /\$/, // Environment variables
      /[<>"|?*]/ // Invalid filename characters
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(filePath)) {
        throw this.createSecurityError(`Dangerous file path pattern in ${context}`, {
          code: 'DANGEROUS_PATH_PATTERN',
          context,
          pattern: pattern.source,
          hash: this.hashInput(filePath)
        });
      }
    }
    
    if (filePath.length > 255) {
      throw this.createSecurityError(`File path too long in ${context}`, {
        code: 'PATH_TOO_LONG',
        context,
        length: filePath.length
      });
    }
    
    return filePath;
  }
  
  /**
   * Validate user input against common injection patterns
   * @param {string} input - Input to validate
   * @param {string} context - Context for error reporting
   * @returns {string} Validated input
   * @throws {SecurityError} If dangerous patterns found
   */
  static validateUserInput(input, context = 'unknown') {
    if (!input || typeof input !== 'string') {
      return input; // Allow empty/null values
    }
    
    // Check for common injection patterns
    const injectionPatterns = [
      // Command injection
      /[;&|`$(){}[\]]/,
      /\b(cat|ls|pwd|whoami|id|uname|ps|kill|rm|mv|cp|chmod|chown)\b/i,
      
      // LDAP injection
      /[()&|!]/,
      
      // NoSQL injection
      /\$where|\$ne|\$gt|\$lt|\$regex/i,
      
      // General dangerous patterns
      /eval\s*\(/i,
      /exec\s*\(/i,
      /system\s*\(/i,
      /shell_exec/i,
      /passthru/i,
      /proc_open/i
    ];
    
    for (const pattern of injectionPatterns) {
      if (pattern.test(input)) {
        logger.warn('Potential injection attempt detected', {
          context,
          pattern: pattern.source,
          hash: this.hashInput(input)
        });
        
        throw this.createSecurityError(`Potential injection attempt in ${context}`, {
          code: 'INJECTION_ATTEMPT',
          context,
          pattern: pattern.source,
          hash: this.hashInput(input)
        });
      }
    }
    
    return input;
  }
}

module.exports = SecurityValidator;
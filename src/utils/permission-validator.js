const logger = require('./logger');
const AuditLogger = require('./auditLogger');
const SecurityValidator = require('./securityValidator');

/**
 * Permission levels hierarchy
 */
const PERMISSION_LEVELS = {
  NONE: 0,
  READ: 1,
  WRITE: 2,
  ADMIN: 3,
  OWNER: 4,
  SYSTEM: 5
};

/**
 * Default role permissions
 */
const DEFAULT_ROLES = {
  guest: {
    level: PERMISSION_LEVELS.NONE,
    permissions: []
  },
  member: {
    level: PERMISSION_LEVELS.READ,
    permissions: [
      'view_config',
      'view_stats'
    ]
  },
  moderator: {
    level: PERMISSION_LEVELS.WRITE,
    permissions: [
      'view_config',
      'view_stats',
      'view_violations',
      'override_decisions',
      'manage_exemptions'
    ]
  },
  admin: {
    level: PERMISSION_LEVELS.ADMIN,
    permissions: [
      'view_config',
      'view_stats',
      'view_violations',
      'override_decisions',
      'manage_exemptions',
      'modify_config',
      'manage_channels',
      'view_audit_logs',
      'export_data'
    ]
  },
  owner: {
    level: PERMISSION_LEVELS.OWNER,
    permissions: [
      'view_config',
      'view_stats',
      'view_violations',
      'override_decisions',
      'manage_exemptions',
      'modify_config',
      'manage_channels',
      'view_audit_logs',
      'export_data',
      'manage_users',
      'delete_data',
      'system_config'
    ]
  },
  system: {
    level: PERMISSION_LEVELS.SYSTEM,
    permissions: ['*'] // All permissions
  }
};

/**
 * API endpoint permission mappings
 */
const ENDPOINT_PERMISSIONS = {
  // Config endpoints
  'GET:/api/servers/:serverId/config': 'view_config',
  'PUT:/api/servers/:serverId/config': 'modify_config',
  'POST:/api/servers/:serverId/config': 'modify_config',
  
  // Stats endpoints
  'GET:/api/servers/:serverId/stats': 'view_stats',
  'GET:/api/servers/:serverId/analytics': 'view_stats',
  
  // Violation endpoints
  'GET:/api/servers/:serverId/violations': 'view_violations',
  'POST:/api/servers/:serverId/violations/:violationId/override': 'override_decisions',
  
  // User management
  'GET:/api/servers/:serverId/users': 'view_config',
  'PUT:/api/servers/:serverId/users/:userId/exempt': 'manage_exemptions',
  'DELETE:/api/servers/:serverId/users/:userId/exempt': 'manage_exemptions',
  'POST:/api/servers/:serverId/users/:userId/delete': 'delete_data',
  
  // Channel management
  'GET:/api/servers/:serverId/channels': 'view_config',
  'PUT:/api/servers/:serverId/channels': 'manage_channels',
  
  // Audit and exports
  'GET:/api/servers/:serverId/audit': 'view_audit_logs',
  'POST:/api/servers/:serverId/export': 'export_data',
  
  // System endpoints
  'GET:/api/health': null, // Public endpoint
  'GET:/api/status': 'view_stats',
  'POST:/api/system/maintenance': 'system_config',
  
  // Security endpoints
  'GET:/api/security/status': 'view_audit_logs',
  'POST:/api/security/reset': 'system_config'
};

/**
 * Permission rate limits by permission level
 */
const PERMISSION_RATE_LIMITS = {
  [PERMISSION_LEVELS.NONE]: { requests: 10, window: 60000 }, // 10/min
  [PERMISSION_LEVELS.READ]: { requests: 60, window: 60000 }, // 60/min
  [PERMISSION_LEVELS.WRITE]: { requests: 100, window: 60000 }, // 100/min
  [PERMISSION_LEVELS.ADMIN]: { requests: 200, window: 60000 }, // 200/min
  [PERMISSION_LEVELS.OWNER]: { requests: 500, window: 60000 }, // 500/min
  [PERMISSION_LEVELS.SYSTEM]: { requests: 1000, window: 60000 } // 1000/min
};

/**
 * Enhanced Permission Validator with RBAC
 */
class PermissionValidator {
  constructor() {
    this.roles = new Map();
    this.userPermissions = new Map();
    this.serverRoles = new Map();
    this.permissionCache = new Map();
    this.cacheTimeout = 300000; // 5 minutes
    
    this.stats = {
      permissionChecks: 0,
      permissionDenials: 0,
      cacheHits: 0,
      cacheMisses: 0
    };
    
    this.initializeDefaultRoles();
  }
  
  /**
   * Initialize default role definitions
   */
  initializeDefaultRoles() {
    for (const [roleName, roleData] of Object.entries(DEFAULT_ROLES)) {
      this.roles.set(roleName, {
        ...roleData,
        isDefault: true,
        createdAt: Date.now()
      });
    }
    
    logger.info('Permission validator initialized with default roles');
  }
  
  /**
   * Check if user has permission for operation
   */
  async checkPermissions(userId, serverId, method, path, options = {}) {
    try {
      this.stats.permissionChecks++;
      
      // Validate inputs
      const validatedUserId = SecurityValidator.validateDiscordId(userId, 'permission_check');
      const validatedServerId = SecurityValidator.validateDiscordId(serverId, 'permission_check');
      
      // Check cache first
      const cacheKey = `${validatedUserId}:${validatedServerId}:${method}:${path}`;
      const cached = this.permissionCache.get(cacheKey);
      
      if (cached && (Date.now() - cached.timestamp < this.cacheTimeout)) {
        this.stats.cacheHits++;
        return cached.hasPermission;
      }
      
      this.stats.cacheMisses++;
      
      // Get required permission for endpoint
      const requiredPermission = this.getRequiredPermission(method, path);
      
      // If no permission required (public endpoint), allow
      if (!requiredPermission) {
        this.cachePermission(cacheKey, true);
        return true;
      }
      
      // Get user's effective permissions
      const userPermissions = await this.getUserPermissions(validatedUserId, validatedServerId);
      
      // Check if user has required permission
      const hasPermission = this.hasPermission(userPermissions, requiredPermission);
      
      // Cache the result
      this.cachePermission(cacheKey, hasPermission);
      
      // Log permission check
      await this.logPermissionCheck(
        validatedUserId,
        validatedServerId,
        method,
        path,
        requiredPermission,
        hasPermission,
        options
      );
      
      if (!hasPermission) {
        this.stats.permissionDenials++;
      }
      
      return hasPermission;
      
    } catch (error) {
      logger.error('Permission check failed:', error);
      
      await AuditLogger.logSecurityEvent({
        type: 'PERMISSION_CHECK_ERROR',
        userId,
        serverId,
        method,
        path,
        error: error.message,
        timestamp: Date.now()
      });
      
      // Fail secure - deny permission on error
      return false;
    }
  }
  
  /**
   * Get required permission for an endpoint
   */
  getRequiredPermission(method, path) {
    const normalizedPath = this.normalizePath(path);
    const key = `${method.toUpperCase()}:${normalizedPath}`;
    
    // Check exact match first
    if (ENDPOINT_PERMISSIONS[key] !== undefined) {
      return ENDPOINT_PERMISSIONS[key];
    }
    
    // Check pattern matches
    for (const [pattern, permission] of Object.entries(ENDPOINT_PERMISSIONS)) {
      if (this.matchesPattern(key, pattern)) {
        return permission;
      }
    }
    
    // Default to requiring admin permission for unknown endpoints
    logger.warn(`No permission mapping found for ${key}, defaulting to admin`);
    return 'system_config';
  }
  
  /**
   * Normalize path for permission checking
   */
  normalizePath(path) {
    return path
      .replace(/\/\d{17,19}/g, '/:serverId') // Replace Discord IDs with placeholder
      .replace(/\/[a-f0-9]{24}/g, '/:id') // Replace MongoDB ObjectIds
      .replace(/\/[a-f0-9-]{36}/g, '/:uuid'); // Replace UUIDs
  }
  
  /**
   * Check if endpoint pattern matches
   */
  matchesPattern(endpoint, pattern) {
    const endpointRegex = pattern
      .replace(/:\w+/g, '[^/]+') // Replace :param with regex
      .replace(/\//g, '\\/'); // Escape forward slashes
    
    return new RegExp(`^${endpointRegex}$`).test(endpoint);
  }
  
  /**
   * Get user's effective permissions
   */
  async getUserPermissions(userId, serverId) {
    try {
      // Check if we have cached user permissions
      const cacheKey = `user_perms:${userId}:${serverId}`;
      const cached = this.userPermissions.get(cacheKey);
      
      if (cached && (Date.now() - cached.timestamp < this.cacheTimeout)) {
        return cached.permissions;
      }
      
      // Get user's role in the server
      const userRole = await this.getUserRole(userId, serverId);
      
      // Get role permissions
      const roleData = this.roles.get(userRole);
      if (!roleData) {
        logger.warn(`Unknown role: ${userRole} for user ${userId}`);
        return this.roles.get('guest').permissions;
      }
      
      // Get any additional user-specific permissions
      const additionalPermissions = await this.getUserSpecificPermissions(userId, serverId);
      
      // Combine role permissions with additional permissions
      const effectivePermissions = [
        ...roleData.permissions,
        ...additionalPermissions
      ];
      
      // Cache the permissions
      this.userPermissions.set(cacheKey, {
        permissions: effectivePermissions,
        level: roleData.level,
        role: userRole,
        timestamp: Date.now()
      });
      
      return effectivePermissions;
      
    } catch (error) {
      logger.error('Failed to get user permissions:', error);
      return []; // Return no permissions on error
    }
  }
  
  /**
   * Get user's role in a server
   */
  async getUserRole(userId, serverId) {
    try {
      // This would typically query Discord API or your database
      // For now, we'll use a simple mapping or default to 'member'
      
      const serverRoleKey = `${serverId}:${userId}`;
      const cachedRole = this.serverRoles.get(serverRoleKey);
      
      if (cachedRole && (Date.now() - cachedRole.timestamp < this.cacheTimeout)) {
        return cachedRole.role;
      }
      
      // TODO: Implement actual role fetching from Discord API
      // This is a simplified implementation
      const role = await this.fetchUserRoleFromDiscord(userId, serverId);
      
      // Cache the role
      this.serverRoles.set(serverRoleKey, {
        role,
        timestamp: Date.now()
      });
      
      return role;
      
    } catch (error) {
      logger.error('Failed to get user role:', error);
      return 'guest'; // Default to guest role on error
    }
  }
  
  /**
   * Fetch user role from Discord (placeholder implementation)
   */
  async fetchUserRoleFromDiscord(userId, serverId) {
    // This would use Discord API to check user's highest role
    // For now, return a default role based on some logic
    
    // System users (bot accounts, etc.)
    if (userId === process.env.DISCORD_BOT_USER_ID) {
      return 'system';
    }
    
    // Check if user is server owner (this would come from Discord API)
    const isOwner = await this.checkIfServerOwner(userId, serverId);
    if (isOwner) {
      return 'owner';
    }
    
    // Check if user has admin permissions (this would come from Discord API)
    const hasAdminPerms = await this.checkDiscordAdminPermissions(userId, serverId);
    if (hasAdminPerms) {
      return 'admin';
    }
    
    // Check if user has manage messages permission (moderator)
    const hasModPerms = await this.checkDiscordModeratorPermissions(userId, serverId);
    if (hasModPerms) {
      return 'moderator';
    }
    
    // Default to member
    return 'member';
  }
  
  /**
   * Get user-specific permissions (beyond role)
   */
  async getUserSpecificPermissions(userId, serverId) {
    // This would query your database for any additional permissions
    // granted specifically to this user
    return [];
  }
  
  /**
   * Check if user has specific permission
   */
  hasPermission(userPermissions, requiredPermission) {
    // System permission grants everything
    if (userPermissions.includes('*')) {
      return true;
    }
    
    // Check for exact permission match
    return userPermissions.includes(requiredPermission);
  }
  
  /**
   * Add custom role
   */
  addRole(roleName, roleData) {
    if (this.roles.has(roleName)) {
      throw new Error(`Role ${roleName} already exists`);
    }
    
    const role = {
      ...roleData,
      isDefault: false,
      createdAt: Date.now()
    };
    
    this.roles.set(roleName, role);
    
    logger.info(`Added custom role: ${roleName}`);
  }
  
  /**
   * Update role permissions
   */
  updateRole(roleName, updates) {
    const role = this.roles.get(roleName);
    if (!role) {
      throw new Error(`Role ${roleName} not found`);
    }
    
    if (role.isDefault) {
      throw new Error(`Cannot modify default role: ${roleName}`);
    }
    
    const updatedRole = {
      ...role,
      ...updates,
      updatedAt: Date.now()
    };
    
    this.roles.set(roleName, updatedRole);
    
    // Clear related caches
    this.clearUserPermissionCache();
    
    logger.info(`Updated role: ${roleName}`);
  }
  
  /**
   * Grant permission to specific user
   */
  async grantUserPermission(userId, serverId, permission) {
    const validatedUserId = SecurityValidator.validateDiscordId(userId, 'grant_permission');
    const validatedServerId = SecurityValidator.validateDiscordId(serverId, 'grant_permission');
    
    // This would store the permission in your database
    // For now, we'll just clear the cache to force refresh
    this.clearUserPermissionCache(validatedUserId, validatedServerId);
    
    await AuditLogger.log({
      action: 'PERMISSION_GRANTED',
      userId: validatedUserId,
      serverId: validatedServerId,
      permission,
      timestamp: Date.now()
    });
    
    logger.info(`Granted permission ${permission} to user ${validatedUserId} in server ${validatedServerId}`);
  }
  
  /**
   * Revoke permission from specific user
   */
  async revokeUserPermission(userId, serverId, permission) {
    const validatedUserId = SecurityValidator.validateDiscordId(userId, 'revoke_permission');
    const validatedServerId = SecurityValidator.validateDiscordId(serverId, 'revoke_permission');
    
    // This would remove the permission from your database
    this.clearUserPermissionCache(validatedUserId, validatedServerId);
    
    await AuditLogger.log({
      action: 'PERMISSION_REVOKED',
      userId: validatedUserId,
      serverId: validatedServerId,
      permission,
      timestamp: Date.now()
    });
    
    logger.info(`Revoked permission ${permission} from user ${validatedUserId} in server ${validatedServerId}`);
  }
  
  /**
   * Get user's permission level for rate limiting
   */
  async getUserPermissionLevel(userId, serverId) {
    try {
      const userRole = await this.getUserRole(userId, serverId);
      const roleData = this.roles.get(userRole);
      return roleData ? roleData.level : PERMISSION_LEVELS.NONE;
    } catch (error) {
      logger.error('Failed to get user permission level:', error);
      return PERMISSION_LEVELS.NONE;
    }
  }
  
  /**
   * Get rate limit for permission level
   */
  getRateLimitForLevel(level) {
    return PERMISSION_RATE_LIMITS[level] || PERMISSION_RATE_LIMITS[PERMISSION_LEVELS.NONE];
  }
  
  /**
   * Cache permission result
   */
  cachePermission(key, hasPermission) {
    this.permissionCache.set(key, {
      hasPermission,
      timestamp: Date.now()
    });
    
    // Limit cache size
    if (this.permissionCache.size > 10000) {
      // Remove oldest entries
      const entries = Array.from(this.permissionCache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      for (let i = 0; i < 1000; i++) {
        this.permissionCache.delete(entries[i][0]);
      }
    }
  }
  
  /**
   * Clear permission caches
   */
  clearUserPermissionCache(userId = null, serverId = null) {
    if (userId && serverId) {
      // Clear specific user's cache
      const prefix = `user_perms:${userId}:${serverId}`;
      this.userPermissions.delete(prefix);
      
      // Clear permission check cache for this user
      for (const [key] of this.permissionCache) {
        if (key.startsWith(`${userId}:${serverId}:`)) {
          this.permissionCache.delete(key);
        }
      }
    } else {
      // Clear all caches
      this.userPermissions.clear();
      this.permissionCache.clear();
      this.serverRoles.clear();
    }
  }
  
  /**
   * Log permission check for audit
   */
  async logPermissionCheck(userId, serverId, method, path, requiredPermission, hasPermission, options = {}) {
    // Only log denials and sensitive operations
    if (!hasPermission || this.isSensitiveOperation(requiredPermission)) {
      await AuditLogger.log({
        action: hasPermission ? 'PERMISSION_GRANTED' : 'PERMISSION_DENIED',
        userId,
        serverId,
        method,
        path,
        requiredPermission,
        hasPermission,
        timestamp: Date.now(),
        ip: options.ip,
        userAgent: options.userAgent
      });
    }
  }
  
  /**
   * Check if operation is sensitive and should always be logged
   */
  isSensitiveOperation(permission) {
    const sensitivePermissions = [
      'system_config',
      'delete_data',
      'manage_users',
      'view_audit_logs',
      'export_data'
    ];
    
    return sensitivePermissions.includes(permission);
  }
  
  /**
   * Placeholder methods for Discord API integration
   */
  async checkIfServerOwner(userId, serverId) {
    // This would check if the user is the server owner via Discord API
    return false;
  }
  
  async checkDiscordAdminPermissions(userId, serverId) {
    // This would check if the user has admin permissions via Discord API
    return false;
  }
  
  async checkDiscordModeratorPermissions(userId, serverId) {
    // This would check if the user has moderator permissions via Discord API
    return false;
  }
  
  /**
   * Get all available permissions
   */
  getAvailablePermissions() {
    const permissions = new Set();
    
    for (const [roleName, roleData] of this.roles) {
      for (const permission of roleData.permissions) {
        if (permission !== '*') {
          permissions.add(permission);
        }
      }
    }
    
    return Array.from(permissions).sort();
  }
  
  /**
   * Get role hierarchy
   */
  getRoleHierarchy() {
    const roles = Array.from(this.roles.entries()).map(([name, data]) => ({
      name,
      level: data.level,
      permissions: data.permissions.length,
      isDefault: data.isDefault
    }));
    
    return roles.sort((a, b) => a.level - b.level);
  }
  
  /**
   * Validate permission name
   */
  validatePermissionName(permission) {
    if (!permission || typeof permission !== 'string') {
      throw new Error('Permission name must be a string');
    }
    
    if (permission.length < 3 || permission.length > 50) {
      throw new Error('Permission name must be between 3 and 50 characters');
    }
    
    if (!/^[a-z_]+$/.test(permission)) {
      throw new Error('Permission name can only contain lowercase letters and underscores');
    }
    
    return permission;
  }
  
  /**
   * Get permission statistics
   */
  getStats() {
    return {
      ...this.stats,
      roles: this.roles.size,
      cachedPermissions: this.permissionCache.size,
      cachedUserPermissions: this.userPermissions.size,
      cachedServerRoles: this.serverRoles.size,
      cacheHitRate: this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses) || 0
    };
  }
  
  /**
   * Export permission configuration
   */
  exportConfiguration() {
    const config = {
      roles: Object.fromEntries(this.roles),
      endpointPermissions: ENDPOINT_PERMISSIONS,
      permissionLevels: PERMISSION_LEVELS,
      rateLimits: PERMISSION_RATE_LIMITS,
      exportedAt: new Date().toISOString()
    };
    
    return config;
  }
  
  /**
   * Import permission configuration
   */
  importConfiguration(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('Invalid configuration object');
    }
    
    // Validate configuration structure
    if (!config.roles || typeof config.roles !== 'object') {
      throw new Error('Configuration must include roles object');
    }
    
    // Clear existing non-default roles
    for (const [roleName, roleData] of this.roles) {
      if (!roleData.isDefault) {
        this.roles.delete(roleName);
      }
    }
    
    // Import new roles
    for (const [roleName, roleData] of Object.entries(config.roles)) {
      if (!roleData.isDefault) {
        this.roles.set(roleName, {
          ...roleData,
          importedAt: Date.now()
        });
      }
    }
    
    // Clear caches
    this.clearUserPermissionCache();
    
    logger.info('Permission configuration imported successfully');
  }
}

// Export singleton instance
module.exports = new PermissionValidator();
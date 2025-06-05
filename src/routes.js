const SecurityValidator = require("./utils/security-validator");
const { client } = require('./bot');
const { body, param, query, validationResult } = require('express-validator');
const { 
  ServerConfig, 
  UserData, 
  ViolationLog, 
  getServerConfig,
  sanitizeInput,
  validateServerId,
  validateUserId 
} = require('./database');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const logger = require('./utils/logger');
const errorManager = require('./utils/error-manager');

// Helper function to check admin permissions
async function verifyAdminPermissions(userId, serverId) {
  try {
    if (!SecurityValidator.validateUserId(userId) || !SecurityValidator.validateServerId(serverId)) {
      return false;
    }
    
    const guild = client.guilds.cache.get(serverId);
    if (!guild) {
      return false;
    }
    
    const member = await guild.members.fetch(userId).catch(() => null);
    if (!member) {
      return false;
    }
    
    return member.permissions.has('Administrator');
  } catch (error) {
    logger.error('Error verifying admin permissions:', error);
    return false;
  }
}

// Set up API routes
function setupRoutes(app, validateRequest) {
  // Authentication with comprehensive validation
  app.post('/api/login', [
    body('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format'),
    body('userId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid user ID format')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId, userId } = req.body;
      
      // Sanitize inputs
      const sanitizedServerId = sanitizeInput(serverId);
      const sanitizedUserId = sanitizeInput(userId);
      
      // Verify admin permissions
      const hasAdminPermissions = await verifyAdminPermissions(sanitizedUserId, sanitizedServerId);
      if (!hasAdminPermissions) {
        logger.warn('Unauthorized login attempt', {
          userId: sanitizedUserId.substring(0, 10) + '...',
          serverId: sanitizedServerId.substring(0, 10) + '...',
          ip: req.ip
        });
        return res.status(403).json({ error: 'Insufficient permissions or server access denied' });
      }
      
      // Get additional user info for token
      const guild = client.guilds.cache.get(sanitizedServerId);
      const member = await guild.members.fetch(sanitizedUserId);
      
      // Generate JWT token with enhanced claims
      const tokenPayload = {
        userId: sanitizedUserId,
        serverId: sanitizedServerId,
        username: member.user.username,
        discriminator: member.user.discriminator,
        iat: Math.floor(Date.now() / 1000),
        iss: 'discord-ai-moderator',
        aud: 'discord-api'
      };
      
      const token = jwt.sign(
        tokenPayload,
        process.env.JWT_SECRET,
        { 
          expiresIn: '7d',
          algorithm: 'HS256'
        }
      );
      
      // Log successful authentication
      logger.info('User authenticated successfully', {
        userId: sanitizedUserId.substring(0, 10) + '...',
        serverId: sanitizedServerId.substring(0, 10) + '...',
        username: member.user.username,
        ip: req.ip
      });
      
      return res.json({ 
        token,
        user: {
          id: sanitizedUserId,
          username: member.user.username,
          serverId: sanitizedServerId,
          serverName: guild.name
        }
      });
    } catch (error) {
      logger.error('Error in login route:', error);
      return res.status(500).json({ error: 'Authentication failed' });
    }
  });
  
  // Server Config with comprehensive validation
  app.get('/api/servers/:serverId/config', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const sanitizedServerId = sanitizeInput(serverId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        logger.warn('Unauthorized config access attempt', {
          requestedServer: sanitizedServerId.substring(0, 10) + '...',
          userServer: req.user.serverId?.substring(0, 10) + '...',
          userId: req.user.userId?.substring(0, 10) + '...',
          ip: req.ip
        });
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      const config = await getServerConfig(sanitizedServerId);
      if (!config) {
        return res.status(404).json({ error: 'Server configuration not found' });
      }
      
      // Remove sensitive data before sending
      const sanitizedConfig = {
        serverId: config.serverId,
        enabled: config.enabled,
        channels: config.channels,
        rules: config.rules,
        strictness: config.strictness,
        notifications: config.notifications,
        createdAt: config.createdAt,
        updatedAt: config.updatedAt
      };
      
      return res.json(sanitizedConfig);
    } catch (error) {
      logger.error(`Error getting server config for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to retrieve configuration' });
    }
  });
  
  app.put('/api/servers/:serverId/config', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format'),
    body('enabled')
      .optional()
      .isBoolean()
      .withMessage('Enabled must be a boolean'),
    body('channels')
      .optional()
      .isArray({ max: 50 })
      .withMessage('Channels must be an array with max 50 items'),
    body('channels.*')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid channel ID format'),
    body('rules')
      .optional()
      .isString()
      .isLength({ min: 1, max: 5000 })
      .withMessage('Rules must be between 1 and 5000 characters'),
    body('strictness')
      .optional()
      .isIn(['low', 'medium', 'high'])
      .withMessage('Strictness must be low, medium, or high'),
    body('notifications.channel')
      .optional()
      .custom(value => {
        if (value === null) return true;
        if (typeof value === 'string' && /^\d{17,19}$/.test(value)) return true;
        throw new Error('Invalid notification channel ID');
      }),
    body('notifications.sendAlerts')
      .optional()
      .isBoolean()
      .withMessage('Send alerts must be a boolean')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const updatedConfig = req.body;
      const sanitizedServerId = sanitizeInput(serverId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      // Validate config structure
      if (!updatedConfig || typeof updatedConfig !== 'object') {
        return res.status(400).json({ error: 'Invalid configuration object' });
      }
      
      // Update config using secure database function
      const { saveServerConfiguration } = require('./database');
      const config = await saveServerConfiguration(sanitizedServerId, updatedConfig);
      
      if (!config) {
        return res.status(500).json({ error: 'Failed to save configuration' });
      }
      
      logger.info('Server configuration updated', {
        serverId: sanitizedServerId.substring(0, 10) + '...',
        userId: req.user.userId?.substring(0, 10) + '...',
        changes: Object.keys(updatedConfig)
      });
      
      return res.json(config);
    } catch (error) {
      logger.error(`Error updating server config for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to update configuration' });
    }
  });
  
  // Analytics with pagination and limits
  app.get('/api/servers/:serverId/stats', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format'),
    query('timeframe')
      .optional()
      .isIn(['today', 'week', 'month', 'all'])
      .withMessage('Invalid timeframe'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 1000 })
      .withMessage('Limit must be between 1 and 1000'),
    query('offset')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Offset must be non-negative')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const { timeframe = 'week', limit = 100, offset = 0 } = req.query;
      const sanitizedServerId = sanitizeInput(serverId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      // Calculate date range
      const now = new Date();
      let startDate;
      
      switch (timeframe) {
        case 'today':
          startDate = new Date(now.setHours(0, 0, 0, 0));
          break;
        case 'week':
          startDate = new Date(now);
          startDate.setDate(startDate.getDate() - 7);
          break;
        case 'month':
          startDate = new Date(now);
          startDate.setMonth(startDate.getMonth() - 1);
          break;
        case 'all':
          startDate = new Date(0); // Beginning of time
          break;
        default:
          startDate = new Date(now);
          startDate.setDate(startDate.getDate() - 7);
      }
      
      // Get violation statistics with safe aggregation
      const violationStats = await ViolationLog.aggregate([
        {
          $match: {
            serverId: sanitizedServerId,
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: {
              isViolation: '$isViolation',
              actionTaken: '$actionTaken',
              category: '$category'
            },
            count: { $sum: 1 }
          }
        },
        {
          $limit: 1000 // Limit results for performance
        }
      ]);
      
      // Get user statistics with pagination
      const userStats = await ViolationLog.aggregate([
        {
          $match: {
            serverId: sanitizedServerId,
            isViolation: true,
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: '$userId',
            violations: { $sum: 1 },
            lastViolation: { $max: '$createdAt' }
          }
        },
        {
          $sort: { violations: -1 }
        },
        {
          $skip: parseInt(offset)
        },
        {
          $limit: Math.min(parseInt(limit), 100) // Cap at 100
        }
      ]);
      
      // Get token usage with limits
      const tokenStats = await ViolationLog.aggregate([
        {
          $match: {
            serverId: sanitizedServerId,
            createdAt: { $gte: startDate },
            tokensUsed: { $exists: true, $ne: null }
          }
        },
        {
          $group: {
            _id: '$modelUsed',
            tokenCount: { $sum: '$tokensUsed' },
            messageCount: { $sum: 1 },
            avgProcessingTime: { $avg: '$processingTimeMs' }
          }
        },
        {
          $limit: 50 // Limit model types
        }
      ]);
      
      // Calculate total processed vs skipped
      const processingStats = await ViolationLog.aggregate([
        {
          $match: {
            serverId: sanitizedServerId,
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: '$processed',
            count: { $sum: 1 }
          }
        }
      ]);
      
      // Format results safely
      const stats = {
        timeframe,
        period: {
          start: startDate.toISOString(),
          end: now.toISOString()
        },
        violations: violationStats,
        topUsers: userStats.map(user => ({
          userId: user._id?.substring(0, 10) + '...', // Partial ID for privacy
          violations: user.violations,
          lastViolation: user.lastViolation
        })),
        tokenUsage: tokenStats,
        processing: processingStats,
        pagination: {
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: userStats.length === parseInt(limit)
        }
      };
      
      return res.json(stats);
    } catch (error) {
      logger.error(`Error getting stats for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to retrieve statistics' });
    }
  });
  
  // User management with validation
  app.get('/api/servers/:serverId/users', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format'),
    query('sort')
      .optional()
      .isIn(['violationCount', 'recent', 'created'])
      .withMessage('Invalid sort parameter'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('offset')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Offset must be non-negative')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const { sort = 'violationCount', limit = 50, offset = 0 } = req.query;
      const sanitizedServerId = sanitizeInput(serverId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      // Define sort options safely
      const sortOptions = {};
      switch (sort) {
        case 'violationCount':
          sortOptions.totalViolations = -1;
          break;
        case 'recent':
          sortOptions.lastActionTaken = -1;
          break;
        case 'created':
          sortOptions.createdAt = -1;
          break;
        default:
          sortOptions.totalViolations = -1;
      }
      
      // Get users with safe query
      const users = await UserData.find({ 
        serverId: sanitizedServerId,
        totalViolations: { $gt: 0 } // Only users with violations for privacy
      })
        .select('-__v') // Exclude version key
        .sort(sortOptions)
        .skip(parseInt(offset))
        .limit(Math.min(parseInt(limit), 100)) // Cap at 100
        .lean();
      
      // Get total count for pagination
      const total = await UserData.countDocuments({ 
        serverId: sanitizedServerId,
        totalViolations: { $gt: 0 }
      });
      
      // Sanitize user data
      const sanitizedUsers = users.map(user => ({
        userId: user.userId?.substring(0, 10) + '...', // Partial ID for privacy
        isExempt: user.isExempt,
        exemptUntil: user.exemptUntil,
        recentViolations: user.recentViolations,
        totalViolations: user.totalViolations,
        lastActionTaken: user.lastActionTaken,
        joinedAt: user.joinedAt
      }));
      
      return res.json({
        users: sanitizedUsers,
        pagination: {
          total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: (parseInt(offset) + parseInt(limit)) < total
        }
      });
    } catch (error) {
      logger.error(`Error getting users for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to retrieve user data' });
    }
  });
  
  // Get Discord server channels with validation
  app.get('/api/servers/:serverId/channels', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const sanitizedServerId = sanitizeInput(serverId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      // Get the guild
      const guild = client.guilds.cache.get(sanitizedServerId);
      if (!guild) {
        return res.status(404).json({ error: 'Server not found or bot not in server' });
      }
      
      // Get text channels only
      const channels = guild.channels.cache
        .filter(channel => channel.type === 0) // TextChannel
        .map(channel => ({
          id: channel.id,
          name: sanitizeInput(channel.name),
          type: channel.type,
          position: channel.position
        }))
        .sort((a, b) => a.position - b.position)
        .slice(0, 100); // Limit to 100 channels
      
      return res.json(channels);
    } catch (error) {
      logger.error(`Error getting channels for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to retrieve channel list' });
    }
  });
  
  // Create exempt user with validation
  app.post('/api/servers/:serverId/exempt', [
    param('serverId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid server ID format'),
    body('userId')
      .isString()
      .isLength({ min: 17, max: 19 })
      .matches(/^\d+$/)
      .withMessage('Invalid user ID format'),
    body('duration')
      .optional()
      .isInt({ min: 0, max: 525600 }) // Max 1 year in minutes
      .withMessage('Duration must be between 0 and 525600 minutes')
  ], validateRequest, async (req, res) => {
    try {
      const { serverId } = req.params;
      const { userId, duration } = req.body;
      const sanitizedServerId = sanitizeInput(serverId);
      const sanitizedUserId = sanitizeInput(userId);
      
      // Verify user has access to this server
      if (req.user.serverId !== sanitizedServerId) {
        return res.status(403).json({ error: 'Access denied to this server' });
      }
      
      // Verify the target user exists in the server
      const guild = client.guilds.cache.get(sanitizedServerId);
      if (!guild) {
        return res.status(404).json({ error: 'Server not found' });
      }
      
      const targetMember = await guild.members.fetch(sanitizedUserId).catch(() => null);
      if (!targetMember) {
        return res.status(404).json({ error: 'User not found in server' });
      }
      
      // Calculate exempt until date
      let exemptUntil = null;
      if (duration && duration > 0) {
        exemptUntil = new Date();
        exemptUntil.setMinutes(exemptUntil.getMinutes() + duration);
      }
      
      // Update user data
      const userData = await UserData.findOneAndUpdate(
        { userId: sanitizedUserId, serverId: sanitizedServerId },
        { 
          isExempt: true,
          exemptUntil,
          updatedAt: new Date()
        },
        { 
          new: true, 
          upsert: true,
          runValidators: true
        }
      ).lean();
      
      logger.info('User exempted from moderation', {
        targetUserId: sanitizedUserId.substring(0, 10) + '...',
        serverId: sanitizedServerId.substring(0, 10) + '...',
        adminUserId: req.user.userId?.substring(0, 10) + '...',
        duration: duration || 'permanent'
      });
      
      // Sanitize response
      const sanitizedResponse = {
        userId: userData.userId?.substring(0, 10) + '...',
        serverId: userData.serverId?.substring(0, 10) + '...',
        isExempt: userData.isExempt,
        exemptUntil: userData.exemptUntil,
        updatedAt: userData.updatedAt
      };
      
      return res.json(sanitizedResponse);
    } catch (error) {
      logger.error(`Error creating exempt user for ${req.params.serverId}:`, error);
      return res.status(500).json({ error: 'Failed to exempt user' });
    }
  });
}

module.exports = {
  setupRoutes
};
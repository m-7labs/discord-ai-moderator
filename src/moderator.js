const { performance } = require('perf_hooks');
const { processWithAI } = require('./anthropic');
const { 
  getServerConfig, 
  getUserData, 
  logAction 
} = require('./database');
const { 
  shouldSkipProcessing, 
  patternAnalysis, 
  assessRiskLevel, 
  selectModelByRisk, 
  generateOptimalContext, 
  takeAction 
} = require('./utils/moderation-utils');
const logger = require('./utils/logger');
const errorManager = require('./utils/error-manager');
const NodeCache = require('node-cache');

// Setup cache
const cache = new NodeCache({
  stdTTL: parseInt(process.env.CACHE_TTL || '300'), // Default 5 minutes
  checkperiod: 60
});

/**
 * Process a Discord message for moderation
 * @param {Object} message - Discord.js message object
 */
async function processMessage(message) {
  // Skip messages without guild (DMs)
  if (!message.guild) return;
  
  // Skip bot messages
  if (message.author.bot) return;
  
  // Performance tracking
  const startTime = performance.now();
  
  try {
    // Get server configuration
    const serverConfig = await getServerConfig(message.guild.id).catch(error => {
      return errorManager.handleError(error, 'database', {
        operation: 'getServerConfig',
        serverId: message.guild.id,
        retryFunction: async () => await getServerConfig(message.guild.id)
      });
    });
    
    // If error manager returned null or couldn't recover, use empty config
    if (!serverConfig || !serverConfig.enabled) return;
    
    // Check if channel is monitored
    if (!serverConfig.channels.includes(message.channel.id)) return;
    
    // Get user data
    const userData = await getUserData(message.author.id, message.guild.id).catch(error => {
      return errorManager.handleError(error, 'database', {
        operation: 'getUserData',
        userId: message.author.id,
        serverId: message.guild.id,
        retryFunction: async () => await getUserData(message.author.id, message.guild.id)
      });
    });
    
    // If we couldn't get user data even with recovery, use default
    const userDataWithDefaults = userData || {
      isExempt: false,
      recentViolations: 0,
      totalViolations: 0,
      joinedRecently: false
    };
    
    // Stage 1: No-cost pre-filtering
    if (shouldSkipProcessing(message, userDataWithDefaults, message.channel.id)) {
      await logSkippedMessage(message, "pre-filter");
      return;
    }
    
    // Stage 2: Pattern-based analysis
    const patternResult = patternAnalysis(message.content, userDataWithDefaults);
    if (patternResult.isViolation) {
      await takeAction(patternResult.action, message.author.id, message).catch(error => {
        return errorManager.handleError(error, 'discord', {
          operation: 'takeAction',
          action: patternResult.action,
          userId: message.author.id,
          messageId: message.id,
          retryFunction: async () => await takeAction(patternResult.action, message.author.id, message)
        });
      });
      
      await logActionTaken(message, patternResult, "pattern");
      return;
    }
    
    // Stage 3: Risk assessment
    const risk = assessRiskLevel(message, userDataWithDefaults, message.channel);
    const model = selectModelByRisk(risk);
    
    // Stage 4: Context preparation
    const context = await generateOptimalContext(message).catch(error => {
      // If we can't get context, continue with empty context
      errorManager.handleError(error, 'discord', {
        operation: 'generateOptimalContext',
        messageId: message.id
      });
      return [];
    });
    
    // Stage 5: Process with AI API
    const analysis = await processWithAI(
      message.content, 
      context, 
      serverConfig.rules, 
      model
    ).catch(error => {
      return errorManager.handleError(error, 'ai_provider', {
        operation: 'processWithAI',
        message: {
          content: message.content,
          id: message.id
        },
        userData: userDataWithDefaults,
        retryFunction: async () => await processWithAI(message.content, context, serverConfig.rules, model)
      });
    });
    
    // If analysis failed even with recovery, use fallback result
    if (!analysis || (!analysis.isViolation && !analysis.hasOwnProperty('isViolation'))) {
      // Fallback to pattern analysis with higher sensitivity
      const fallbackResult = patternAnalysis(message.content, userDataWithDefaults, true);
      
      if (fallbackResult.isViolation) {
        await takeAction(fallbackResult.action, message.author.id, message).catch(error => {
          errorManager.handleError(error, 'discord', {
            operation: 'takeAction',
            action: fallbackResult.action,
            userId: message.author.id,
            messageId: message.id
          });
        });
        
        await logActionTaken(message, fallbackResult, "fallback");
      }
      
      return;
    }
    
    // Stage 6: Take appropriate action
    if (analysis.isViolation) {
      await takeAction(analysis.recommendedAction, message.author.id, message).catch(error => {
        errorManager.handleError(error, 'discord', {
          operation: 'takeAction',
          action: analysis.recommendedAction,
          userId: message.author.id,
          messageId: message.id
        });
      });
      
      await logActionTaken(message, analysis, "AI");
    } else {
      // Log non-violation for analytics
      await logNonViolation(message, analysis);
    }
    
  } catch (error) {
    // Catch any unexpected errors
    errorManager.handleError(error, 'moderator', {
      operation: 'processMessage',
      messageId: message.id,
      channelId: message.channel.id,
      userId: message.author.id,
      guildId: message.guild.id
    });
  }
  
  const endTime = performance.now();
  logger.debug(`Message ${message.id} processed in ${endTime - startTime}ms`);
}

/**
 * Log a skipped message
 * @param {Object} message - Discord.js message object
 * @param {String} reason - Reason for skipping
 */
async function logSkippedMessage(message, reason) {
  try {
    await logAction({
      serverId: message.guild.id,
      userId: message.author.id,
      messageId: message.id,
      channelId: message.channel.id,
      content: message.content,
      isViolation: false,
      processed: false,
      skipped: true,
      skipReason: reason,
      actionTaken: 'none'
    });
  } catch (error) {
    logger.error(`Error logging skipped message ${message.id}:`, error);
  }
}

/**
 * Log a violation and action taken
 * @param {Object} message - Discord.js message object
 * @param {Object} analysis - Analysis result
 * @param {String} source - Source of the action (pattern/AI)
 */
async function logActionTaken(message, analysis, source) {
  try {
    await logAction({
      serverId: message.guild.id,
      userId: message.author.id,
      messageId: message.id,
      channelId: message.channel.id,
      content: message.content,
      isViolation: true,
      category: analysis.category,
      severity: analysis.severity,
      confidence: analysis.confidence,
      intent: analysis.intent,
      actionTaken: analysis.recommendedAction || analysis.action,
      actionSource: source,
      modelUsed: analysis.modelUsed,
      tokensUsed: analysis.tokensUsed,
      processingTimeMs: analysis.processingTimeMs
    });
  } catch (error) {
    logger.error(`Error logging action for message ${message.id}:`, error);
  }
}

/**
 * Log a non-violation for analytics
 * @param {Object} message - Discord.js message object
 * @param {Object} analysis - Analysis result
 */
async function logNonViolation(message, analysis) {
  try {
    await logAction({
      serverId: message.guild.id,
      userId: message.author.id,
      messageId: message.id,
      channelId: message.channel.id,
      content: message.content,
      isViolation: false,
      actionTaken: 'none',
      actionSource: 'AI',
      modelUsed: analysis.modelUsed,
      tokensUsed: analysis.tokensUsed,
      processingTimeMs: analysis.processingTimeMs
    });
  } catch (error) {
    logger.error(`Error logging non-violation for message ${message.id}:`, error);
  }
}

module.exports = {
  processMessage
};
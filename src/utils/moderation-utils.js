/**
 * Common utility functions for message moderation
 */
const logger = require('./logger');
const errorManager = require('./error-manager');

/**
 * Determine if a message should be skipped for processing
 * @param {Object} message - Discord.js message object
 * @param {Object} user - User data object
 * @param {String} channelId - Channel ID
 * @returns {Boolean} Whether to skip processing
 */
function shouldSkipProcessing(message, user, channelId) {
  // Skip in degraded mode if message is not high priority
  if (errorManager.degradedMode) {
    // In degraded mode, only process messages from users with history of violations
    if (user.totalViolations === 0 && !containsFlaggedTerms(message.content)) {
      return true;
    }
  }
  
  // Skip messages from exempt users
  if (user.isExempt) {
    if (user.exemptUntil && user.exemptUntil < new Date()) {
      // Exemption has expired, but will be updated on next DB query
      return false;
    }
    return true;
  }
  
  // Skip very short messages (typically greetings, reactions)
  if (message.content.length < 5) return true;
  
  // Skip commands (starting with /)
  if (message.content.startsWith('/')) return true;
  
  // Skip bot-specified channels
  if (message.channel.name.includes('bot') || message.channel.name.includes('command')) return true;
  
  return false;
}

/**
 * Check message for pattern-based violations
 * @param {String} content - Message content
 * @param {Object} userHistory - User history data
 * @param {Boolean} highSensitivity - Use higher sensitivity for fallback mode
 * @returns {Object} Pattern analysis result
 */
function patternAnalysis(content, userHistory, highSensitivity = false) {
  // Initialize result
  const result = {
    isViolation: false,
    action: null,
    category: null,
    severity: null,
    confidence: 1.0, // Pattern-based is always high confidence
    intent: 'normal'
  };
  
  // Lower thresholds in high sensitivity mode (used when AI service is unavailable)
  const mentionThreshold = highSensitivity ? 5 : 10;
  const repeatCharThreshold = highSensitivity ? 7 : 10;
  
  // Check for spam patterns (repeated messages)
  if (userHistory.recentMessages && userHistory.recentMessages.length > 3) {
    const lastThreeMessages = userHistory.recentMessages.slice(-3);
    if (lastThreeMessages.every(msg => msg === content)) {
      result.isViolation = true;
      result.action = "mute";
      result.category = "spam";
      result.severity = "moderate";
      result.intent = "intentional";
      return result;
    }
  }
  
  // Check for excessive mentions
  const mentionCount = (content.match(/<@/g) || []).length;
  if (mentionCount > mentionThreshold) {
    result.isViolation = true;
    result.action = "warn";
    result.category = "spam";
    result.severity = "mild";
    result.intent = "intentional";
    return result;
  }
  
  // Check for invite links (if not permitted)
  if (content.includes("discord.gg/") && !userHistory.canPostInvites) {
    result.isViolation = true;
    result.action = "delete";
    result.category = "spam";
    result.severity = "mild";
    result.intent = "accidental";
    return result;
  }
  
  // Check for repeated text or emoji spam
  if (new RegExp(`(.)\\1{${repeatCharThreshold - 1},}`).test(content)) {
    result.isViolation = true;
    result.action = "delete";
    result.category = "spam";
    result.severity = "mild";
    result.intent = "intentional";
    return result;
  }
  
  // High sensitivity mode: check for flagged terms
  if (highSensitivity && containsFlaggedTerms(content)) {
    result.isViolation = true;
    result.action = "flag"; // Just flag, don't take action automatically
    result.category = "potential_violation";
    result.severity = "mild";
    result.intent = "unknown";
    result.confidence = 0.7; // Lower confidence since this is pattern-based
    return result;
  }
  
  return result;
}

/**
 * Check if message contains flagged terms
 * @param {String} content - Message content
 * @returns {Boolean} Whether message contains flagged terms
 */
function containsFlaggedTerms(content) {
  // Common hate speech, slurs, extreme profanity
  // This is a minimal list - would be expanded in a real implementation
  const flaggedTerms = [
    'kill yourself', 'kys', 'die', 'suicide',
    'nazi', 'hitler', 'genocide'
  ];
  
  // Add regex matches for evasion attempts
  const evasionPatterns = [
    /k+\s*y+\s*s+/i,                 // k y s with spacing/repeating
    /k\W*i\W*l\W*l\W*y\W*o\W*u\W*r/i  // k.i.l.l.y.o.u.r with any non-word chars
  ];
  
  const lowerContent = content.toLowerCase();
  
  // Check direct matches
  if (flaggedTerms.some(term => lowerContent.includes(term))) {
    return true;
  }
  
  // Check regex patterns
  if (evasionPatterns.some(pattern => pattern.test(lowerContent))) {
    return true;
  }
  
  return false;
}

/**
 * Assess the risk level of a message
 * @param {Object} message - Discord.js message object
 * @param {Object} user - User data object
 * @param {Object} channel - Channel object
 * @returns {Number} Risk score between 0 and 1
 */
function assessRiskLevel(message, user, channel) {
  let riskScore = 0;
  
  // User history factors
  if (user.recentViolations > 0) riskScore += 0.2;
  if (user.totalViolations > 3) riskScore += 0.1;
  if (user.joinedRecently) riskScore += 0.1;
  
  // Message content factors
  if (containsFlaggedTerms(message.content)) riskScore += 0.3;
  if (message.mentions.users && message.mentions.users.size > 5) riskScore += 0.2;
  if (message.content.includes("http")) riskScore += 0.1;
  
  // Channel factors
  if (channel.name.includes("welcome") || channel.name.includes("rules")) riskScore += 0.1;
  
  return Math.min(riskScore, 1.0);
}

/**
 * Select appropriate AI model based on risk score
 * @param {Number} riskScore - Risk score between 0 and 1
 * @returns {String} Model name
 */
function selectModelByRisk(riskScore) {
  const { getModelForRisk } = require('../anthropic');
  
  // If in degraded mode, use only the most efficient model
  if (errorManager.degradedMode) {
    return getModelForRisk('low');
  }
  
  // Low risk messages (70-80% of traffic)
  if (riskScore < 0.3) {
    return getModelForRisk('low');
  }
  
  // Medium risk messages (15-25% of traffic)
  if (riskScore < 0.7) {
    return getModelForRisk('medium');
  }
  
  // High risk messages (5-10% of traffic)
  return getModelForRisk('high');
}

/**
 * Generate optimal context for message analysis
 * @param {Object} message - Discord.js message object
 * @returns {Array} Message context
 */
async function generateOptimalContext(message) {
  // Get recent channel messages (up to 5)
  const contextMessages = [];
  
  try {
    // Fetch messages before the current one
    const messages = await message.channel.messages.fetch({ 
      limit: 5, 
      before: message.id 
    });
    
    // Add to context
    messages.forEach(msg => {
      if (!msg.author.bot) {
        contextMessages.push({
          id: msg.id,
          author: msg.author.id,
          content: msg.content,
          timestamp: msg.createdTimestamp
        });
      }
    });
  } catch (error) {
    // If we can't fetch context, just continue with empty context
    console.error("Error fetching message context:", error);
  }
  
  return contextMessages;
}

/**
 * Take moderation action based on recommendation
 * @param {String} action - Recommended action
 * @param {String} userId - User ID to action
 * @param {Object} message - Discord.js message object
 */
async function takeAction(action, userId, message) {
  try {
    switch (action) {
      case 'delete':
        // Delete the message
        if (message.deletable) {
          await message.delete();
        }
        break;
        
      case 'warn':
        // Delete and send warning
        if (message.deletable) {
          await message.delete();
        }
        
        try {
          await message.channel.send({
            content: `<@${userId}> Your message was removed for violating server rules. Please review the rules and be mindful of your content.`
          });
        } catch (replyError) {
          errorManager.handleError(replyError, 'discord', {
            operation: 'sendWarning',
            userId,
            channelId: message.channel.id
          });
        }
        break;
        
      case 'mute':
        // Delete, warn, and timeout the user
        if (message.deletable) {
          await message.delete();
        }
        
        try {
          // Add timeout (10 minutes)
          await message.member.timeout(10 * 60 * 1000, 'Automatic moderation');
          
          // Send notification
          await message.channel.send({
            content: `<@${userId}> You have been timed out for 10 minutes for violating server rules.`
          });
        } catch (muteError) {
          // If timeout fails (e.g., missing permissions), try to at least send a warning
          errorManager.handleError(muteError, 'discord', {
            operation: 'timeoutUser',
            userId,
            messageId: message.id,
            fallback: async () => {
              try {
                await message.channel.send({
                  content: `<@${userId}> Your message violated server rules. This would normally result in a timeout, but I don't have permission to do that.`
                });
                return { success: true };
              } catch (error) {
                return { success: false };
              }
            }
          });
        }
        break;
        
      case 'kick':
        // Delete message and kick user
        if (message.deletable) {
          await message.delete();
        }
        
        try {
          await message.member.kick('Automatic moderation: Severe rule violation');
        } catch (kickError) {
          errorManager.handleError(kickError, 'discord', {
            operation: 'kickUser',
            userId,
            messageId: message.id
          });
        }
        break;
        
      case 'ban':
        // Delete message and ban user
        if (message.deletable) {
          await message.delete();
        }
        
        try {
          await message.member.ban({
            reason: 'Automatic moderation: Critical rule violation',
            deleteMessageSeconds: 86400 // Delete last 24h of messages
          });
        } catch (banError) {
          errorManager.handleError(banError, 'discord', {
            operation: 'banUser',
            userId,
            messageId: message.id
          });
        }
        break;
        
      case 'flag':
        // Just log the message for review, don't take action
        logger.info('Message flagged for review:', {
          userId,
          messageId: message.id,
          channelId: message.channel.id,
          guildId: message.guild.id,
          content: message.content.substring(0, 100) + (message.content.length > 100 ? '...' : '')
        });
        break;
        
      default:
        // No action needed
        break;
    }
  } catch (error) {
    throw error; // Let the caller handle unexpected errors
  }
}

module.exports = {
  shouldSkipProcessing,
  patternAnalysis,
  containsFlaggedTerms,
  assessRiskLevel,
  selectModelByRisk,
  generateOptimalContext,
  takeAction
};
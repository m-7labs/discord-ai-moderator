/**
 * Setup command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeSetupCommand(interaction) {
  const { ServerConfig } = require('../database');
  const { client } = require('../bot');
  
  try {
    // Check if user has admin permissions
    if (!interaction.member.permissions.has('Administrator')) {
      return interaction.reply({
        content: 'You need administrator permissions to run this command.',
        ephemeral: true
      });
    }
    
    // Begin setup process
    await interaction.reply({
      content: "Welcome to the AI Moderator setup wizard! Let's get your server protected in less than 2 minutes.",
      ephemeral: true
    });
    
    const serverId = interaction.guild.id;
    
    // Check if configuration already exists
    let config = await ServerConfig.findOne({ serverId });
    const isNewSetup = !config;
    
    // Default configuration
    const defaultConfig = {
      enabled: true,
      channels: [],
      rules: 'Be respectful to others. No harassment, hate speech, or NSFW content.',
      strictness: 'medium',
      notifications: {
        channel: interaction.channel.id,
        sendAlerts: true
      }
    };
    
    // Create or update configuration
    config = await ServerConfig.findOneAndUpdate(
      { serverId },
      {
        ...defaultConfig,
        updatedAt: Date.now()
      },
      {
        new: true,
        upsert: true
      }
    );
    
    // Generate dashboard URL
    const dashboardUrl = `https://dashboard.example.com/setup/${serverId}`;
    
    // Response based on new setup or update
    if (isNewSetup) {
      await interaction.followUp({
        content: `✅ Initial setup complete! Your server is now protected by AI Moderator with basic settings.\n\nComplete your configuration by visiting ${dashboardUrl} or by using \`/modagent_config\`.\n\nUse \`/modagent_help\` to see all available commands.`,
        ephemeral: true
      });
    } else {
      await interaction.followUp({
        content: `✅ AI Moderator has been reconfigured with default settings.\n\nAdjust your configuration by visiting ${dashboardUrl} or by using \`/modagent_config\`.\n\nUse \`/modagent_help\` to see all available commands.`,
        ephemeral: true
      });
    }
  } catch (error) {
    console.error('Error executing setup command:', error);
    
    // Handle error response
    if (!interaction.replied) {
      await interaction.reply({
        content: 'An error occurred during setup. Please try again later.',
        ephemeral: true
      });
    } else {
      await interaction.followUp({
        content: 'An error occurred during setup. Please try again later.',
        ephemeral: true
      });
    }
  }
}

/**
 * Configuration command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeConfigCommand(interaction) {
  try {
    // Check if user has admin permissions
    if (!interaction.member.permissions.has('Administrator')) {
      return interaction.reply({
        content: 'You need administrator permissions to run this command.',
        ephemeral: true
      });
    }
    
    // Generate dashboard URL
    const dashboardUrl = `https://dashboard.example.com/config/${interaction.guild.id}`;
    
    await interaction.reply({
      content: `To configure AI Moderator, please visit the web dashboard:\n${dashboardUrl}\n\nFrom there, you can adjust rules, moderation settings, monitored channels, and notification preferences.`,
      ephemeral: true
    });
  } catch (error) {
    console.error('Error executing config command:', error);
    
    await interaction.reply({
      content: 'An error occurred. Please try again later.',
      ephemeral: true
    });
  }
}

/**
 * Status command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeStatusCommand(interaction) {
  const { getServerConfig } = require('../database');
  const { ViolationLog } = require('../database');
  
  try {
    const serverId = interaction.guild.id;
    
    // Get server configuration
    const config = await getServerConfig(serverId);
    if (!config) {
      return interaction.reply({
        content: 'AI Moderator is not configured for this server. Use `/modagent_setup` to get started.',
        ephemeral: true
      });
    }
    
    // Get recent statistics
    const now = new Date();
    const oneDayAgo = new Date(now);
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);
    
    const recentViolations = await ViolationLog.countDocuments({
      serverId,
      isViolation: true,
      createdAt: { $gte: oneDayAgo }
    });
    
    const recentActions = await ViolationLog.countDocuments({
      serverId,
      actionTaken: { $ne: 'none' },
      createdAt: { $gte: oneDayAgo }
    });
    
    const totalProcessed = await ViolationLog.countDocuments({
      serverId,
      createdAt: { $gte: oneDayAgo }
    });
    
    // Format the status message
    const statusMessage = `## AI Moderator Status
    
**Status:** ${config.enabled ? '✅ Active' : '⚠️ Disabled'}
**Monitored Channels:** ${config.channels.length} channels
**Strictness Level:** ${config.strictness.charAt(0).toUpperCase() + config.strictness.slice(1)}

**Last 24 Hours:**
• Messages Processed: ${totalProcessed}
• Violations Detected: ${recentViolations}
• Actions Taken: ${recentActions}

Use \`/modagent_stats\` for detailed analytics or \`/modagent_help\` to see all commands.`;
    
    await interaction.reply({
      content: statusMessage,
      ephemeral: false
    });
  } catch (error) {
    console.error('Error executing status command:', error);
    
    await interaction.reply({
      content: 'An error occurred while retrieving status. Please try again later.',
      ephemeral: true
    });
  }
}

/**
 * Help command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeHelpCommand(interaction) {
  try {
    // Check for degraded mode to display appropriate help
    const errorManager = require('../utils/errorManager');
    const isInDegradedMode = errorManager.degradedMode;

    const helpMessage = `# AI Moderator Commands

## Basic Commands
• \`/modagent_status\` - See current moderation stats and status
• \`/modagent_help\` - View this help message
• \`/modagent_config\` - Change your moderation settings

## Moderation Actions
• \`/modagent_review <message_id>\` - Manually review a message
• \`/modagent_override <case_id> <action>\` - Override an AI decision
• \`/modagent_exempt <user> [duration]\` - Temporarily exempt a user from moderation

## Analytics
• \`/modagent_stats [timeframe]\` - View moderation statistics

## Admin System Commands
• \`/modagent_system\` - View detailed system status and health information
• \`/modagent_reset_errors\` - Reset error counters and attempt system recovery
• \`/modagent_health_check\` - Force an immediate system health check

${isInDegradedMode ? `
## ⚠️ DEGRADED MODE ACTIVE
The system is currently operating in degraded mode due to technical issues. During this time:
- Some features may be limited
- Pattern-based moderation is used instead of AI analysis
- Fewer messages are processed to reduce load

Our team is working to restore full functionality as soon as possible.
` : ''}

For more detailed documentation and setup instructions, visit our [support site](https://example.com/support).`;
    
    await interaction.reply({
      content: helpMessage,
      ephemeral: true
    });
  } catch (error) {
    console.error('Error executing help command:', error);
    
    await interaction.reply({
      content: 'An error occurred. Please try again later.',
      ephemeral: true
    });
  }
}

/**
 * Review command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeReviewCommand(interaction) {
  const { processWithAI } = require('../anthropic');
  const { getServerConfig } = require('../database');
  
  try {
    // Check if user has appropriate permissions
    if (!interaction.member.permissions.has('ModerateMembers')) {
      return interaction.reply({
        content: 'You need moderation permissions to run this command.',
        ephemeral: true
      });
    }
    
    // Get message ID from options
    const messageId = interaction.options.getString('message_id');
    
    // Defer reply
    await interaction.deferReply({ ephemeral: true });
    
    // Try to fetch the message
    let message;
    try {
      // First try in the current channel
      message = await interaction.channel.messages.fetch(messageId);
    } catch (fetchError) {
      // If not found, try to find in all channels
      let found = false;
      
      for (const [, channel] of interaction.guild.channels.cache) {
        if (channel.isTextBased() && channel.permissionsFor(interaction.guild.members.me).has('ViewChannel')) {
          try {
            message = await channel.messages.fetch(messageId);
            found = true;
            break;
          } catch (err) {
            // Message not in this channel, continue searching
          }
        }
      }
      
      if (!found) {
        return interaction.followUp({
          content: `Could not find message with ID ${messageId}. Make sure the ID is correct and the message is still available.`,
          ephemeral: true
        });
      }
    }
    
    // Get server configuration
    const config = await getServerConfig(interaction.guild.id);
    
    // Process with AI
    const analysis = await processWithAI(
      message.content,
      [], // No context needed for manual review
      config.rules,
      'claude-3-sonnet-20240229' // Use a balanced model for manual reviews
    );
    
    // Format the response
    const reviewMessage = `## Message Review Results

**Message:** ${message.content.substring(0, 200)}${message.content.length > 200 ? '...' : ''}
**Author:** <@${message.author.id}>
**Channel:** <#${message.channel.id}>

**Analysis:**
• Violation Detected: ${analysis.isViolation ? '🚫 Yes' : '✅ No'}
${analysis.isViolation ? `• Category: ${analysis.category}
• Severity: ${analysis.severity}
• Confidence: ${Math.round(analysis.confidence * 100)}%
• Intent: ${analysis.intent}
• Recommended Action: ${analysis.recommendedAction}` : ''}

**Reasoning:**
${analysis.reasoning}

Use \`/modagent_override ${message.id} <action>\` to manually take action.`;
    
    await interaction.followUp({
      content: reviewMessage,
      ephemeral: true
    });
  } catch (error) {
    console.error('Error executing review command:', error);
    
    if (interaction.deferred) {
      await interaction.followUp({
        content: 'An error occurred while reviewing the message. Please try again later.',
        ephemeral: true
      });
    } else {
      await interaction.reply({
        content: 'An error occurred while reviewing the message. Please try again later.',
        ephemeral: true
      });
    }
  }
}

/**
 * Override command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeOverrideCommand(interaction) {
  const { ViolationLog } = require('../database');
  const { takeAction } = require('../utils/moderationUtils');
  
  try {
    // Check if user has appropriate permissions
    if (!interaction.member.permissions.has('ModerateMembers')) {
      return interaction.reply({
        content: 'You need moderation permissions to run this command.',
        ephemeral: true
      });
    }
    
    // Get parameters
    const caseId = interaction.options.getString('case_id');
    const action = interaction.options.getString('action');
    
    // Defer reply
    await interaction.deferReply({ ephemeral: true });
    
    // Check if this is a message ID or case ID
    let targetMessage;
    
    try {
      // First try to find the message directly
      try {
        targetMessage = await interaction.channel.messages.fetch(caseId);
      } catch (fetchError) {
        // If not found in current channel, look for case in database
        const violation = await ViolationLog.findById(caseId);
        
        if (!violation) {
          // Try to search for message in all channels
          let found = false;
          
          for (const [, channel] of interaction.guild.channels.cache) {
            if (channel.isTextBased() && channel.permissionsFor(interaction.guild.members.me).has('ViewChannel')) {
              try {
                targetMessage = await channel.messages.fetch(caseId);
                found = true;
                break;
              } catch (err) {
                // Message not in this channel, continue searching
              }
            }
          }
          
          if (!found) {
            return interaction.followUp({
              content: `Could not find case or message with ID ${caseId}. Make sure the ID is correct.`,
              ephemeral: true
            });
          }
        } else {
          // Case found in database, try to fetch the message
          try {
            const channel = interaction.guild.channels.cache.get(violation.channelId);
            if (channel) {
              targetMessage = await channel.messages.fetch(violation.messageId);
            } else {
              return interaction.followUp({
                content: `Found the case but couldn't access the channel to take action.`,
                ephemeral: true
              });
            }
          } catch (msgError) {
            return interaction.followUp({
              content: `Found the case but the message may have been deleted or is no longer accessible.`,
              ephemeral: true
            });
          }
        }
      }
      
      // Take action on the message
      if (action !== 'none') {
        await takeAction(action, targetMessage.author.id, targetMessage);
        
        // Log the override
        await ViolationLog.findOneAndUpdate(
          { messageId: targetMessage.id },
          {
            isViolation: action !== 'none',
            actionTaken: action,
            actionSource: 'override',
            updatedAt: Date.now()
          },
          { upsert: true }
        );
      }
      
      await interaction.followUp({
        content: `Moderation action \`${action}\` has been applied to the message from <@${targetMessage.author.id}>.`,
        ephemeral: true
      });
    } catch (error) {
      console.error('Error executing override command:', error);
      
      await interaction.followUp({
        content: 'An error occurred while taking action. Please try again later.',
        ephemeral: true
      });
    }
  } catch (error) {
    console.error('Error executing override command:', error);
    
    if (interaction.deferred) {
      await interaction.followUp({
        content: 'An error occurred. Please try again later.',
        ephemeral: true
      });
    } else {
      await interaction.reply({
        content: 'An error occurred. Please try again later.',
        ephemeral: true
      });
    }
  }
}

/**
 * Exempt command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeExemptCommand(interaction) {
  const { UserData } = require('../database');
  
  try {
    // Check if user has appropriate permissions
    if (!interaction.member.permissions.has('ModerateMembers')) {
      return interaction.reply({
        content: 'You need moderation permissions to run this command.',
        ephemeral: true
      });
    }
    
    // Get parameters
    const targetUser = interaction.options.getUser('user');
    const duration = interaction.options.getInteger('duration') || 0;
    
    // Calculate exempt until date
    let exemptUntil = null;
    if (duration && duration > 0) {
      exemptUntil = new Date();
      exemptUntil.setMinutes(exemptUntil.getMinutes() + duration);
    }
    
    // Update user data
    await UserData.findOneAndUpdate(
      { userId: targetUser.id, serverId: interaction.guild.id },
      {
        isExempt: true,
        exemptUntil,
        updatedAt: Date.now()
      },
      { upsert: true }
    );
    
    // Format duration message
    let durationText;
    if (duration === 0) {
      durationText = 'permanently';
    } else if (duration < 60) {
      durationText = `for ${duration} minute${duration > 1 ? 's' : ''}`;
    } else {
      const hours = Math.floor(duration / 60);
      const minutes = duration % 60;
      durationText = `for ${hours} hour${hours > 1 ? 's' : ''}${minutes > 0 ? ` and ${minutes} minute${minutes > 1 ? 's' : ''}` : ''}`;
    }
    
    await interaction.reply({
      content: `<@${targetUser.id}> has been exempted from AI moderation ${durationText}.`,
      ephemeral: false
    });
  } catch (error) {
    console.error('Error executing exempt command:', error);
    
    await interaction.reply({
      content: 'An error occurred. Please try again later.',
      ephemeral: true
    });
  }
}

/**
 * Stats command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeStatsCommand(interaction) {
  const { ViolationLog } = require('../database');
  
  try {
    // Get timeframe parameter
    const timeframe = interaction.options.getString('timeframe') || 'week';
    
    // Defer reply
    await interaction.deferReply({ ephemeral: false });
    
    // Calculate date range
    const now = new Date();
    let startDate;
    let timeframeLabel;
    
    switch (timeframe) {
      case 'today':
        startDate = new Date(now.setHours(0, 0, 0, 0));
        timeframeLabel = 'Today';
        break;
      case 'week':
        startDate = new Date(now);
        startDate.setDate(startDate.getDate() - 7);
        timeframeLabel = 'Last 7 Days';
        break;
      case 'month':
        startDate = new Date(now);
        startDate.setMonth(startDate.getMonth() - 1);
        timeframeLabel = 'Last 30 Days';
        break;
      case 'all':
        startDate = new Date(0); // Beginning of time
        timeframeLabel = 'All Time';
        break;
      default:
        startDate = new Date(now);
        startDate.setDate(startDate.getDate() - 7);
        timeframeLabel = 'Last 7 Days';
    }
    
    // Get violation statistics
    const totalMessages = await ViolationLog.countDocuments({
      serverId: interaction.guild.id,
      createdAt: { $gte: startDate }
    });
    
    const totalViolations = await ViolationLog.countDocuments({
      serverId: interaction.guild.id,
      isViolation: true,
      createdAt: { $gte: startDate }
    });
    
    // Get actions by type
    const actionCounts = await ViolationLog.aggregate([
      {
        $match: {
          serverId: interaction.guild.id,
          isViolation: true,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$actionTaken',
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Format actions
    const actionStats = actionCounts.map(action => 
      `• ${action._id.charAt(0).toUpperCase() + action._id.slice(1)}: ${action.count}`
    ).join('\n');
    
    // Get violations by category
    const categoryCounts = await ViolationLog.aggregate([
      {
        $match: {
          serverId: interaction.guild.id,
          isViolation: true,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);
    
    // Format categories
    const categoryStats = categoryCounts.map(category => 
      `• ${category._id ? category._id.charAt(0).toUpperCase() + category._id.slice(1) : 'Other'}: ${category.count}`
    ).join('\n');
    
    // Get top offenders
    const topOffenders = await ViolationLog.aggregate([
      {
        $match: {
          serverId: interaction.guild.id,
          isViolation: true,
          createdAt: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 5
      }
    ]);
    
    // Format top offenders
    let offendersStats = '';
    if (topOffenders.length > 0) {
      offendersStats = topOffenders.map(user => 
        `• <@${user._id}>: ${user.count} violation${user.count > 1 ? 's' : ''}`
      ).join('\n');
    } else {
      offendersStats = '• No violations detected in this period';
    }
    
    // Calculate percentage
    const violationPercentage = totalMessages > 0 
      ? ((totalViolations / totalMessages) * 100).toFixed(1) 
      : 0;
    
    // Format the stats message
    const statsMessage = `# Moderation Statistics (${timeframeLabel})

**Overview:**
• Messages Processed: ${totalMessages}
• Violations Detected: ${totalViolations} (${violationPercentage}%)

**Actions Taken:**
${actionStats || '• None'}

**Violation Categories:**
${categoryStats || '• None'}

**Top Users with Violations:**
${offendersStats}

For more detailed analytics, visit the [dashboard](https://dashboard.example.com/stats/${interaction.guild.id}).`;
    
    await interaction.followUp({
      content: statsMessage,
      ephemeral: false
    });
  } catch (error) {
    console.error('Error executing stats command:', error);
    
    if (interaction.deferred) {
      await interaction.followUp({
        content: 'An error occurred while retrieving statistics. Please try again later.',
        ephemeral: true
      });
    } else {
      await interaction.reply({
        content: 'An error occurred while retrieving statistics. Please try again later.',
        ephemeral: true
      });
    }
  }
}

module.exports = {
  executeSetupCommand,
  executeConfigCommand,
  executeStatusCommand,
  executeHelpCommand,
  executeReviewCommand,
  executeOverrideCommand,
  executeExemptCommand,
  executeStatsCommand
};
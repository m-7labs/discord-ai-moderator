const { Client, GatewayIntentBits, Events, Partials } = require('discord.js');
const { processMessage } = require('./moderator');
const { handleCommandInteraction } = require('./commands');
const { validateServerId, validateUserId } = require('./database');
const logger = require('./utils/logger');
const errorManager = require('./utils/errorManager');

// Validate environment variables
if (!process.env.DISCORD_BOT_TOKEN) {
  throw new Error('DISCORD_BOT_TOKEN is required');
}

if (!process.env.CLIENT_ID) {
  throw new Error('CLIENT_ID is required');
}

if (!process.env.DISCORD_BOT_TOKEN.length > 50) {
  throw new Error('Invalid Discord bot token format');
}

if (!validateUserId(process.env.CLIENT_ID)) {
  throw new Error('Invalid Discord client ID format');
}

// Initialize Discord client with security settings
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
  partials: [Partials.Message, Partials.Channel],
  // Security settings
  rest: {
    retries: 3,
    timeout: 15000,
    userAgentAppendix: 'Discord-AI-Moderator/1.0.0'
  },
  // Rate limiting protection
  ws: {
    large_threshold: 50,
    compress: true
  }
});

// Rate limiting for message processing
const messageProcessingLimiter = new Map();
const PROCESSING_RATE_LIMIT = 100; // messages per minute per guild
const RATE_LIMIT_WINDOW = 60000; // 1 minute

function checkMessageRateLimit(guildId) {
  const now = Date.now();
  const key = `guild_${guildId}`;
  
  if (!messageProcessingLimiter.has(key)) {
    messageProcessingLimiter.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  
  const data = messageProcessingLimiter.get(key);
  
  if (now > data.resetTime) {
    // Reset the counter
    messageProcessingLimiter.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  
  if (data.count >= PROCESSING_RATE_LIMIT) {
    return false; // Rate limited
  }
  
  data.count++;
  return true;
}

// Clean up rate limiting data periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of messageProcessingLimiter.entries()) {
    if (now > data.resetTime) {
      messageProcessingLimiter.delete(key);
    }
  }
}, RATE_LIMIT_WINDOW);

// Setup client event listeners for error handling
client.on('error', (error) => {
  errorManager.handleError(error, 'discord', { 
    operation: 'client',
    critical: true 
  });
});

client.on('shardError', (error, shardId) => {
  errorManager.handleError(error, 'discord', {
    operation: 'shard',
    shardId,
    critical: true
  });
});

client.on('warn', (message) => {
  logger.warn('Discord client warning:', message);
});

client.on('debug', (message) => {
  // Only log debug in development
  if (process.env.NODE_ENV === 'development') {
    logger.debug('Discord client debug:', message);
  }
});

// Bot ready event
client.once(Events.ClientReady, () => {
  logger.info(`Logged in as ${client.user.tag}`);
  logger.info(`Connected to ${client.guilds.cache.size} servers`);
  
  // Validate bot permissions in all guilds
  client.guilds.cache.forEach(guild => {
    const botMember = guild.members.me;
    if (!botMember) {
      logger.warn(`Bot not found as member in guild ${guild.name} (${guild.id})`);
      return;
    }
    
    // Check essential permissions
    const requiredPermissions = [
      'ViewChannel',
      'ReadMessageHistory',
      'SendMessages',
      'ManageMessages',
      'ModerateMembers'
    ];
    
    const missingPermissions = requiredPermissions.filter(
      permission => !botMember.permissions.has(permission)
    );
    
    if (missingPermissions.length > 0) {
      logger.warn(`Missing permissions in ${guild.name}: ${missingPermissions.join(', ')}`);
    }
  });
  
  // Setup presence with security-conscious information
  client.user.setPresence({
    activities: [{
      name: '/modagent_help',
      type: 0 // Playing
    }],
    status: 'online'
  });
});

// Message event handler with security checks
client.on(Events.MessageCreate, async (message) => {
  try {
    // Basic security checks
    if (!message || !message.guild || !message.author) {
      return;
    }
    
    // Skip messages from self
    if (message.author.id === client.user.id) return;
    
    // Validate IDs format for security
    if (!validateUserId(message.author.id) || !validateServerId(message.guild.id)) {
      logger.warn('Invalid ID format in message', {
        authorId: message.author.id?.length,
        guildId: message.guild.id?.length,
        messageId: message.id
      });
      return;
    }
    
    // Check rate limiting per guild
    if (!checkMessageRateLimit(message.guild.id)) {
      logger.warn(`Rate limit exceeded for guild ${message.guild.id}`);
      return;
    }
    
    // Content length check
    if (message.content && message.content.length > 4000) {
      logger.warn('Message content too long, skipping processing', {
        messageId: message.id,
        length: message.content.length
      });
      return;
    }
    
    // Check if message is from a webhook (additional security)
    if (message.webhookId) {
      logger.debug('Skipping webhook message', { webhookId: message.webhookId });
      return;
    }
    
    // Process message for moderation
    await processMessage(message);
  } catch (error) {
    errorManager.handleError(error, 'discord', {
      operation: 'messageCreate',
      messageId: message?.id,
      channelId: message?.channel?.id,
      guildId: message?.guild?.id,
      authorId: message?.author?.id?.substring(0, 10) + '...'
    });
  }
});

// Interaction event handler with security
client.on(Events.InteractionCreate, async (interaction) => {
  try {
    // Basic security validation
    if (!interaction || !interaction.guild || !interaction.user) {
      logger.warn('Invalid interaction received');
      return;
    }
    
    // Validate IDs
    if (!validateUserId(interaction.user.id) || !validateServerId(interaction.guild.id)) {
      logger.warn('Invalid ID format in interaction', {
        userId: interaction.user.id?.length,
        guildId: interaction.guild.id?.length
      });
      return;
    }
    
    // Only handle command interactions from our app
    if (interaction.isCommand()) {
      // Verify the command is from our application
      if (interaction.applicationId !== process.env.CLIENT_ID) {
        logger.warn('Command from unknown application', {
          applicationId: interaction.applicationId,
          commandName: interaction.commandName
        });
        return;
      }
      
      // Check if user has required permissions for the command
      const member = interaction.member;
      if (!member) {
        await interaction.reply({
          content: 'Unable to verify your permissions.',
          ephemeral: true
        });
        return;
      }
      
      // Log command usage for security monitoring
      logger.info('Command executed', {
        command: interaction.commandName,
        userId: interaction.user.id.substring(0, 10) + '...',
        guildId: interaction.guild.id.substring(0, 10) + '...',
        username: interaction.user.username
      });
      
      await handleCommandInteraction(interaction);
    }
  } catch (error) {
    errorManager.handleError(error, 'discord', {
      operation: 'interactionCreate',
      interactionId: interaction?.id,
      commandName: interaction?.commandName,
      userId: interaction?.user?.id?.substring(0, 10) + '...'
    });
    
    // Respond to user if we haven't already
    try {
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({
          content: 'An error occurred while processing this command.',
          ephemeral: true
        });
      } else if (interaction.deferred && !interaction.replied) {
        await interaction.followUp({
          content: 'An error occurred while processing this command.',
          ephemeral: true
        });
      }
    } catch (replyError) {
      logger.error('Failed to reply to interaction after error:', replyError);
    }
  }
});

// Guild-related events for security monitoring
client.on(Events.GuildCreate, (guild) => {
  logger.info(`Bot added to new guild: ${guild.name} (${guild.id})`, {
    memberCount: guild.memberCount,
    ownerId: guild.ownerId?.substring(0, 10) + '...'
  });
  
  // Check if this is a suspicious guild (very large or very new)
  if (guild.memberCount > 100000) {
    logger.warn(`Added to very large guild: ${guild.name} (${guild.memberCount} members)`);
  }
  
  const guildAge = Date.now() - guild.createdTimestamp;
  if (guildAge < 24 * 60 * 60 * 1000) { // Less than 24 hours old
    logger.warn(`Added to very new guild: ${guild.name} (created ${new Date(guild.createdTimestamp)})`);
  }
});

client.on(Events.GuildDelete, (guild) => {
  logger.info(`Bot removed from guild: ${guild.name} (${guild.id})`);
});

// Handle guild member add/remove for monitoring
client.on(Events.GuildMemberAdd, (member) => {
  // Log if a user with administrative permissions joins
  if (member.permissions.has('Administrator')) {
    logger.info('User with admin permissions joined', {
      userId: member.id.substring(0, 10) + '...',
      guildId: member.guild.id.substring(0, 10) + '...',
      username: member.user.username
    });
  }
});

// Graceful shutdown handling
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down Discord client gracefully...');
  try {
    client.destroy();
    logger.info('Discord client destroyed');
  } catch (error) {
    logger.error('Error during Discord client shutdown:', error);
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down Discord client gracefully...');
  try {
    client.destroy();
    logger.info('Discord client destroyed');
  } catch (error) {
    logger.error('Error during Discord client shutdown:', error);
  }
  process.exit(0);
});

module.exports = { client };
const _SecurityValidator = require("./utils/security-validator");
// Import all required classes from discord.js instead of separate packages
const { SlashCommandBuilder, REST, Routes } = require('discord.js');
const { PermissionFlagsBits } = require('discord.js');
const {
  executeSetupCommand,
  executeConfigCommand,
  executeStatusCommand,
  executeHelpCommand,
  executeReviewCommand,
  executeOverrideCommand,
  executeExemptCommand,
  executeStatsCommand
} = require('./handlers/command-handlers');
const logger = require('./utils/logger');

// Define slash commands
const commands = [
  new SlashCommandBuilder()
    .setName('modagent_setup')
    .setDescription('Setup the AI moderation system')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_config')
    .setDescription('Configure moderation settings')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_status')
    .setDescription('Check moderation system status')
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_help')
    .setDescription('View all available commands')
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_review')
    .setDescription('Manually review a message')
    .addStringOption(option =>
      option.setName('message_id')
        .setDescription('ID of the message to review')
        .setRequired(true))
    .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_override')
    .setDescription('Override an AI decision')
    .addStringOption(option =>
      option.setName('case_id')
        .setDescription('ID of the case to override')
        .setRequired(true))
    .addStringOption(option =>
      option.setName('action')
        .setDescription('Action to take')
        .setRequired(true)
        .addChoices(
          { name: 'None', value: 'none' },
          { name: 'Warn', value: 'warn' },
          { name: 'Mute', value: 'mute' },
          { name: 'Kick', value: 'kick' },
          { name: 'Ban', value: 'ban' }
        ))
    .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_exempt')
    .setDescription('Exempt a user from moderation')
    .addUserOption(option =>
      option.setName('user')
        .setDescription('User to exempt')
        .setRequired(true))
    .addIntegerOption(option =>
      option.setName('duration')
        .setDescription('Duration in minutes (0 for permanent)'))
    .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_stats')
    .setDescription('View moderation statistics')
    .addStringOption(option =>
      option.setName('timeframe')
        .setDescription('Timeframe for statistics')
        .addChoices(
          { name: 'Today', value: 'today' },
          { name: 'Week', value: 'week' },
          { name: 'Month', value: 'month' },
          { name: 'All Time', value: 'all' }
        ))
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_system')
    .setDescription('View detailed system status and health')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_reset_errors')
    .setDescription('Reset error counters and attempt system recovery')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .toJSON(),

  new SlashCommandBuilder()
    .setName('modagent_health_check')
    .setDescription('Force an immediate system health check')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .toJSON(),
];

// Register commands with Discord
const setupCommands = async () => {
  const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_BOT_TOKEN);

  try {
    logger.info('Started refreshing application commands...');

    await rest.put(
      Routes.applicationCommands(process.env.CLIENT_ID),
      { body: commands },
    );

    logger.info('Successfully reloaded application commands');
  } catch (error) {
    logger.error('Error registering commands:', error);
    throw error;
  }
};

// Handle command interactions
const handleCommandInteraction = async (interaction) => {
  const commandName = interaction.commandName;

  // Import system command handlers
  const {
    executeSystemStatusCommand,
    executeResetErrorsCommand,
    executeForceHealthCheckCommand
  } = require('./handlers/system-handler');

  switch (commandName) {
    case 'modagent_setup':
      await executeSetupCommand(interaction);
      break;
    case 'modagent_config':
      await executeConfigCommand(interaction);
      break;
    case 'modagent_status':
      await executeStatusCommand(interaction);
      break;
    case 'modagent_help':
      await executeHelpCommand(interaction);
      break;
    case 'modagent_review':
      await executeReviewCommand(interaction);
      break;
    case 'modagent_override':
      await executeOverrideCommand(interaction);
      break;
    case 'modagent_exempt':
      await executeExemptCommand(interaction);
      break;
    case 'modagent_stats':
      await executeStatsCommand(interaction);
      break;
    case 'modagent_system':
      await executeSystemStatusCommand(interaction);
      break;
    case 'modagent_reset_errors':
      await executeResetErrorsCommand(interaction);
      break;
    case 'modagent_health_check':
      await executeForceHealthCheckCommand(interaction);
      break;
    default:
      await interaction.reply({
        content: `Unknown command: ${commandName}`,
        ephemeral: true
      });
  }
};

module.exports = {
  setupCommands,
  handleCommandInteraction
};
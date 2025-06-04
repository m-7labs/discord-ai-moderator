/**
 * System status command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeSystemStatusCommand(interaction) {
  const errorManager = require('../utils/errorManager');
  const { getServerConfig } = require('../database');
  
  try {
    // Check if user has admin permissions
    if (!interaction.member.permissions.has('Administrator')) {
      return interaction.reply({
        content: 'You need administrator permissions to check system status.',
        ephemeral: true
      });
    }
    
    // Defer reply
    await interaction.deferReply({ ephemeral: true });
    
    // Get server configuration
    const serverId = interaction.guild.id;
    const config = await getServerConfig(serverId);
    
    // Get system status
    const status = errorManager.getStatus();
    
    // Calculate uptime
    const uptime = status.uptime;
    const days = Math.floor(uptime / (1000 * 60 * 60 * 24));
    const hours = Math.floor((uptime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
    const uptimeString = `${days}d ${hours}h ${minutes}m`;
    
    // Format service status
    const serviceStatus = Object.entries(status.serviceStatus).map(([name, data]) => {
      return `${name.charAt(0).toUpperCase() + name.slice(1)}: ${data.healthy ? '✅ Healthy' : '❌ Unhealthy'}`;
    }).join('\n');
    
    // Format error metrics
    const errorMetrics = status.metrics.errors.map(error => {
      return `${error.source.charAt(0).toUpperCase() + error.source.slice(1)}: ${error.count} errors`;
    }).join('\n');
    
    // Format the status message with detailed information
    const statusMessage = `# 🔍 System Status

**Current Mode:** ${status.degradedMode ? '⚠️ DEGRADED MODE' : '✅ NORMAL MODE'}
**System Uptime:** ${uptimeString}
**Total Operations:** ${status.metrics.totalOperations.toLocaleString()}

## Service Health
${serviceStatus}

${status.degradedMode ? 
`## ⚠️ DEGRADED MODE ACTIVE
The system is currently operating in degraded mode due to service issues. 
During this time:
- Only essential moderation functions are available
- Pattern-based detection is used instead of AI analysis for some messages
- Non-critical messages may be skipped to reduce load
- Anthropic API calls are limited to the most efficient model

We're working to restore normal operation as soon as possible.` 
: ''}

## Error Metrics
${errorMetrics || 'No errors reported'}

## Your Server Configuration
**Status:** ${config.enabled ? '✅ Active' : '⚠️ Disabled'}
**Strictness:** ${config.strictness.charAt(0).toUpperCase() + config.strictness.slice(1)}
**Channels Monitored:** ${config.channels.length}

For additional support, please contact our support team.`;
    
    await interaction.followUp({
      content: statusMessage,
      ephemeral: true
    });
  } catch (error) {
    console.error('Error executing system status command:', error);
    
    if (interaction.deferred && !interaction.replied) {
      await interaction.followUp({
        content: 'An error occurred while retrieving system status. Please try again later.',
        ephemeral: true
      });
    } else if (!interaction.replied) {
      await interaction.reply({
        content: 'An error occurred while retrieving system status. Please try again later.',
        ephemeral: true
      });
    }
  }
}

/**
 * Reset error counters command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeResetErrorsCommand(interaction) {
  const errorManager = require('../utils/errorManager');
  
  try {
    // Check if user has admin permissions
    if (!interaction.member.permissions.has('Administrator')) {
      return interaction.reply({
        content: 'You need administrator permissions to reset error counters.',
        ephemeral: true
      });
    }
    
    // Reset error metrics
    errorManager.metrics.errors = {};
    errorManager.metrics.totalOperations = 0;
    
    // Also reset service failure counters
    for (const service in errorManager.serviceStatus) {
      errorManager.serviceStatus[service].failures = 0;
      
      // If degraded mode was enabled due to this service, check its health
      if (!errorManager.serviceStatus[service].healthy) {
        // Force a health check
        let healthy = false;
        
        switch (service) {
          case 'discord':
            healthy = await errorManager.checkDiscordHealth();
            break;
          case 'anthropic':
            healthy = await errorManager.checkAnthropicHealth();
            break;
          case 'database':
            healthy = await errorManager.checkDatabaseHealth();
            break;
        }
        
        if (healthy) {
          errorManager.serviceStatus[service].healthy = true;
          await interaction.reply({
            content: `✅ Error counters reset and ${service} service health restored!`,
            ephemeral: true
          });
          return;
        }
      }
    }
    
    // If in degraded mode, check if we can exit it
    if (errorManager.degradedMode && errorManager.allServicesHealthy()) {
      await errorManager.disableDegradedMode();
      await interaction.reply({
        content: '✅ Error counters reset and system returned to normal mode!',
        ephemeral: true
      });
    } else {
      await interaction.reply({
        content: '✅ Error counters have been reset.',
        ephemeral: true
      });
    }
  } catch (error) {
    console.error('Error executing reset errors command:', error);
    
    await interaction.reply({
      content: 'An error occurred while resetting error counters. Please try again later.',
      ephemeral: true
    });
  }
}

/**
 * Force health check command handler
 * @param {Object} interaction - Discord.js interaction object
 */
async function executeForceHealthCheckCommand(interaction) {
  const errorManager = require('../utils/errorManager');
  
  try {
    // Check if user has admin permissions
    if (!interaction.member.permissions.has('Administrator')) {
      return interaction.reply({
        content: 'You need administrator permissions to force a health check.',
        ephemeral: true
      });
    }
    
    // Defer reply since health checks can take time
    await interaction.deferReply({ ephemeral: true });
    
    // Run health checks
    await errorManager.runHealthChecks();
    
    // Get updated status
    const status = errorManager.getStatus();
    
    // Format service status
    const serviceStatus = Object.entries(status.serviceStatus).map(([name, data]) => {
      return `${name.charAt(0).toUpperCase() + name.slice(1)}: ${data.healthy ? '✅ Healthy' : '❌ Unhealthy'}`;
    }).join('\n');
    
    // Format the message
    const statusMessage = `# Health Check Results

**Current Mode:** ${status.degradedMode ? '⚠️ DEGRADED MODE' : '✅ NORMAL MODE'}

## Service Health
${serviceStatus}

${status.degradedMode ? 
`## ⚠️ DEGRADED MODE ACTIVE
The system is still operating in degraded mode due to service issues.` 
: '✅ All services are operational.'}`;
    
    await interaction.followUp({
      content: statusMessage,
      ephemeral: true
    });
  } catch (error) {
    console.error('Error executing force health check command:', error);
    
    if (interaction.deferred && !interaction.replied) {
      await interaction.followUp({
        content: 'An error occurred while running health check. Please try again later.',
        ephemeral: true
      });
    } else if (!interaction.replied) {
      await interaction.reply({
        content: 'An error occurred while running health check. Please try again later.',
        ephemeral: true
      });
    }
  }
}

module.exports = {
  executeSystemStatusCommand,
  executeResetErrorsCommand,
  executeForceHealthCheckCommand
};
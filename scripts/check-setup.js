
/**
 * Discord AI Moderator Setup Validation Script
 * This script checks if your environment is properly configured
 */

const fs = require('fs');
// Path module is not used in this script
const _path = require('path');

console.log('🔍 Discord AI Moderator - Setup Validation');
console.log('==========================================\n');

let hasErrors = false;
let hasWarnings = false;

function logError(message) {
  console.log(`❌ ERROR: ${message}`);
  hasErrors = true;
}

function logWarning(message) {
  console.log(`⚠️  WARNING: ${message}`);
  hasWarnings = true;
}

function logSuccess(message) {
  console.log(`✅ ${message}`);
}

function logInfo(message) {
  console.log(`ℹ️  ${message}`);
}

// Check Node.js version
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);

if (majorVersion >= 18) {
  logSuccess(`Node.js version ${nodeVersion} is supported`);
} else {
  logError(`Node.js version ${nodeVersion} is not supported. Please upgrade to version 18 or higher.`);
}

// Check if package.json exists
if (fs.existsSync('package.json')) {
  logSuccess('package.json found');

  // Check if node_modules exists
  if (fs.existsSync('node_modules')) {
    logSuccess('Dependencies appear to be installed');
  } else {
    logError('Dependencies not installed. Run: npm install');
  }
} else {
  logError('package.json not found. Are you in the correct directory?');
}

// Check environment file
if (fs.existsSync('.env')) {
  logSuccess('.env file found');

  // Load and validate environment variables
  require('dotenv').config();

  const requiredVars = [
    'DISCORD_BOT_TOKEN',
    'CLIENT_ID'
  ];

  const conditionalVars = [
    {
      condition: () => process.env.AI_PROVIDER === 'ANTHROPIC',
      vars: ['ANTHROPIC_API_KEY'],
      name: 'Anthropic'
    },
    {
      condition: () => process.env.AI_PROVIDER === 'OPENROUTER' || !process.env.AI_PROVIDER,
      vars: ['OPENROUTER_API_KEY'],
      name: 'OpenRouter'
    }
  ];

  const optionalVars = [
    'AI_PROVIDER',
    'MONGODB_URI',
    'JWT_SECRET',
    'DASHBOARD_PORT',
    'LOG_LEVEL',
    'LOW_RISK_MODEL',
    'MEDIUM_RISK_MODEL',
    'HIGH_RISK_MODEL'
  ];

  // Check required variables
  console.log('\n📋 Checking required environment variables:');
  requiredVars.forEach(varName => {
    // eslint-disable-next-line security/detect-object-injection
    const value = process.env[varName];
    if (value && value.trim() !== '' && !value.includes('your_') && !value.includes('_here')) {
      logSuccess(`${varName} is configured`);
    } else {
      logError(`${varName} is missing or not properly configured`);
    }
  });

  // Check conditional variables based on AI provider
  console.log('\n📋 Checking AI provider configuration:');
  const aiProvider = process.env.AI_PROVIDER || 'OPENROUTER';
  logInfo(`AI Provider set to: ${aiProvider}`);

  conditionalVars.forEach(condition => {
    if (condition.condition()) {
      condition.vars.forEach(varName => {
        // eslint-disable-next-line security/detect-object-injection
        const value = process.env[varName];
        if (value && value.trim() !== '' && !value.includes('your_') && !value.includes('_here')) {
          logSuccess(`${varName} is configured for ${condition.name}`);
        } else {
          logError(`${varName} is required for ${condition.name} provider but not configured`);
        }
      });
    }
  });

  // Check optional variables
  console.log('\n📋 Checking optional environment variables:');
  optionalVars.forEach(varName => {
    // eslint-disable-next-line security/detect-object-injection
    const value = process.env[varName];
    if (value && value.trim() !== '' && !value.includes('your_')) {
      logSuccess(`${varName} is configured`);
    } else {
      logWarning(`${varName} is not configured (this is optional)`);
    }
  });

  // Validate token formats
  console.log('\n🔍 Validating token formats:');

  // Discord bot token should start with specific patterns
  const botToken = process.env.DISCORD_BOT_TOKEN;
  if (botToken && (botToken.length > 50 && botToken.includes('.'))) {
    logSuccess('Discord bot token format looks valid');
  } else if (botToken) {
    logWarning('Discord bot token format might be incorrect');
  }

  // Client ID should be numeric
  const clientId = process.env.CLIENT_ID;
  if (clientId && /^\d+$/.test(clientId) && clientId.length >= 17) {
    logSuccess('Discord client ID format looks valid');
  } else if (clientId) {
    logWarning('Discord client ID format might be incorrect (should be numeric)');
  }

  // Validate AI provider keys
  const currentAiProvider = process.env.AI_PROVIDER || 'OPENROUTER';
  if (currentAiProvider === 'ANTHROPIC') {
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (anthropicKey && anthropicKey.startsWith('sk-ant-')) {
      logSuccess('Anthropic API key format looks valid');
    } else if (anthropicKey) {
      logWarning('Anthropic API key format might be incorrect (should start with sk-ant-)');
    }
  } else if (currentAiProvider === 'OPENROUTER') {
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    if (openrouterKey && openrouterKey.startsWith('sk-or-v1-')) {
      logSuccess('OpenRouter API key format looks valid');
    } else if (openrouterKey) {
      logWarning('OpenRouter API key format might be incorrect (should start with sk-or-v1-)');
    }
  }

} else {
  logError('.env file not found. Copy .env.example to .env and configure it.');
}

// Check directory structure
console.log('\n📁 Checking directory structure:');
const requiredDirs = ['src', 'src/utils', 'src/handlers'];
const requiredFiles = [
  'src/index.js',
  'src/bot.js',
  'src/database.js',
  'src/utils/errorManager.js'
];

requiredDirs.forEach(dir => {
  if (fs.existsSync(dir)) {
    logSuccess(`Directory ${dir} exists`);
  } else {
    logError(`Directory ${dir} is missing`);
  }
});

requiredFiles.forEach(file => {
  if (fs.existsSync(file)) {
    logSuccess(`File ${file} exists`);
  } else {
    logError(`File ${file} is missing`);
  }
});

// Check if logs directory exists, create if not
if (!fs.existsSync('logs')) {
  try {
    fs.mkdirSync('logs');
    logSuccess('Created logs directory');
  } catch (error) {
    logWarning('Could not create logs directory');
  }
} else {
  logSuccess('Logs directory exists');
}

// Test database connectivity (basic check)
console.log('\n🗄️  Database configuration:');
const dbType = process.env.DB_TYPE || 'MONGODB';
if (dbType === 'MONGODB') {
  const mongoUri = process.env.MONGODB_URI;
  if (mongoUri && mongoUri.includes('mongodb')) {
    logSuccess('MongoDB URI format looks valid');
    if (mongoUri.includes('localhost') || mongoUri.includes('127.0.0.1')) {
      logInfo('Using local MongoDB - make sure MongoDB is running');
    } else if (mongoUri.includes('mongodb.net')) {
      logInfo('Using MongoDB Atlas - check your cluster is active');
    }
  } else {
    logWarning('MongoDB URI format might be incorrect');
  }
} else {
  logInfo('Using SQLite database');
}

// Check Docker setup if files exist
console.log('\n🐳 Docker configuration:');
if (fs.existsSync('docker-compose.yml')) {
  logSuccess('docker-compose.yml found');
  if (fs.existsSync('Dockerfile')) {
    logSuccess('Dockerfile found');
  } else {
    logWarning('Dockerfile not found');
  }
} else {
  logInfo('Docker files not found (Docker deployment not configured)');
}

// Summary
console.log('\n' + '='.repeat(50));
console.log('📊 SETUP VALIDATION SUMMARY');
console.log('='.repeat(50));

if (hasErrors) {
  console.log('❌ Setup has ERRORS that need to be fixed before running the bot.');
  console.log('\n🔧 Common fixes:');
  console.log('   • Run: npm install');
  console.log('   • Copy .env.example to .env and configure it');
  console.log('   • Get your Discord bot token from https://discord.com/developers/applications');
  console.log('   • Choose an AI provider:');
  console.log('     - OpenRouter (recommended): https://openrouter.ai');
  console.log('     - Anthropic (Claude only): https://console.anthropic.com');
  console.log('\n📚 For detailed help, see: INSTALLATION_GUIDE.md and AI_PROVIDER_GUIDE.md');
  process.exit(1);
} else if (hasWarnings) {
  console.log('⚠️  Setup is mostly ready but has some warnings.');
  console.log('✅ You can try running the bot, but some features might not work correctly.');
  console.log('\n🚀 To start the bot: npm start');
  console.log('📚 For detailed help, see: INSTALLATION_GUIDE.md');
} else {
  console.log('✅ Setup looks good! You should be ready to run the bot.');
  console.log('\n🚀 To start the bot: npm start');
  console.log('🎉 Happy moderating!');
}

console.log('\n📋 Next steps:');
console.log('   1. Add the bot to your Discord server');
console.log('   2. Run the bot with: npm start');
console.log('   3. Use /modagent_setup in your Discord server');
console.log('   4. Configure your moderation settings');

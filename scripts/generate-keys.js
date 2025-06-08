
/* eslint-disable no-console */
/**
 * Security Key Generation Script
 * Generates cryptographically secure keys for the Discord AI Moderator
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

function log(message, color = colors.white) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(message) {
  log('\n' + '='.repeat(60), colors.cyan);
  log(`  ${message}`, colors.bright + colors.cyan);
  log('='.repeat(60), colors.cyan);
}

function logSuccess(message) {
  log(`✅ ${message}`, colors.green);
}

function logWarning(message) {
  log(`⚠️  ${message}`, colors.yellow);
}

function logError(message) {
  log(`❌ ${message}`, colors.red);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, colors.blue);
}

/**
 * Generate a cryptographically secure random string
 */
function generateSecureKey(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a strong JWT secret
 */
function generateJWTSecret() {
  // Generate 64 random bytes for JWT secret
  const secret = crypto.randomBytes(64).toString('base64url');
  return secret;
}

/**
 * Generate all required security keys
 */
function generateAllKeys() {
  const keys = {
    // 32-byte encryption key for AES-256
    ENCRYPTION_KEY: generateSecureKey(32),

    // JWT signing secret (64 bytes base64url encoded)
    JWT_SECRET: generateJWTSecret(),

    // HMAC secret for audit log integrity (32 bytes)
    AUDIT_SECRET_KEY: generateSecureKey(32),

    // Session hash salt (16 bytes)
    HASH_SALT: generateSecureKey(16),

    // Instance secret for distributed systems (16 bytes)
    INSTANCE_SECRET: generateSecureKey(16),

    // Webhook verification secret (32 bytes)
    WEBHOOK_SECRET: generateSecureKey(32)
  };

  return keys;
}

/**
 * Validate existing .env file
 */
function validateExistingEnv() {
  const envPath = path.join(process.cwd(), '.env');

  if (!fs.existsSync(envPath)) {
    return { exists: false, keys: {} };
  }

  try {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const existingKeys = {};

    const keyPatterns = [
      'ENCRYPTION_KEY',
      'JWT_SECRET',
      'AUDIT_SECRET_KEY',
      'HASH_SALT',
      'INSTANCE_SECRET',
      'WEBHOOK_SECRET'
    ];

    keyPatterns.forEach(key => {
      // eslint-disable-next-line security/detect-non-literal-regexp
      const regex = new RegExp(`^${key}=(.+)$`, 'm');
      const match = envContent.match(regex);
      if (match && match[1] && match[1].trim() !== '' && match[1] !== 'your_key_here') {
        // eslint-disable-next-line security/detect-object-injection
        existingKeys[key] = match[1];
      }
    });

    return { exists: true, keys: existingKeys, content: envContent };
  } catch (error) {
    logError(`Failed to read existing .env file: ${error.message}`);
    return { exists: false, keys: {} };
  }
}

/**
 * Update or create .env file with new keys
 */
function updateEnvFile(newKeys, existingEnv) {
  const envPath = path.join(process.cwd(), '.env');
  const examplePath = path.join(process.cwd(), '.env.example');

  let envContent;

  if (existingEnv.exists) {
    envContent = existingEnv.content;
  } else if (fs.existsSync(examplePath)) {
    logInfo('Creating .env from .env.example template...');
    envContent = fs.readFileSync(examplePath, 'utf8');
  } else {
    logError('.env.example file not found. Creating basic .env file...');
    envContent = generateBasicEnvTemplate();
  }

  // Update or add each key
  Object.entries(newKeys).forEach(([key, value]) => {
    // eslint-disable-next-line security/detect-non-literal-regexp
    const regex = new RegExp(`^${key}=.*$`, 'm');
    const replacement = `${key}=${value}`;

    if (envContent.match(regex)) {
      envContent = envContent.replace(regex, replacement);
    } else {
      // Add the key at the end of the security section or end of file
      if (envContent.includes('# Security')) {
        envContent = envContent.replace(
          /(# Security.*?\n)/s,
          `$1${replacement}\n`
        );
      } else {
        envContent += `\n# Generated Security Keys\n${replacement}\n`;
      }
    }
  });

  try {
    fs.writeFileSync(envPath, envContent);
    logSuccess(`.env file updated at: ${envPath}`);
  } catch (error) {
    logError(`Failed to write .env file: ${error.message}`);
    throw error;
  }
}

/**
 * Generate basic .env template if .env.example doesn't exist
 */
function generateBasicEnvTemplate() {
  return `# Discord Bot Configuration
DISCORD_BOT_TOKEN=your_discord_bot_token_here
CLIENT_ID=your_discord_client_id_here

# AI Provider Configuration
AI_PROVIDER=OPENROUTER
OPENROUTER_API_KEY=your_openrouter_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/discord-ai-moderator

# Security Keys (Generated)
# These keys are automatically generated - DO NOT SHARE

# Performance Settings
REDIS_URL=redis://localhost:6379
ENABLE_CLUSTERING=false
ENABLE_CACHING=true

# Monitoring
SECURITY_WS_PORT=8080
MONITORING_INTERVAL=30000
HEALTH_CHECK_INTERVAL=60000

# Privacy & Compliance
DATA_RETENTION_DAYS=365
ANONYMIZATION_ENABLED=true
AUDIT_RETENTION_DAYS=90

# Dashboard
DASHBOARD_ENABLED=true
DASHBOARD_PORT=3000
`;
}

/**
 * Display security information
 */
function displaySecurityInfo(keys) {
  logHeader('SECURITY INFORMATION');

  log('\n📋 Generated Keys:', colors.bright);
  Object.entries(keys).forEach(([key, value]) => {
    const maskedValue = value.substring(0, 8) + '...' + value.substring(value.length - 8);
    log(`   ${key}: ${maskedValue}`, colors.cyan);
  });

  log('\n🔒 Security Best Practices:', colors.bright + colors.yellow);
  log('   • Never commit .env files to version control');
  log('   • Store these keys securely in production');
  log('   • Rotate keys regularly in production environments');
  log('   • Use environment-specific keys for dev/staging/prod');
  log('   • Consider using a secrets management service in production');

  log('\n🚨 IMPORTANT WARNINGS:', colors.bright + colors.red);
  log('   • Keep these keys secret and secure');
  log('   • Do not share keys in public repositories');
  log('   • Regenerate keys if compromised');
  log('   • Use different keys for different environments');
}

/**
 * Backup existing .env file
 */
function backupExistingEnv() {
  const envPath = path.join(process.cwd(), '.env');

  if (fs.existsSync(envPath)) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(process.cwd(), `.env.backup.${timestamp}`);

    try {
      fs.copyFileSync(envPath, backupPath);
      logInfo(`Existing .env backed up to: .env.backup.${timestamp}`);
    } catch (error) {
      logWarning(`Failed to backup existing .env: ${error.message}`);
    }
  }
}

/**
 * Main execution function
 */
async function main() {
  try {
    logHeader('Discord AI Moderator - Security Key Generator');

    log('\nThis script will generate cryptographically secure keys for your Discord AI Moderator.');
    log('These keys are essential for security features including encryption, JWT tokens, and audit logging.\n');

    // Check existing environment
    const existingEnv = validateExistingEnv();
    const existingKeyCount = Object.keys(existingEnv.keys).length;

    if (existingKeyCount > 0) {
      logInfo(`Found ${existingKeyCount} existing security keys in .env file`);

      // Show existing keys (masked)
      Object.keys(existingEnv.keys).forEach(key => {
        // eslint-disable-next-line security/detect-object-injection
        const value = existingEnv.keys[key];
        const maskedValue = value.substring(0, 4) + '...' + value.substring(value.length - 4);
        logInfo(`   ${key}: ${maskedValue}`);
      });
    }

    // Generate new keys
    logInfo('\nGenerating new security keys...');
    const newKeys = generateAllKeys();

    // Merge with existing keys (prioritize existing)
    const finalKeys = { ...newKeys, ...existingEnv.keys };

    // Count new keys being generated
    const newKeyCount = Object.keys(newKeys).filter(key => {
      // eslint-disable-next-line security/detect-object-injection
      return !existingEnv.keys[key];
    }).length;

    if (newKeyCount > 0) {
      logSuccess(`Generated ${newKeyCount} new security keys`);

      // Backup existing .env if it exists
      if (existingEnv.exists) {
        backupExistingEnv();
      }

      // Update .env file
      updateEnvFile(finalKeys, existingEnv);

      // Display security information
      displaySecurityInfo(finalKeys);

      log('\n✅ Security key generation completed successfully!', colors.bright + colors.green);
      log('\nNext steps:', colors.bright);
      log('1. Review your .env file and add your Discord bot token and API keys');
      log('2. Ensure .env is added to your .gitignore file');
      log('3. Set up Redis server for session management');
      log('4. Run npm install to install dependencies');
      log('5. Start your bot with npm start');

    } else {
      logInfo('All security keys already exist in .env file. No new keys generated.');
      logInfo('To regenerate all keys, delete the existing keys from .env and run this script again.');
    }

  } catch (error) {
    logError(`Key generation failed: ${error.message}`);
    process.exit(1);
  }
}

// Handle command line arguments
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  logHeader('Discord AI Moderator - Key Generator Help');
  log('\nUsage: node scripts/generate-keys.js [options]\n');
  log('Options:');
  log('  --help, -h     Show this help message');
  log('  --force        Regenerate all keys (overwrites existing)');
  log('  --backup       Create backup before generating new keys');
  log('\nThis script generates cryptographically secure keys for:');
  log('  • ENCRYPTION_KEY (32 bytes) - AES-256 encryption');
  log('  • JWT_SECRET (64 bytes) - JWT token signing');
  log('  • AUDIT_SECRET_KEY (32 bytes) - Audit log integrity');
  log('  • HASH_SALT (16 bytes) - Password hashing');
  log('  • INSTANCE_SECRET (16 bytes) - Instance identification');
  log('  • WEBHOOK_SECRET (32 bytes) - Webhook verification');
  log('\nGenerated keys are automatically added to your .env file.');
  process.exit(0);
}

if (args.includes('--force')) {
  logWarning('Force mode enabled - will regenerate ALL keys');
  // TODO: Implement force mode if needed
}

// Run the main function
if (require.main === module) {
  main();
}

module.exports = {
  generateAllKeys,
  generateSecureKey,
  generateJWTSecret,
  validateExistingEnv,
  updateEnvFile
};
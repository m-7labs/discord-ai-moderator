# Discord AI Moderator - Complete Installation Guide

This comprehensive guide will help you set up and run the Discord AI Moderator bot on your computer or server with enterprise-grade security features.

## 📋 Prerequisites

Before starting, ensure you have:

1. **Node.js** (version 18.0.0 or higher) - [Download here](https://nodejs.org)
2. **MongoDB** (version 4.4 or higher) - Local installation or [MongoDB Atlas](https://mongodb.com/atlas) (free cloud option)
3. **Redis** (version 6.0 or higher) - Optional but recommended for production
4. **Discord Bot Token** - [Create here](https://discord.com/developers/applications)
5. **AI API Key** - [OpenRouter](https://openrouter.ai) (recommended) or [Anthropic](https://anthropic.com)

## 🚀 Quick Start (One-Command Setup)

For experienced users:

```bash
git clone https://github.com/yourusername/discord-ai-moderator.git
cd discord-ai-moderator
npm run setup:complete
```

This will:
- Install all dependencies
- Generate security keys
- Create `.env` file from template
- Run validation checks

Then edit your `.env` file with your tokens and run `npm start`.

---

## 📝 Detailed Step-by-Step Installation

### Step 1: Install Node.js

#### Windows:
1. Go to [nodejs.org](https://nodejs.org)
2. Download the **LTS version** (Long Term Support)
3. Run the installer and follow the prompts
4. Open **Command Prompt** and verify installation:
   ```cmd
   node --version
   npm --version
   ```

#### macOS:
**Option A - Direct Download:**
1. Go to [nodejs.org](https://nodejs.org) and download the LTS version
2. Run the installer

**Option B - Using Homebrew (recommended):**
```bash
brew install node
```

Verify installation:
```bash
node --version
npm --version
```

#### Linux (Ubuntu/Debian):
```bash
# Install Node.js LTS
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

#### Linux (CentOS/RHEL/Fedora):
```bash
# Install Node.js LTS
curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
sudo dnf install -y nodejs npm

# Verify installation
node --version
npm --version
```

### Step 2: Set Up Database

#### Option A: MongoDB Atlas (Recommended for Beginners)

**MongoDB Atlas provides a free cloud database:**

1. Go to [mongodb.com/atlas](https://www.mongodb.com/atlas)
2. Create a free account
3. Click **"Build a Database"**
4. Choose **"Shared"** (free tier)
5. Select **"AWS"** and your closest region
6. Name your cluster (e.g., "discord-moderator")
7. Wait for the cluster to be created (2-3 minutes)

**Configure Access:**
1. Click **"Database Access"** in the sidebar
2. Click **"Add New Database User"**
3. Choose **"Password"** authentication
4. Create username and strong password
5. Set role to **"Read and write to any database"**
6. Click **"Add User"**

**Set Network Access:**
1. Click **"Network Access"** in the sidebar
2. Click **"Add IP Address"**
3. Choose **"Allow access from anywhere"** (for development)
4. Click **"Confirm"**

**Get Connection String:**
1. Go back to **"Database"**
2. Click **"Connect"** on your cluster
3. Choose **"Connect your application"**
4. Copy the connection string (looks like: `mongodb+srv://username:password@cluster.mongodb.net/`)
5. **Save this connection string** - you'll need it in Step 6

#### Option B: Local MongoDB Installation

**Windows:**
1. Download MongoDB Community Server from [mongodb.com/try/download/community](https://www.mongodb.com/try/download/community)
2. Run the installer with default settings
3. MongoDB will start automatically as a Windows service

**macOS:**
```bash
# Using Homebrew
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb/brew/mongodb-community
```

**Linux (Ubuntu/Debian):**
```bash
# Import MongoDB public GPG key
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -

# Create list file for MongoDB
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

# Update and install
sudo apt-get update
sudo apt-get install -y mongodb-org

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
```

Your local connection string will be: `mongodb://localhost:27017/discord-ai-moderator`

### Step 3: Set Up Redis (Optional but Recommended)

Redis improves performance and enables advanced features like session management and caching.

#### Option A: Redis Cloud (Free Tier)
1. Go to [redis.com](https://redis.com)
2. Create free account
3. Create new database
4. Copy connection string (format: `redis://username:password@host:port`)

#### Option B: Local Redis Installation

**Windows:**
1. Download Redis from [github.com/microsoftarchive/redis/releases](https://github.com/microsoftarchive/redis/releases)
2. Extract and run `redis-server.exe`

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**Docker (All Platforms):**
```bash
docker run -d -p 6379:6379 --name redis redis:7-alpine
```

Your local Redis connection will be: `redis://localhost:6379`

### Step 4: Create Discord Bot

#### Create Discord Application:
1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. Click **"New Application"**
3. Give it a name (e.g., "AI Moderator Pro")
4. Click **"Create"**

#### Set Up Bot:
1. Click **"Bot"** in the sidebar
2. Click **"Add Bot"** → **"Yes, do it!"**
3. Under **"Token"**, click **"Copy"** to copy your bot token
4. **⚠️ Save this token securely - you'll need it later**
5. **⚠️ Never share this token publicly**

#### Configure Bot Settings:
1. Under **"Privileged Gateway Intents"**, enable:
   - ✅ **Message Content Intent** (required)
   - ✅ **Server Members Intent** (recommended for better user tracking)
2. Under **"Authorization Flow"**, disable **"Public Bot"** if you want to keep it private

#### Get Application ID:
1. Go to **"General Information"** tab
2. Copy the **"Application ID"** (this is your `CLIENT_ID`)

### Step 5: Get AI Provider API Key

You have two options for AI providers. **OpenRouter is recommended** as it provides access to multiple AI models and better cost optimization.

#### Option A: OpenRouter (Recommended - Multi-Provider Access)

**Benefits:**
- Access to Claude, GPT, Gemini, and 50+ other models
- Cost comparison and optimization
- Pay only for what you use (no monthly fees)
- Automatic failover between providers
- Better rate limits

**Setup:**
1. Go to [openrouter.ai](https://openrouter.ai)
2. Create account or sign in
3. Go to **"Keys"** in your dashboard
4. Click **"Create Key"**
5. Give it a name (e.g., "Discord Moderator")
6. **Copy and save the API key** (starts with `sk-or-v1-`)
7. **Add credits** to your account:
   - Click **"Credits"** in dashboard
   - Add $5-20 to start (goes a long way)
   - Models cost $0.0001-0.01 per message typically

#### Option B: Direct Anthropic (Claude Only)

**Setup:**
1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Create account or sign in
3. Go to **"API Keys"** in dashboard
4. Click **"Create Key"**
5. Give it a name and click **"Create"**
6. **Copy and save the API key** (starts with `sk-ant-`)
7. **Add credits** to your account in the billing section

### Step 6: Download and Configure the Project

#### Download the Project:
```bash
# Clone the repository
git clone https://github.com/yourusername/discord-ai-moderator.git
cd discord-ai-moderator

# Install dependencies
npm install
```

#### Generate Security Keys:
```bash
# This generates all required encryption keys automatically
npm run generate:keys
```

This creates a `.env` file with secure encryption keys pre-generated.

#### Configure Environment Variables:

Edit the `.env` file with your information:

```bash
# Open with your preferred editor
nano .env        # Linux/Mac
code .env        # VS Code
notepad .env     # Windows
```

**Required Configuration:**
```env
# Discord Configuration
DISCORD_BOT_TOKEN=your_bot_token_from_step_4
CLIENT_ID=your_application_id_from_step_4

# AI Provider Configuration
AI_PROVIDER=OPENROUTER

# If using OpenRouter (recommended):
OPENROUTER_API_KEY=your_openrouter_key_from_step_5
OPENROUTER_APP_NAME=Discord-AI-Moderator
OPENROUTER_SITE_URL=https://github.com/yourusername/discord-ai-moderator

# If using Anthropic instead:
# AI_PROVIDER=ANTHROPIC
# ANTHROPIC_API_KEY=your_anthropic_key_from_step_5

# Database Configuration
MONGODB_URI=your_mongodb_connection_string_from_step_2

# Redis Configuration (optional but recommended)
REDIS_URL=your_redis_connection_string_from_step_3

# Performance Settings
ENABLE_CLUSTERING=false
ENABLE_CACHING=true
```

**Advanced Configuration (Optional):**
```env
# Model Selection (for OpenRouter)
LOW_RISK_MODEL=anthropic/claude-3-haiku:beta
MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta  
HIGH_RISK_MODEL=anthropic/claude-3-opus:beta

# Security Settings
SECURITY_WS_PORT=8080
MONITORING_INTERVAL=30000

# Dashboard
DASHBOARD_ENABLED=true
DASHBOARD_PORT=3000

# Privacy & Compliance
DATA_RETENTION_DAYS=365
ANONYMIZATION_ENABLED=true

# Logging
LOG_LEVEL=info
```

### Step 7: Invite Bot to Your Discord Server

#### Generate Invite Link:
1. In Discord Developer Portal, go to **"OAuth2"** → **"URL Generator"**
2. Select scopes:
   - ✅ **bot**
   - ✅ **applications.commands**
3. Select bot permissions:
   - ✅ **Read Messages/View Channels**
   - ✅ **Send Messages**
   - ✅ **Manage Messages**
   - ✅ **Moderate Members**
   - ✅ **Use Slash Commands**
   - ✅ **Add Reactions**
   - ✅ **Read Message History**
4. Copy the generated URL

#### Add to Server:
1. Open the generated URL in your browser
2. Select your Discord server
3. Click **"Authorize"**
4. Complete the captcha if prompted

### Step 8: Start the Bot

#### Test the Installation:
```bash
# Run validation checks
npm run validate

# Start the bot
npm start
```

**Expected Output:**
```
✅ Environment validation passed
✅ Security components initialized successfully  
✅ Database connected
✅ Redis connected (if configured)
✅ Discord commands registered
✅ Logged in as YourBotName#1234
✅ Security monitoring initialized
✅ Discord AI Moderator started successfully in 2847ms
```

#### Verify Bot is Working:
1. In your Discord server, type: `/moderate help`
2. You should see a list of available commands
3. Try: `/moderate setup` to begin configuration

### Step 9: Initial Bot Configuration

#### Server Setup:
1. Run `/moderate setup` in your Discord server
2. Follow the interactive setup wizard:
   - Configure moderation channels
   - Set strictness levels
   - Enable/disable features
   - Set up custom rules

#### Test the System:
1. Run `/moderate test` to test AI moderation
2. Send a test message that should be flagged
3. Check that the bot responds appropriately

### Step 10: Access Web Dashboard (Optional)

If you enabled the dashboard:

1. Open your browser and go to `http://localhost:3000`
2. You'll be prompted to authenticate with Discord
3. Configure additional settings through the web interface:
   - View real-time moderation logs
   - Monitor system performance
   - Manage server settings
   - Review user appeals

## 🔧 Production Deployment

### Using PM2 (Process Manager)
```bash
# Install PM2 globally
npm install -g pm2

# Start the bot with PM2
pm2 start src/index.js --name discord-ai-moderator

# Save PM2 configuration
pm2 save

# Set up PM2 to start on system boot
pm2 startup
```

### Using Docker
```bash
# Build and run with Docker Compose
npm run compose:up

# View logs
npm run compose:logs

# Stop services
npm run compose:down
```

### Environment-Specific Configuration

**Development:**
```env
NODE_ENV=development
LOG_LEVEL=debug
ENABLE_CLUSTERING=false
```

**Production:**
```env
NODE_ENV=production
LOG_LEVEL=info
ENABLE_CLUSTERING=true
ENABLE_CACHING=true
```

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Bot doesn't respond to commands:
- ✅ Check bot is online in Discord server member list
- ✅ Verify bot has required permissions
- ✅ Check console for error messages
- ✅ Ensure bot was invited with slash command permissions
- ✅ Try kicking and re-inviting the bot

#### "Invalid Token" error:
- ✅ Double-check Discord bot token in `.env`
- ✅ Ensure no extra spaces or characters
- ✅ Regenerate token if necessary in Discord Developer Portal
- ✅ Restart the bot after changing token

#### Database connection errors:
- ✅ Verify MongoDB connection string format
- ✅ For Atlas: Check IP whitelist and user permissions  
- ✅ For local: Ensure MongoDB service is running
- ✅ Test connection with MongoDB Compass

#### AI API errors:
- ✅ Verify API key is correct and active
- ✅ Check account has sufficient credits
- ✅ Monitor usage in provider's console
- ✅ For OpenRouter: Check model availability
- ✅ Check rate limits haven't been exceeded

#### Permission errors:
- ✅ Ensure bot role is above roles it needs to moderate
- ✅ Check channel-specific permissions
- ✅ Verify server-wide bot permissions
- ✅ Check for permission overwrites

#### Redis connection issues:
- ✅ Verify Redis is running (`redis-cli ping`)
- ✅ Check connection string format
- ✅ Ensure Redis accepts external connections if remote
- ✅ Bot will work without Redis but with reduced functionality

### Performance Issues

#### High latency/slow responses:
- ✅ Enable Redis caching with `ENABLE_CACHING=true`
- ✅ Use clustering with `ENABLE_CLUSTERING=true`
- ✅ Choose faster AI models for low-risk messages
- ✅ Monitor system resources (CPU, memory)

#### High AI costs:
- ✅ Use OpenRouter for cost optimization
- ✅ Configure appropriate model tiers (Haiku for low-risk)
- ✅ Adjust strictness levels to reduce API calls
- ✅ Enable pre-filtering to skip obvious non-violations
- ✅ Monitor usage in your AI provider dashboard

### Debug Mode

Enable detailed logging for troubleshooting:

```env
LOG_LEVEL=debug
NODE_ENV=development
```

Then restart and check logs:
```bash
npm run dev
# or
tail -f logs/moderator.log
```

### System Health Checks

Check system status:
```bash
# In Discord
/moderate system

# Or via API
curl http://localhost:3000/api/health
```

## 🛡️ Security Best Practices

### Environment Security
1. **Never commit `.env` files** to version control
2. **Use strong, unique passwords** for all services
3. **Regularly rotate API keys** (monthly recommended)
4. **Enable two-factor authentication** on all accounts
5. **Use environment-specific keys** for dev/staging/production

### Database Security
1. **Use MongoDB authentication** in production
2. **Enable SSL/TLS** for database connections
3. **Regular database backups**:
   ```bash
   npm run backup:data
   ```
4. **Monitor database access logs**
5. **Use MongoDB Atlas security features** if using cloud

### API Security
1. **Monitor API usage** to detect unusual patterns
2. **Set up billing alerts** to avoid unexpected charges
3. **Use separate API keys** for different environments
4. **Regularly review API access logs**
5. **Enable rate limiting** on your AI provider account

### Discord Security
1. **Use minimal required permissions** for the bot
2. **Regularly audit bot permissions** in servers
3. **Monitor bot activity logs**
4. **Keep Discord.js library updated**
5. **Use server-specific configurations**

## 📊 Monitoring and Maintenance

### Regular Maintenance Tasks

#### Daily:
- Check system health via dashboard or `/moderate system`
- Monitor AI usage and costs
- Review moderation logs for accuracy

#### Weekly:
- Update dependencies: `npm run update:deps`
- Security audit: `npm run test:security`
- Backup data: `npm run backup:data`
- Review error logs

#### Monthly:
- Rotate API keys
- Review and update moderation rules
- Update bot permissions as needed
- Performance optimization review

### Monitoring Setup

#### Built-in Monitoring:
- Web dashboard at `http://localhost:3000`
- WebSocket alerts for critical events
- Comprehensive logging system
- Health check endpoints

#### External Monitoring (Recommended):
```bash
# Set up external health checks
# Example webhook for status monitoring
HEALTH_CHECK_URL=https://your-monitoring-service.com/webhook
```

### Performance Metrics

Key metrics to monitor:
- **Response time**: Should be <200ms average
- **AI API usage**: Track tokens/costs per day
- **Memory usage**: Should stay under 512MB per instance
- **Database performance**: Query times <50ms
- **Error rates**: Should be <1% of total requests

### Logs and Analytics

#### Log Files:
- `logs/moderator.log` - General application logs
- `logs/security.log` - Security events and alerts
- `logs/moderation.log` - Moderation actions taken
- `logs/error.log` - Error tracking and debugging

#### Analytics Dashboard:
Access detailed analytics at `http://localhost:3000/analytics`:
- Moderation statistics by server
- AI model performance comparison
- Cost analysis and optimization suggestions
- User behavior patterns
- Security incident reports

## 🔄 Updating the Bot

### Standard Updates:
```bash
# Pull latest changes
git pull origin main

# Update dependencies
npm install

# Run validation
npm run validate

# Restart bot
npm start
```

### Major Version Updates:
1. **Backup your data** first: `npm run backup:data`
2. **Read the changelog** for breaking changes
3. **Test in development** environment first
4. **Update configuration** as needed
5. **Deploy to production** during low-traffic period

### Rollback Procedure:
```bash
# If update causes issues
git checkout previous-working-commit
npm install
npm start

# Restore data if needed
npm run restore:data backup-file-name.json
```

## 🆘 Getting Support

### Self-Help Resources:
1. **Check the logs** first: `logs/moderator.log`
2. **Run system diagnostics**: `/moderate system`
3. **Search existing issues**: [GitHub Issues](https://github.com/yourusername/discord-ai-moderator/issues)
4. **Check the wiki**: [GitHub Wiki](https://github.com/yourusername/discord-ai-moderator/wiki)

### Community Support:
1. **GitHub Discussions**: [Ask questions and share ideas](https://github.com/yourusername/discord-ai-moderator/discussions)
2. **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/discord-ai-moderator/issues)
3. **Discord Server**: [Join our support community](https://discord.gg/your-support-server)

### Creating Bug Reports:

When reporting issues, include:
```bash
# Generate system information
npm run generate:debug-info

# This creates debug-info.json with:
# - System specifications
# - Installed versions
# - Configuration (sanitized)
# - Recent error logs
# - Performance metrics
```

Attach this file to your GitHub issue along with:
- **Clear description** of the problem
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Screenshots** if applicable

### Security Issues:

**⚠️ Do not report security vulnerabilities publicly**

Instead:
1. Email security issues to: `security@yourproject.com`
2. Include full details and reproduction steps
3. Allow 48 hours for initial response
4. We'll work with you to address the issue privately

## 📋 Post-Installation Checklist

After successful installation, verify:

### Basic Functionality:
- [ ] Bot appears online in Discord server
- [ ] Slash commands respond correctly (`/moderate help`)
- [ ] Setup wizard completes (`/moderate setup`)
- [ ] Test moderation works (`/moderate test`)
- [ ] Dashboard accessible (if enabled)

### Security:
- [ ] Environment variables properly configured
- [ ] Security keys generated and unique
- [ ] Database access restricted
- [ ] API keys have appropriate permissions
- [ ] Audit logging enabled

### Performance:
- [ ] Response times under 200ms
- [ ] Memory usage reasonable (<512MB)
- [ ] No error messages in logs
- [ ] Caching enabled (if Redis configured)
- [ ] Monitoring dashboard functional

### Compliance:
- [ ] Privacy policy reviewed and accepted
- [ ] Data retention policies configured
- [ ] GDPR compliance features enabled
- [ ] Audit logging properly configured
- [ ] Backup procedures tested

## 🎯 Next Steps

After installation:

1. **Configure your server settings**:
   - Run `/moderate setup` for initial configuration
   - Customize moderation rules for your community
   - Set up custom responses and actions

2. **Train your moderation team**:
   - Familiarize moderators with new commands
   - Establish procedures for appeal reviews
   - Set up escalation processes

3. **Monitor and optimize**:
   - Review moderation accuracy daily
   - Adjust settings based on performance
   - Monitor costs and optimize model usage

4. **Stay updated**:
   - Star the repository for updates
   - Join the community discussions
   - Follow the project roadmap

5. **Contribute back**:
   - Report bugs and suggest improvements
   - Share your configuration templates
   - Help other users in discussions

---

## 🎉 Congratulations!

Your Discord AI Moderator is now installed and ready to protect your community with enterprise-grade AI moderation. The system includes advanced security features, comprehensive monitoring, and intelligent cost optimization.

**Need help?** Check our [troubleshooting section](#🔍-troubleshooting) or reach out to the community.

**Want to contribute?** See our [contributing guidelines](CONTRIBUTING.md).

**Found this helpful?** ⭐ Star the repository and share with others!

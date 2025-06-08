# Discord AI Moderator Installation Guide

This guide provides detailed instructions for installing, configuring, and running the Discord AI Moderator application with all its advanced features.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [Redis Setup](#redis-setup)
7. [Discord Bot Setup](#discord-bot-setup)
8. [AI Provider Configuration](#ai-provider-configuration)
9. [Security Configuration](#security-configuration)
10. [Performance Tuning](#performance-tuning)
11. [Running the Application](#running-the-application)
12. [Verification](#verification)
13. [Troubleshooting](#troubleshooting)
14. [Upgrading](#upgrading)
15. [Docker Deployment](#docker-deployment)

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores
- **RAM**: 2GB
- **Disk**: 10GB SSD
- **Network**: Stable internet connection
- **Operating System**: Ubuntu 20.04+, Debian 11+, CentOS 8+, or Windows 10/11 with WSL2

### Recommended Requirements

- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Disk**: 20GB+ SSD
- **Network**: High-speed internet connection
- **Operating System**: Ubuntu 22.04 LTS or Debian 12

## Prerequisites

Before installing the Discord AI Moderator, ensure you have the following prerequisites:

1. **Node.js**: Version 18.x or higher
   ```bash
   # Using NVM (recommended)
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
   source ~/.bashrc
   nvm install 18
   nvm use 18
   
   # Or using package manager
   # Ubuntu/Debian
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **npm**: Version 8.x or higher (comes with Node.js)
   ```bash
   npm install -g npm@latest
   ```

3. **Git**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install git
   
   # CentOS
   sudo yum install git
   ```

4. **SQLite** (for development) or **PostgreSQL** (for production):
   ```bash
   # SQLite (Ubuntu/Debian)
   sudo apt-get install sqlite3
   
   # PostgreSQL (Ubuntu/Debian)
   sudo apt-get install postgresql postgresql-contrib
   ```

5. **Redis** (for caching and session management):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install redis-server
   sudo systemctl enable redis-server
   sudo systemctl start redis-server
   ```

6. **Python** (for some AI providers):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3 python3-pip
   ```

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/discord-ai-moderator.git
cd discord-ai-moderator
```

### Install Dependencies

```bash
npm install
```

### Build the Application

```bash
npm run build
```

## Configuration

The Discord AI Moderator uses environment variables for configuration. Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Edit the `.env` file with your preferred text editor:

```bash
nano .env
```

### Basic Configuration

```env
# Application Settings
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# Discord Bot Token
DISCORD_TOKEN=your_discord_bot_token

# Database Configuration
DB_TYPE=sqlite
DB_PATH=./data/database.sqlite
# For PostgreSQL
# DB_TYPE=postgres
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=discord_ai_mod
# DB_USER=username
# DB_PASSWORD=password

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_PREFIX=discord_ai_mod:
```

### Advanced Configuration

```env
# Worker Thread Pool Configuration
WORKER_THREAD_POOL_SIZE=4
WORKER_THREAD_POOL_MIN_SIZE=2
WORKER_THREAD_POOL_MAX_SIZE=8
WORKER_THREAD_IDLE_TIMEOUT=60000

# Tiered Cache Configuration
ENABLE_TIERED_CACHE=true
L1_CACHE_CAPACITY=1000
L2_CACHE_TTL=300000
L1_WRITE_POLICY=write-through
L1_WRITE_BACK_INTERVAL=60000
CACHE_STATS_INTERVAL=300000

# Adaptive Query Optimizer Configuration
ENABLE_ADAPTIVE_QUERY_OPTIMIZER=true
MAX_CONCURRENT_QUERIES=50
QUERY_MONITORING_INTERVAL=5000
ENABLE_QUERY_REWRITING=true
ENABLE_ADAPTIVE_INDEXING=false
MAX_QUERY_QUEUE_SIZE=1000
QUERY_STATISTICS_RETENTION=3600000

# Security Configuration
SESSION_SECRET=your_secure_random_string
ENABLE_CSP=true
CSP_REPORT_URI=/api/csp-report
CSP_REPORT_ONLY=false
ENABLE_IP_REPUTATION=true
IP_REPUTATION_SUSPICIOUS_THRESHOLD=-10
IP_REPUTATION_MALICIOUS_THRESHOLD=-50
IP_REPUTATION_RESET_INTERVAL=86400000
SESSION_MAX_AGE=3600000
SESSION_ROTATION_INTERVAL=1800000
SESSION_STORE=redis

# AI Provider Configuration
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4
```

## Database Setup

### SQLite (Development)

SQLite is the default database for development. The database file will be created automatically at the path specified in the `DB_PATH` environment variable.

### PostgreSQL (Production)

For production environments, PostgreSQL is recommended:

1. Create a PostgreSQL database and user:

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE discord_ai_mod;
CREATE USER discord_ai_mod_user WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE discord_ai_mod TO discord_ai_mod_user;
\q
```

2. Update your `.env` file with PostgreSQL configuration:

```env
DB_TYPE=postgres
DB_HOST=localhost
DB_PORT=5432
DB_NAME=discord_ai_mod
DB_USER=discord_ai_mod_user
DB_PASSWORD=your_password
```

3. Run database migrations:

```bash
npm run migrate
```

## Redis Setup

Redis is used for caching, session management, and message queuing. Ensure Redis is running and accessible:

1. Verify Redis is running:

```bash
redis-cli ping
```

Should return `PONG`.

2. Configure Redis in your `.env` file:

```env
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_PREFIX=discord_ai_mod:
```

3. For production, secure your Redis instance:

```bash
sudo nano /etc/redis/redis.conf
```

Update the following settings:

```
bind 127.0.0.1
requirepass your_secure_redis_password
```

Restart Redis:

```bash
sudo systemctl restart redis-server
```

## Discord Bot Setup

1. Create a Discord application at [Discord Developer Portal](https://discord.com/developers/applications)

2. Create a bot for your application:
   - Go to the "Bot" tab
   - Click "Add Bot"
   - Enable "Privileged Gateway Intents" (SERVER MEMBERS INTENT, MESSAGE CONTENT INTENT)

3. Get your bot token:
   - Under the "Bot" tab, click "Reset Token" or copy your existing token
   - Add this token to your `.env` file as `DISCORD_TOKEN`

4. Invite the bot to your server:
   - Go to the "OAuth2" tab
   - Select "bot" under "SCOPES"
   - Select the required permissions (Administrator is easiest for full functionality)
   - Copy the generated URL and open it in your browser
   - Select your server and authorize the bot

## AI Provider Configuration

The Discord AI Moderator supports multiple AI providers. See [AI_PROVIDER_GUIDE.md](AI_PROVIDER_GUIDE.md) for detailed configuration instructions.

### OpenAI Configuration

```env
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.7
OPENAI_MAX_TOKENS=2048
```

### Azure OpenAI Configuration

```env
AI_PROVIDER=azure
AZURE_OPENAI_API_KEY=your_azure_openai_api_key
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=your_deployment_name
AZURE_OPENAI_API_VERSION=2023-05-15
```

### Anthropic Configuration

```env
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-2
ANTHROPIC_MAX_TOKENS=2048
```

## Security Configuration

### Session Secret

Generate a secure random string for your session secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Add this to your `.env` file:

```env
SESSION_SECRET=generated_secure_random_string
```

### Content Security Policy

Configure CSP settings:

```env
ENABLE_CSP=true
CSP_REPORT_URI=/api/csp-report
CSP_REPORT_ONLY=false
```

### IP Reputation Tracking

Configure IP reputation tracking:

```env
ENABLE_IP_REPUTATION=true
IP_REPUTATION_SUSPICIOUS_THRESHOLD=-10
IP_REPUTATION_MALICIOUS_THRESHOLD=-50
IP_REPUTATION_RESET_INTERVAL=86400000
```

### Session Management

Configure session management:

```env
SESSION_MAX_AGE=3600000
SESSION_ROTATION_INTERVAL=1800000
SESSION_STORE=redis
```

## Performance Tuning

### Worker Thread Pool

Configure the worker thread pool based on your system's CPU cores:

```env
WORKER_THREAD_POOL_SIZE=4  # Set to number of CPU cores
WORKER_THREAD_POOL_MIN_SIZE=2
WORKER_THREAD_POOL_MAX_SIZE=8  # Set to 2x number of CPU cores
WORKER_THREAD_IDLE_TIMEOUT=60000
```

### Tiered Cache

Configure the tiered cache based on your system's memory:

```env
ENABLE_TIERED_CACHE=true
L1_CACHE_CAPACITY=1000  # Increase for systems with more RAM
L2_CACHE_TTL=300000
L1_WRITE_POLICY=write-through
L1_WRITE_BACK_INTERVAL=60000
CACHE_STATS_INTERVAL=300000
```

### Adaptive Query Optimizer

Configure the adaptive query optimizer:

```env
ENABLE_ADAPTIVE_QUERY_OPTIMIZER=true
MAX_CONCURRENT_QUERIES=50
QUERY_MONITORING_INTERVAL=5000
ENABLE_QUERY_REWRITING=true
ENABLE_ADAPTIVE_INDEXING=false
MAX_QUERY_QUEUE_SIZE=1000
QUERY_STATISTICS_RETENTION=3600000
```

## Running the Application

### Development Mode

```bash
npm run dev
```

### Production Mode

```bash
npm run build
npm start
```

### Using PM2 (Recommended for Production)

```bash
# Install PM2
npm install -g pm2

# Start the application
pm2 start ecosystem.config.js

# Ensure PM2 starts on system boot
pm2 startup
pm2 save
```

## Verification

After starting the application, verify it's working correctly:

1. Check the logs for any errors:

```bash
# If running directly
npm start

# If using PM2
pm2 logs discord-ai-moderator
```

2. Verify the bot is online in your Discord server

3. Test basic commands:
   - Type `!help` in a channel where the bot has access
   - The bot should respond with a list of available commands

4. Test moderation features:
   - Type a message that would trigger moderation
   - The bot should analyze and respond appropriately

## Troubleshooting

### Bot Not Connecting to Discord

1. Verify your Discord token is correct
2. Ensure you've enabled the required intents in the Discord Developer Portal
3. Check your internet connection
4. Look for any errors in the application logs

### Database Connection Issues

1. Verify database credentials in your `.env` file
2. Ensure the database server is running
3. Check if the database and user exist with correct permissions
4. For PostgreSQL, verify the pg_hba.conf file allows connections

### Redis Connection Issues

1. Verify Redis is running: `redis-cli ping`
2. Check Redis credentials in your `.env` file
3. Ensure Redis is listening on the configured host and port

### Performance Issues

1. Check system resources (CPU, memory, disk I/O)
2. Adjust worker thread pool size based on CPU cores
3. Adjust cache settings based on available memory
4. Consider upgrading your server if resources are consistently maxed out

### Run Diagnostics

The application includes a diagnostic script:

```bash
npm run diagnostics
```

This will check:
- Node.js version
- Database connectivity
- Redis connectivity
- Discord API connectivity
- AI provider connectivity
- System resources

## Upgrading

To upgrade to a new version:

1. Backup your data:

```bash
# Backup SQLite database
cp ./data/database.sqlite ./data/database.sqlite.backup

# Backup PostgreSQL database
pg_dump -U discord_ai_mod_user discord_ai_mod > discord_ai_mod_backup.sql

# Backup .env file
cp .env .env.backup
```

2. Pull the latest changes:

```bash
git pull origin main
```

3. Install dependencies:

```bash
npm install
```

4. Run migrations:

```bash
npm run migrate
```

5. Restart the application:

```bash
# If running directly
npm restart

# If using PM2
pm2 restart discord-ai-moderator
```

## Docker Deployment

The Discord AI Moderator can be deployed using Docker:

1. Build the Docker image:

```bash
docker build -t discord-ai-moderator .
```

2. Create a `.env` file as described in the Configuration section

3. Run the container:

```bash
docker run -d \
  --name discord-ai-moderator \
  --env-file .env \
  -v $(pwd)/data:/app/data \
  discord-ai-moderator
```

4. For Docker Compose deployment, create a `docker-compose.yml` file:

```yaml
version: '3'

services:
  app:
    build: .
    restart: always
    env_file: .env
    volumes:
      - ./data:/app/data
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:14
    restart: always
    environment:
      POSTGRES_DB: discord_ai_mod
      POSTGRES_USER: discord_ai_mod_user
      POSTGRES_PASSWORD: your_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    restart: always
    command: redis-server --requirepass your_redis_password
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

5. Start the Docker Compose deployment:

```bash
docker-compose up -d
```

## Additional Resources

- [README.md](README.md): Overview and features
- [CHANGELOG.md](CHANGELOG.md): Version history and changes
- [AI_PROVIDER_GUIDE.md](AI_PROVIDER_GUIDE.md): Detailed AI provider configuration
- [docs/TECHNICAL.md](docs/TECHNICAL.md): Technical documentation
- [docs/WORKER_THREAD_POOL.md](docs/WORKER_THREAD_POOL.md): Worker thread pool documentation
- [docs/TIERED_CACHE.md](docs/TIERED_CACHE.md): Tiered cache documentation
- [docs/ADAPTIVE_QUERY_OPTIMIZER.md](docs/ADAPTIVE_QUERY_OPTIMIZER.md): Adaptive query optimizer documentation
- [docs/SECURITY_FEATURES.md](docs/SECURITY_FEATURES.md): Security features documentation

## Support

If you encounter any issues or need assistance, please:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [documentation](docs/)
3. Open an issue on GitHub
4. Join our Discord support server: [Discord Invite Link]

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
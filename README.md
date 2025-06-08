# Discord AI Moderator

An advanced Discord bot that uses artificial intelligence to moderate server content with enterprise-grade performance, security, and reliability features.

![Discord AI Moderator](https://example.com/discord-ai-mod-banner.png)

## Features

### Core Functionality

- **AI-Powered Moderation**: Automatically detect and handle inappropriate content using advanced AI models
- **Multi-Provider Support**: Compatible with OpenAI, Azure OpenAI, Anthropic, Google Vertex AI, Hugging Face, and local models
- **Custom Rules**: Create server-specific moderation rules and policies
- **User Management**: Track user behavior, issue warnings, timeouts, and bans
- **Logging**: Comprehensive logging of all moderation actions and events
- **Dashboard**: Web interface for configuration and monitoring
- **Analytics**: Insights into server activity and moderation effectiveness

### Enterprise-Grade Enhancements

#### Performance Optimization

- **Tiered Caching System**: Two-level (L1/L2) caching architecture for optimal performance
  - Memory-based L1 cache with LRU eviction
  - Persistent L2 cache with TTL expiration
  - Configurable write policies (write-through and write-back)
  - Comprehensive cache statistics and monitoring

- **Worker Thread Pool**: Adaptive thread pool for CPU-intensive operations
  - Dynamic scaling based on system load
  - Priority-based task queuing
  - Specialized worker tasks for different operations
  - Performance metrics and monitoring

- **Adaptive Query Optimization**: Intelligent database query handling
  - Load-aware query execution
  - Query classification and prioritization
  - Execution plan caching
  - Dynamic batch sizing for bulk operations
  - Performance metrics collection

#### Security Features

- **Content Security Policy (CSP)**: Protection against XSS and other injection attacks
  - Nonce-based validation for inline scripts
  - Strict content source restrictions
  - Violation reporting and monitoring

- **IP Reputation Tracking**: Advanced protection against malicious actors
  - Behavior-based reputation scoring
  - Dynamic rate limiting based on reputation
  - Automatic recovery for legitimate users
  - Comprehensive security metrics

- **Secure Session Management**: Protection against session-based attacks
  - Client fingerprinting to detect session hijacking
  - Automatic session rotation
  - Secure cookie handling
  - Comprehensive session monitoring

#### Reliability Features

- **Graceful Error Handling**: Robust error recovery mechanisms
  - Automatic retry with exponential backoff
  - Fallback strategies for critical operations
  - Comprehensive error logging and monitoring

- **Health Monitoring**: Proactive system health checks
  - Resource utilization monitoring
  - Performance metrics collection
  - Automatic alerting for anomalies
  - Self-healing capabilities

## Getting Started

### Prerequisites

- Node.js 18.x or higher
- npm 8.x or higher
- Discord Bot Token
- AI Provider API Key (OpenAI, Azure, Anthropic, etc.)
- Database (SQLite for development, PostgreSQL for production)
- Redis (for caching and session management)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/discord-ai-moderator.git
   cd discord-ai-moderator
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file based on `.env.example`:
   ```bash
   cp .env.example .env
   ```

4. Edit the `.env` file with your configuration.

5. Run the application:
   ```bash
   npm start
   ```

For detailed installation instructions, see [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md).

### Docker Deployment

The application can be easily deployed using Docker:

1. Using Docker Compose (recommended):
   ```bash
   # Start all services
   docker-compose up -d
   
   # View logs
   docker-compose logs -f
   
   # Stop all services
   docker-compose down
   ```

2. Using Docker Run:
   ```bash
   # Build the image
   docker build -t discord-ai-moderator .
   
   # Run the container
   docker run -d --name discord-ai-moderator --env-file .env -p 3000:3000 -p 8080:8080 -v $(pwd)/data:/app/data discord-ai-moderator
   ```

The Docker deployment includes:
- Non-root user for security
- Health checks for all services
- Resource limits and monitoring
- Volume mounts for persistent data
- Support for MongoDB, PostgreSQL, and Redis

For detailed Docker deployment instructions, see [INSTALLATION_GUIDE.md#docker-deployment](INSTALLATION_GUIDE.md#docker-deployment).

## Configuration

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

# AI Provider
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4
```

### Advanced Configuration

For detailed configuration options, see:
- [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) - Complete setup instructions
- [AI_PROVIDER_GUIDE.md](AI_PROVIDER_GUIDE.md) - AI provider configuration
- [docs/TIERED_CACHE.md](docs/TIERED_CACHE.md) - Tiered cache configuration
- [docs/WORKER_THREAD_POOL.md](docs/WORKER_THREAD_POOL.md) - Worker thread pool configuration
- [docs/ADAPTIVE_QUERY_OPTIMIZER.md](docs/ADAPTIVE_QUERY_OPTIMIZER.md) - Query optimizer configuration
- [docs/SECURITY_FEATURES.md](docs/SECURITY_FEATURES.md) - Security features configuration

## Architecture

The Discord AI Moderator is built with a modular architecture designed for performance, security, and extensibility:

### Core Components

- **Discord Integration**: Handles Discord API interactions using Discord.js
- **AI Service**: Manages AI provider interactions with unified API
- **Database Layer**: Handles data persistence with caching and optimization
- **Web Dashboard**: Provides configuration and monitoring interface
- **API Layer**: Exposes RESTful API for external integrations

### Performance Components

- **Tiered Cache**: Manages multi-level caching for optimal performance
- **Worker Thread Pool**: Handles CPU-intensive tasks in separate threads
- **Adaptive Query Optimizer**: Optimizes database queries based on load
- **Performance Monitor**: Tracks system performance metrics

### Security Components

- **Security Middleware**: Implements security headers and protections
- **IP Reputation Tracker**: Monitors and manages client reputation
- **Session Manager**: Handles secure session management
- **Audit Logger**: Records security-relevant events

## Usage

### Bot Commands

- `!help` - Display help information
- `!config` - Configure server-specific settings
- `!stats` - Show moderation statistics
- `!warn <user> <reason>` - Warn a user
- `!timeout <user> <duration> <reason>` - Timeout a user
- `!ban <user> <reason>` - Ban a user
- `!logs` - Show recent moderation logs

### Web Dashboard

The web dashboard is available at `http://your-server:3000` and provides:

- Server configuration
- Moderation rules management
- User management
- Moderation logs and analytics
- System performance monitoring
- Security monitoring

## Performance Optimization

### Tiered Caching

The tiered caching system significantly improves performance by reducing database load:

```javascript
// Example usage
const configCache = new TieredCache({
  namespace: 'server-config',
  l1Capacity: 500,
  l2TTL: 3600000,
  l1WritePolicy: 'write-through'
});

// Get server configuration with caching
async function getServerConfig(serverId) {
  const cacheKey = `config:${serverId}`;
  
  // Try cache first
  const cached = configCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Get from database
  const config = await db.getServerConfig(serverId);
  
  // Cache the result
  configCache.set(cacheKey, config);
  
  return config;
}
```

### Worker Thread Pool

The worker thread pool handles CPU-intensive tasks without blocking the main thread:

```javascript
// Example usage
const result = await workerManager.executeTask({
  type: 'content-analysis',
  data: {
    content: messageContent,
    userId: message.author.id,
    serverId: message.guild.id
  },
  priority: 'high'
});
```

### Adaptive Query Optimization

The adaptive query optimizer improves database performance under varying load:

```javascript
// Example usage
const messages = await queryOptimizer.executeQuery({
  sql: 'SELECT * FROM messages WHERE server_id = ? ORDER BY timestamp DESC LIMIT ?',
  params: [serverId, limit],
  type: 'read',
  priority: 'medium'
});
```

## Security Features

### Content Security Policy

The CSP implementation protects against XSS and other injection attacks:

```javascript
// Example CSP header
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'; style-src 'self' 'nonce-random123'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'
```

### IP Reputation Tracking

The IP reputation system protects against malicious actors:

```javascript
// Example reputation update
reputationTracker.updateReputation(ip, 'failed-login', -1);
```

### Secure Session Management

The session management system protects against session-based attacks:

```javascript
// Example session rotation
rotateSession(req, res, (err) => {
  if (err) {
    return res.status(500).json({ error: 'Authentication failed' });
  }
  
  req.session.authenticated = true;
  req.session.userId = user.id;
});
```

## Health Monitoring

The application includes comprehensive health monitoring:

```bash
# Run health check
npm run healthcheck
```

The health check verifies:
- Application status
- Database connectivity
- Redis connectivity
- System resources
- Worker thread pool status
- Cache performance

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Discord.js](https://discord.js.org/) - Discord API library
- [OpenAI](https://openai.com/) - AI provider
- [Anthropic](https://www.anthropic.com/) - AI provider
- [Express](https://expressjs.com/) - Web framework
- [SQLite](https://www.sqlite.org/) - Database
- [PostgreSQL](https://www.postgresql.org/) - Database
- [Redis](https://redis.io/) - Cache and session store

## Support

If you need help with the Discord AI Moderator, please:

1. Check the documentation
2. Open an issue on GitHub
3. Join our Discord support server: [Discord Invite Link]

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes in each version.

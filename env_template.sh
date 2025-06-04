# =====================================================
# Discord AI Moderator - Environment Configuration
# =====================================================

# =====================================================
# CORE DISCORD CONFIGURATION
# =====================================================

# Discord bot token (required)
DISCORD_BOT_TOKEN=your_discord_bot_token_here

# Discord bot user ID (for system permissions)
DISCORD_BOT_USER_ID=your_bot_user_id_here

# Discord application ID
DISCORD_APPLICATION_ID=your_application_id_here

# =====================================================
# AI PROVIDER CONFIGURATION
# =====================================================

# AI Provider: ANTHROPIC or OPENROUTER (default: OPENROUTER)
AI_PROVIDER=OPENROUTER

# Anthropic API Configuration (if AI_PROVIDER=ANTHROPIC)
ANTHROPIC_API_KEY=sk-ant-your_anthropic_api_key_here

# OpenRouter API Configuration (if AI_PROVIDER=OPENROUTER)
OPENROUTER_API_KEY=sk-or-v1-your_openrouter_api_key_here
OPENROUTER_SITE_URL=https://github.com/yourusername/discord-ai-moderator
OPENROUTER_APP_NAME=Discord AI Moderator

# Model Configuration
LOW_RISK_MODEL=anthropic/claude-3-haiku:beta
MEDIUM_RISK_MODEL=anthropic/claude-3-sonnet:beta
HIGH_RISK_MODEL=anthropic/claude-3-opus:beta
MAX_TOKENS=300

# AI Cost Management
MAX_DAILY_SPEND=100.00
ALERT_THRESHOLD=50.00

# =====================================================
# DATABASE CONFIGURATION
# =====================================================

# Database Type: MONGODB or SQLITE (default: MONGODB)
DB_TYPE=MONGODB

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/discord-ai-moderator
MONGODB_SSL=false
MONGODB_SSL_VALIDATE=true
MONGODB_CA_CERT=/path/to/ca-cert.pem

# =====================================================
# REDIS CONFIGURATION
# =====================================================

# Redis URL for caching and session management
REDIS_URL=redis://localhost:6379

# Redis SSL Configuration
REDIS_SSL=false
REDIS_SSL_CERT=/path/to/redis-cert.pem

# =====================================================
# SECURITY & ENCRYPTION
# =====================================================

# JWT Secret (required - generate with: openssl rand -hex 32)
JWT_SECRET=your_jwt_secret_key_here_minimum_32_chars

# Encryption Key (required - generate with: openssl rand -hex 32)
ENCRYPTION_KEY=your_encryption_key_here_64_hex_chars

# Session Configuration
SESSION_TIMEOUT=86400000
SESSION_CLEANUP_INTERVAL=3600000
SESSION_ENCRYPTION_KEY=your_session_encryption_key_here

# Audit Logging
AUDIT_SECRET_KEY=your_audit_secret_key_here
AUDIT_FILE_LOGGING=true
AUDIT_DB_LOGGING=true
AUDIT_RETENTION_DAYS=90

# =====================================================
# WEB DASHBOARD CONFIGURATION
# =====================================================

# Enable web dashboard
DASHBOARD_ENABLED=true
DASHBOARD_PORT=3000
DASHBOARD_HOST=127.0.0.1

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# Server Timeouts
SERVER_TIMEOUT=30000
KEEP_ALIVE_TIMEOUT=65000
HEADERS_TIMEOUT=66000
MAX_CONNECTIONS=1000
SHUTDOWN_TIMEOUT=10000

# =====================================================
# PRIVACY & GDPR COMPLIANCE
# =====================================================

# Data Retention
DATA_RETENTION_DAYS=365
LOG_RETENTION_DAYS=90
ANONYMIZATION_ENABLED=true

# Privacy Request Processing
AUTO_PROCESS_REQUESTS=false
REQUEST_EXPIRY_DAYS=30

# =====================================================
# SECURITY MONITORING
# =====================================================

# Security Monitoring
ENABLE_REAL_TIME_MONITORING=true
ENABLE_ANOMALY_DETECTION=true
ENABLE_THREAT_DETECTION=true
SECURITY_ALERT_THRESHOLD=0.7
MONITORING_INTERVAL=30000
SECURITY_WS_PORT=8080

# Health Checks
HEALTH_CHECK_INTERVAL=60000
HEALTH_REPORT_INTERVAL=3600000
ENABLE_DEGRADED_MODE=true
MAX_COMPONENT_FAILURES=5

# =====================================================
# PERFORMANCE OPTIMIZATION
# =====================================================

# Clustering
ENABLE_CLUSTERING=false
WORKER_COUNT=4

# Caching
ENABLE_CACHING=true
CACHE_SIZE=100
ENABLE_COMPRESSION=true

# Memory Management
MAX_MEMORY_USAGE=512
ENABLE_CONNECTION_POOLING=true

# =====================================================
# RATE LIMITING & DDOS PROTECTION
# =====================================================

# Rate Limiting
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX=100
RATE_LIMIT_SKIP_SUCCESSFUL=false

# DDoS Protection
DDOS_THRESHOLD=1000
DDOS_BLOCK_DURATION=7200000
DDOS_SUSPICION_THRESHOLD=0.7

# Pattern Detection
PATTERN_DETECTION_ENABLED=true
PATTERN_ANALYSIS_WINDOW=300000
PATTERN_MINIMUM_REQUESTS=10

# =====================================================
# EXTERNAL INTEGRATIONS
# =====================================================

# Cloudflare (for DDoS protection)
CLOUDFLARE_API_KEY=your_cloudflare_api_key
CLOUDFLARE_ZONE_ID=your_cloudflare_zone_id
CLOUDFLARE_EMAIL=your_cloudflare_email

# Emergency Notifications
EMERGENCY_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
SECURITY_WEBHOOK_URL=https://hooks.slack.com/services/your/security/webhook

# Email Notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=noreply@yourdomain.com

# =====================================================
# DEVELOPMENT & DEBUGGING
# =====================================================

# Environment
NODE_ENV=production

# Logging
LOG_LEVEL=info
LOG_FILE=logs/discord-ai-moderator.log
LOG_MAX_SIZE=100MB
LOG_MAX_FILES=10

# Debug Settings
DEBUG_SQL=false
DEBUG_REDIS=false
DEBUG_SECURITY=false

# =====================================================
# OPTIONAL FEATURES
# =====================================================

# Advanced Analytics
ENABLE_ANALYTICS=true
ANALYTICS_RETENTION_DAYS=30

# Machine Learning
ENABLE_ML_FEATURES=true
ML_MODEL_UPDATE_INTERVAL=86400000

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_INTERVAL=86400000
BACKUP_RETENTION_DAYS=30
BACKUP_ENCRYPTION=true

# =====================================================
# TESTING & DEVELOPMENT
# =====================================================

# Test Database (for running tests)
TEST_MONGODB_URI=mongodb://localhost:27017/discord-ai-moderator-test
TEST_REDIS_URL=redis://localhost:6379/1

# Development API Keys (use separate keys for dev)
DEV_ANTHROPIC_API_KEY=sk-ant-dev_key_here
DEV_OPENROUTER_API_KEY=sk-or-v1-dev_key_here

# =====================================================
# DOCKER CONFIGURATION
# =====================================================

# Docker-specific settings
DOCKER_INTERNAL_PORT=3000
DOCKER_TIMEZONE=UTC
DOCKER_USER_ID=1000
DOCKER_GROUP_ID=1000

# Volume Mounts
DATA_VOLUME=/app/data
LOGS_VOLUME=/app/logs
CONFIG_VOLUME=/app/config

# =====================================================
# INSTANCE IDENTIFICATION
# =====================================================

# Instance ID (auto-generated if not set)
INSTANCE_ID=auto

# Server Name/Environment
SERVER_NAME=production-1
ENVIRONMENT=production
REGION=us-east-1

# =====================================================
# MAINTENANCE & OPERATIONS
# =====================================================

# Maintenance Mode
MAINTENANCE_MODE=false
MAINTENANCE_MESSAGE=System is under maintenance

# Feature Flags
FEATURE_FLAG_NEW_UI=false
FEATURE_FLAG_BETA_FEATURES=false
FEATURE_FLAG_EXPERIMENTAL=false

# =====================================================
# COMPLIANCE & LEGAL
# =====================================================

# Legal Compliance
ENABLE_GDPR_COMPLIANCE=true
ENABLE_CCPA_COMPLIANCE=true
DATA_PROCESSING_LEGAL_BASIS=legitimate_interest

# Terms of Service & Privacy Policy URLs
TERMS_OF_SERVICE_URL=https://yourdomain.com/terms
PRIVACY_POLICY_URL=https://yourdomain.com/privacy

# Data Protection Officer Contact
DPO_EMAIL=dpo@yourdomain.com
DPO_NAME=Data Protection Officer

# =====================================================
# NOTES
# =====================================================

# 1. Generate secure keys using: openssl rand -hex 32
# 2. Never commit this file with real values to version control
# 3. Use different keys for development and production
# 4. Regularly rotate encryption keys and API tokens
# 5. Monitor logs for any security warnings
# 6. Keep dependencies updated for security patches
# 7. Review and audit permissions regularly

# =====================================================
# EXAMPLE SECURE KEY GENERATION COMMANDS
# =====================================================

# Generate JWT Secret:
# openssl rand -base64 32

# Generate Encryption Key:
# openssl rand -hex 32

# Generate Session Secret:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate Audit Secret:
# openssl rand -hex 32
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

# AI Provider: OPENAI, AZURE, ANTHROPIC, GOOGLE, HUGGINGFACE, LOCAL, or CUSTOM
AI_PROVIDER=OPENAI

# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_ORGANIZATION=your_organization_id_here
OPENAI_TEMPERATURE=0.7
OPENAI_MAX_TOKENS=2048
OPENAI_TOP_P=1
OPENAI_FREQUENCY_PENALTY=0
OPENAI_PRESENCE_PENALTY=0

# Azure OpenAI Configuration
AZURE_OPENAI_API_KEY=your_azure_openai_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=your_deployment_name_here
AZURE_OPENAI_API_VERSION=2023-05-15
AZURE_OPENAI_TEMPERATURE=0.7
AZURE_OPENAI_MAX_TOKENS=2048

# Anthropic Configuration
ANTHROPIC_API_KEY=sk-ant-your_anthropic_api_key_here
ANTHROPIC_MODEL=claude-3-sonnet
ANTHROPIC_MAX_TOKENS=2048
ANTHROPIC_TEMPERATURE=0.7
ANTHROPIC_TOP_P=1
ANTHROPIC_TOP_K=0

# Google Vertex AI Configuration
GOOGLE_PROJECT_ID=your_google_project_id_here
GOOGLE_LOCATION=us-central1
GOOGLE_MODEL=gemini-pro
GOOGLE_CREDENTIALS_JSON=path/to/credentials.json
GOOGLE_TEMPERATURE=0.7
GOOGLE_MAX_TOKENS=2048
GOOGLE_TOP_P=1
GOOGLE_TOP_K=40

# Hugging Face Configuration
HUGGINGFACE_API_KEY=your_huggingface_api_key_here
HUGGINGFACE_MODEL=mistralai/Mistral-7B-Instruct-v0.2
HUGGINGFACE_TEMPERATURE=0.7
HUGGINGFACE_MAX_TOKENS=2048
HUGGINGFACE_TOP_P=0.95
HUGGINGFACE_REPETITION_PENALTY=1.2

# Local Model Configuration
LOCAL_MODEL_ENDPOINT=http://localhost:11434/api/generate
LOCAL_MODEL_NAME=llama2
LOCAL_MODEL_TEMPERATURE=0.7
LOCAL_MODEL_MAX_TOKENS=2048
LOCAL_MODEL_TOP_P=0.95
LOCAL_MODEL_REPETITION_PENALTY=1.1

# Custom Provider Configuration
CUSTOM_API_KEY=your_custom_api_key_here
CUSTOM_ENDPOINT=https://your-custom-endpoint.com/api
CUSTOM_MODEL=your-model-name
CUSTOM_TEMPERATURE=0.7
CUSTOM_MAX_TOKENS=2048

# AI Provider Fallback
AI_FALLBACK_PROVIDER=ANTHROPIC
AI_FALLBACK_THRESHOLD=3

# AI Request Configuration
AI_TIMEOUT=30000
AI_RETRY_COUNT=3
AI_RETRY_DELAY=1000
AI_CACHE_ENABLED=true
AI_CACHE_TTL=3600000
AI_MAX_CONCURRENT_REQUESTS=5
AI_RATE_LIMIT_WINDOW=60000
AI_RATE_LIMIT_MAX_REQUESTS=60

# AI Cost Management
AI_BUDGET_LIMIT_DAILY=10
AI_BUDGET_LIMIT_MONTHLY=100

# =====================================================
# DATABASE CONFIGURATION
# =====================================================

# Database Type: MONGODB, POSTGRESQL, or SQLITE (default: MONGODB)
DB_TYPE=MONGODB

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/discord-ai-moderator
MONGODB_SSL=false
MONGODB_SSL_VALIDATE=true
MONGODB_CA_CERT=/path/to/ca-cert.pem

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=discord_ai_mod
POSTGRES_USER=discord_ai_mod_user
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_SSL=false
POSTGRES_SSL_CERT=/path/to/postgres-cert.pem
POSTGRES_CONNECTION_POOL_MIN=5
POSTGRES_CONNECTION_POOL_MAX=20

# SQLite Configuration
SQLITE_PATH=./data/database.sqlite

# =====================================================
# REDIS CONFIGURATION
# =====================================================

# Redis URL for caching and session management
REDIS_URL=redis://localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password_here
REDIS_PREFIX=discord_ai_mod:

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
SESSION_SECRET=your_session_secret_key_here
SESSION_MAX_AGE=3600000
SESSION_ROTATION_INTERVAL=1800000
SESSION_STORE=redis
SESSION_TIMEOUT=86400000
SESSION_CLEANUP_INTERVAL=3600000
SESSION_ENCRYPTION_KEY=your_session_encryption_key_here

# Content Security Policy
ENABLE_CSP=true
CSP_REPORT_URI=/api/csp-report
CSP_REPORT_ONLY=false

# IP Reputation Tracking
ENABLE_IP_REPUTATION=true
IP_REPUTATION_SUSPICIOUS_THRESHOLD=-10
IP_REPUTATION_MALICIOUS_THRESHOLD=-50
IP_REPUTATION_RESET_INTERVAL=86400000

# Audit Logging
AUDIT_SECRET_KEY=your_audit_secret_key_here
AUDIT_FILE_LOGGING=true
AUDIT_DB_LOGGING=true
AUDIT_RETENTION_DAYS=90

# =====================================================
# PERFORMANCE OPTIMIZATION
# =====================================================

# Worker Thread Pool
WORKER_THREAD_POOL_SIZE=4
WORKER_THREAD_POOL_MIN_SIZE=2
WORKER_THREAD_POOL_MAX_SIZE=8
WORKER_THREAD_IDLE_TIMEOUT=60000

# Tiered Cache
ENABLE_TIERED_CACHE=true
L1_CACHE_CAPACITY=1000
L2_CACHE_TTL=300000
L1_WRITE_POLICY=write-through
L1_WRITE_BACK_INTERVAL=60000
CACHE_STATS_INTERVAL=300000

# Adaptive Query Optimizer
ENABLE_ADAPTIVE_QUERY_OPTIMIZER=true
MAX_CONCURRENT_QUERIES=50
QUERY_MONITORING_INTERVAL=5000
ENABLE_QUERY_REWRITING=true
ENABLE_ADAPTIVE_INDEXING=false
MAX_QUERY_QUEUE_SIZE=1000
QUERY_STATISTICS_RETENTION=3600000

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
DEBUG_WORKER_THREADS=false
DEBUG_CACHE=false
DEBUG_QUERY_OPTIMIZER=false

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
TEST_POSTGRES_URI=postgresql://test_user:test_password@localhost:5432/discord_ai_mod_test

# Development API Keys (use separate keys for dev)
DEV_OPENAI_API_KEY=sk-dev_key_here
DEV_AZURE_OPENAI_API_KEY=azure_dev_key_here
DEV_ANTHROPIC_API_KEY=sk-ant-dev_key_here
DEV_GOOGLE_CREDENTIALS_JSON=path/to/dev-credentials.json
DEV_HUGGINGFACE_API_KEY=hf_dev_key_here

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
FEATURE_FLAG_TIERED_CACHE=true
FEATURE_FLAG_WORKER_THREADS=true
FEATURE_FLAG_ADAPTIVE_QUERY_OPTIMIZER=true
FEATURE_FLAG_ENHANCED_SECURITY=true

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
# 8. Configure worker thread pool size based on available CPU cores
# 9. Adjust cache settings based on available memory
# 10. Set appropriate rate limits based on expected traffic

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
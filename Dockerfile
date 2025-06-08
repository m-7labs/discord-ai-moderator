FROM node:18-alpine

# Set working directory
WORKDIR /app

# Add non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    curl \
    tini \
    tzdata

# Copy package files
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY --chown=appuser:appgroup . .

# Create necessary directories and set permissions
RUN mkdir -p data logs config && \
    chown -R appuser:appgroup data logs config

# Set environment variables
ENV NODE_ENV=production \
    WORKER_THREAD_POOL_SIZE=4 \
    ENABLE_TIERED_CACHE=true \
    ENABLE_ADAPTIVE_QUERY_OPTIMIZER=true

# Expose ports
EXPOSE 3000 8080

# Set healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node scripts/healthcheck.js

# Switch to non-root user
USER appuser

# Use tini as entrypoint for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start the application
CMD ["npm", "start"]
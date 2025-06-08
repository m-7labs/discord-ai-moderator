const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto');
const EventEmitter = require('events');
const logger = require('./logger');
const AuditLogger = require('./audit-logger');

/**
 * Smart Cache Implementation with LRU and TTL
 */
class SmartCache extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = {
      maxSize: options.maxSize || 512 * 1024 * 1024, // 512MB
      maxItems: options.maxItems || 10000,
      defaultTTL: options.defaultTTL || 300000, // 5 minutes
      enableMetrics: options.enableMetrics !== false,
      enableCompression: options.enableCompression !== false
    };

    this.cache = new Map();
    this.accessTimes = new Map();
    this.currentSize = 0;
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      evictions: 0,
      compressionSaved: 0
    };

    // Start cleanup interval
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000); // Every minute
  }

  /**
   * Get item from cache
   */
  async get(key) {
    const item = this.cache.get(key);

    if (!item) {
      this.stats.misses++;
      return null;
    }

    // Check if expired
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.delete(key);
      this.stats.misses++;
      return null;
    }

    // Update access time for LRU
    this.accessTimes.set(key, Date.now());
    this.stats.hits++;

    // Decompress if needed
    let value = item.value;
    if (item.compressed) {
      value = await this.decompress(value);
    }

    this.emit('hit', { key, size: item.size });
    return value;
  }

  /**
   * Set item in cache
   */
  async set(key, value, ttl = null) {
    const expiresAt = ttl ? Date.now() + ttl : (this.config.defaultTTL ? Date.now() + this.config.defaultTTL : null);

    // Serialize and compress value
    const serialized = JSON.stringify(value);
    let compressed = false;
    let finalValue = serialized;

    if (this.config.enableCompression && serialized.length > 1024) {
      const compressedValue = await this.compress(serialized);
      if (compressedValue.length < serialized.length * 0.8) {
        finalValue = compressedValue;
        compressed = true;
        this.stats.compressionSaved += serialized.length - compressedValue.length;
      }
    }

    const size = Buffer.byteLength(finalValue, 'utf8');

    // Check if we need to evict items
    await this.ensureSpace(size);

    // Remove existing item if present
    if (this.cache.has(key)) {
      const existingItem = this.cache.get(key);
      this.currentSize -= existingItem.size;
    }

    const item = {
      value: finalValue,
      size,
      compressed,
      createdAt: Date.now(),
      expiresAt,
      accessCount: 0
    };

    this.cache.set(key, item);
    this.accessTimes.set(key, Date.now());
    this.currentSize += size;
    this.stats.sets++;

    this.emit('set', { key, size, compressed });
  }

  /**
   * Delete item from cache
   */
  delete(key) {
    const item = this.cache.get(key);
    if (item) {
      this.cache.delete(key);
      this.accessTimes.delete(key);
      this.currentSize -= item.size;
      this.stats.deletes++;
      this.emit('delete', { key, size: item.size });
      return true;
    }
    return false;
  }

  /**
   * Ensure space for new item
   */
  async ensureSpace(requiredSize) {
    // Check size limit
    while (this.currentSize + requiredSize > this.config.maxSize || this.cache.size >= this.config.maxItems) {
      if (!this.evictLRU()) {
        break; // No more items to evict
      }
    }
  }

  /**
   * Evict least recently used item
   */
  evictLRU() {
    if (this.cache.size === 0) return false;

    let oldestKey = null;
    let oldestTime = Infinity;

    for (const [key, time] of this.accessTimes) {
      if (time < oldestTime) {
        oldestTime = time;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.delete(oldestKey);
      this.stats.evictions++;
      return true;
    }

    return false;
  }

  /**
   * Cleanup expired items
   */
  cleanup() {
    const now = Date.now();
    const expiredKeys = [];

    for (const [key, item] of this.cache) {
      if (item.expiresAt && now > item.expiresAt) {
        expiredKeys.push(key);
      }
    }

    for (const key of expiredKeys) {
      this.delete(key);
    }

    if (expiredKeys.length > 0) {
      logger.debug(`Cache cleanup: removed ${expiredKeys.length} expired items`);
    }
  }

  /**
   * Compress data
   */
  async compress(data) {
    const zlib = require('zlib');
    return new Promise((resolve, reject) => {
      zlib.gzip(data, (err, compressed) => {
        if (err) reject(err);
        else resolve(compressed);
      });
    });
  }

  /**
   * Decompress data
   */
  async decompress(data) {
    const zlib = require('zlib');
    return new Promise((resolve, reject) => {
      zlib.gunzip(data, (err, decompressed) => {
        if (err) reject(err);
        else resolve(JSON.parse(decompressed.toString()));
      });
    });
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const hitRate = this.stats.hits / (this.stats.hits + this.stats.misses) || 0;

    return {
      ...this.stats,
      hitRate,
      currentSize: this.currentSize,
      currentItems: this.cache.size,
      maxSize: this.config.maxSize,
      maxItems: this.config.maxItems,
      memoryUsage: {
        bytes: this.currentSize,
        mb: Math.round(this.currentSize / 1024 / 1024 * 100) / 100,
        percentage: (this.currentSize / this.config.maxSize) * 100
      }
    };
  }

  /**
   * Clear cache
   */
  clear() {
    this.cache.clear();
    this.accessTimes.clear();
    this.currentSize = 0;
    this.emit('clear');
  }

  /**
   * Shutdown cache
   */
  shutdown() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.clear();
  }
}

/**
 * Message Queue for async processing
 */
class MessageQueue extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = {
      maxSize: options.maxSize || 10000,
      processingDelay: options.processingDelay || 100,
      batchSize: options.batchSize || 50,
      retryAttempts: options.retryAttempts || 3,
      retryDelay: options.retryDelay || 1000
    };

    this.queues = {
      high: [],
      medium: [],
      low: []
    };

    this.processing = false;
    this.stats = {
      enqueued: 0,
      processed: 0,
      failed: 0,
      retries: 0
    };

    this.workers = new Map();
    this.startProcessing();
  }

  /**
   * Add message to queue
   */
  async enqueue(message, priority = 'medium') {
    if (!['high', 'medium', 'low'].includes(priority)) {
      throw new Error('Invalid priority. Must be high, medium, or low');
    }

    // eslint-disable-next-line security/detect-object-injection
    const queue = this.queues[priority];

    if (queue.length >= this.config.maxSize) {
      throw new Error(`Queue ${priority} is full`);
    }

    const queueItem = {
      id: crypto.randomUUID(),
      message,
      priority,
      attempts: 0,
      enqueuedAt: Date.now(),
      retryAfter: null
    };

    queue.push(queueItem);
    this.stats.enqueued++;

    this.emit('enqueued', { id: queueItem.id, priority });

    return queueItem.id;
  }

  /**
   * Start processing messages
   */
  startProcessing() {
    if (this.processing) return;

    this.processing = true;
    this.processMessages();
  }

  /**
   * Process messages from queues
   */
  async processMessages() {
    while (this.processing) {
      try {
        const batch = this.getBatch();

        if (batch.length === 0) {
          await this.delay(this.config.processingDelay);
          continue;
        }

        await this.processBatch(batch);

      } catch (error) {
        logger.error('Message queue processing error:', error);
        await this.delay(this.config.processingDelay);
      }
    }
  }

  /**
   * Get batch of messages to process
   */
  getBatch() {
    const batch = [];
    const now = Date.now();

    // Process high priority first
    for (const priority of ['high', 'medium', 'low']) {
      // eslint-disable-next-line security/detect-object-injection
      const queue = this.queues[priority];

      while (queue.length > 0 && batch.length < this.config.batchSize) {
        const item = queue[0];

        // Skip items that are waiting for retry
        if (item.retryAfter && now < item.retryAfter) {
          break;
        }

        batch.push(queue.shift());
      }

      if (batch.length >= this.config.batchSize) {
        break;
      }
    }

    return batch;
  }

  /**
   * Process batch of messages
   */
  async processBatch(batch) {
    const promises = batch.map(item => this.processMessage(item));
    await Promise.allSettled(promises);
  }

  /**
   * Process individual message
   */
  async processMessage(item) {
    try {
      item.attempts++;

      // Emit processing event
      this.emit('processing', { id: item.id, attempts: item.attempts });

      // Process the message (this would be implemented by consumers)
      await this.handleMessage(item.message);

      this.stats.processed++;
      this.emit('processed', { id: item.id, attempts: item.attempts });

    } catch (error) {
      logger.error(`Failed to process message ${item.id}:`, error);

      if (item.attempts < this.config.retryAttempts) {
        // Retry with exponential backoff
        item.retryAfter = Date.now() + (this.config.retryDelay * Math.pow(2, item.attempts - 1));

        // Put back in appropriate queue
        this.queues[item.priority].unshift(item);
        this.stats.retries++;

        this.emit('retry', {
          id: item.id,
          attempts: item.attempts,
          retryAfter: item.retryAfter
        });
      } else {
        this.stats.failed++;
        this.emit('failed', {
          id: item.id,
          attempts: item.attempts,
          error: error.message
        });
      }
    }
  }

  /**
   * Handle message (to be overridden by consumers)
   */
  async handleMessage(message) {
    // Default implementation - just log the message
    logger.debug('Processing message:', message);
  }

  /**
   * Stop processing
   */
  stopProcessing() {
    this.processing = false;
  }

  /**
   * Get queue statistics
   */
  getStats() {
    const totalQueued = Object.values(this.queues).reduce((sum, queue) => sum + queue.length, 0);

    return {
      ...this.stats,
      queued: {
        total: totalQueued,
        high: this.queues.high.length,
        medium: this.queues.medium.length,
        low: this.queues.low.length
      },
      processing: this.processing
    };
  }

  /**
   * Utility delay function
   */
  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Clear all queues
   */
  clear() {
    for (const queue of Object.values(this.queues)) {
      queue.length = 0;
    }
  }

  /**
   * Shutdown queue
   */
  shutdown() {
    this.stopProcessing();
    this.clear();
  }
}

/**
 * Connection Pool Manager
 */
class ConnectionPool {
  constructor(options = {}) {
    this.config = {
      maxConnections: options.maxConnections || 100,
      minConnections: options.minConnections || 10,
      acquireTimeout: options.acquireTimeout || 30000,
      idleTimeout: options.idleTimeout || 300000, // 5 minutes
      validateConnection: options.validateConnection || null
    };

    this.pool = [];
    this.activeConnections = new Set();
    this.waitingQueue = [];
    this.stats = {
      created: 0,
      acquired: 0,
      released: 0,
      destroyed: 0,
      timeouts: 0
    };

    this.initialized = false;
  }

  /**
   * Initialize connection pool
   */
  async initialize(connectionFactory) {
    if (this.initialized) return;

    this.connectionFactory = connectionFactory;

    // Create minimum connections
    for (let i = 0; i < this.config.minConnections; i++) {
      const connection = await this.createConnection();
      this.pool.push({
        connection,
        createdAt: Date.now(),
        lastUsed: Date.now(),
        inUse: false
      });
    }

    // Start maintenance
    this.startMaintenance();

    this.initialized = true;
    logger.info(`Connection pool initialized with ${this.pool.length} connections`);
  }

  /**
   * Acquire connection from pool
   */
  async acquire() {
    if (!this.initialized) {
      throw new Error('Connection pool not initialized');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.stats.timeouts++;
        reject(new Error('Connection acquire timeout'));
      }, this.config.acquireTimeout);

      this.waitingQueue.push({ resolve, reject, timeout });
      this.processWaitingQueue();
    });
  }

  /**
   * Release connection back to pool
   */
  async release(connection) {
    const poolItem = this.pool.find(item => item.connection === connection);

    if (poolItem) {
      poolItem.inUse = false;
      poolItem.lastUsed = Date.now();
      this.activeConnections.delete(connection);
      this.stats.released++;

      // Process waiting queue
      this.processWaitingQueue();
    }
  }

  /**
   * Process waiting queue
   */
  async processWaitingQueue() {
    while (this.waitingQueue.length > 0) {
      // Find available connection
      let availableItem = this.pool.find(item => !item.inUse);

      // Create new connection if needed and under limit
      if (!availableItem && this.pool.length < this.config.maxConnections) {
        try {
          const connection = await this.createConnection();
          availableItem = {
            connection,
            createdAt: Date.now(),
            lastUsed: Date.now(),
            inUse: false
          };
          this.pool.push(availableItem);
        } catch (error) {
          logger.error('Failed to create new connection:', error);
          break;
        }
      }

      if (!availableItem) {
        break; // No available connections
      }

      // Validate connection if validator provided
      if (this.config.validateConnection) {
        try {
          const isValid = await this.config.validateConnection(availableItem.connection);
          if (!isValid) {
            await this.destroyConnection(availableItem);
            continue;
          }
        } catch (error) {
          logger.error('Connection validation failed:', error);
          await this.destroyConnection(availableItem);
          continue;
        }
      }

      // Assign connection to waiting request
      const waiter = this.waitingQueue.shift();
      clearTimeout(waiter.timeout);

      availableItem.inUse = true;
      availableItem.lastUsed = Date.now();
      this.activeConnections.add(availableItem.connection);
      this.stats.acquired++;

      waiter.resolve(availableItem.connection);
    }
  }

  /**
   * Create new connection
   */
  async createConnection() {
    if (!this.connectionFactory) {
      throw new Error('Connection factory not provided');
    }

    const connection = await this.connectionFactory();
    this.stats.created++;
    return connection;
  }

  /**
   * Destroy connection
   */
  async destroyConnection(poolItem) {
    const index = this.pool.indexOf(poolItem);
    if (index > -1) {
      this.pool.splice(index, 1);
      this.activeConnections.delete(poolItem.connection);

      // Call destroy method if available
      if (poolItem.connection.destroy) {
        await poolItem.connection.destroy();
      } else if (poolItem.connection.close) {
        await poolItem.connection.close();
      } else if (poolItem.connection.end) {
        await poolItem.connection.end();
      }

      this.stats.destroyed++;
    }
  }

  /**
   * Start maintenance tasks
   */
  startMaintenance() {
    // Remove idle connections every 5 minutes
    this.maintenanceInterval = setInterval(async () => {
      await this.removeIdleConnections();
    }, 300000);
  }

  /**
   * Remove idle connections
   */
  async removeIdleConnections() {
    const now = Date.now();
    const itemsToDestroy = [];

    for (const item of this.pool) {
      if (!item.inUse &&
        now - item.lastUsed > this.config.idleTimeout &&
        this.pool.length > this.config.minConnections) {
        itemsToDestroy.push(item);
      }
    }

    for (const item of itemsToDestroy) {
      await this.destroyConnection(item);
    }

    if (itemsToDestroy.length > 0) {
      logger.debug(`Removed ${itemsToDestroy.length} idle connections`);
    }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    return {
      ...this.stats,
      pool: {
        total: this.pool.length,
        active: this.activeConnections.size,
        idle: this.pool.length - this.activeConnections.size,
        waiting: this.waitingQueue.length
      },
      config: this.config
    };
  }

  /**
   * Shutdown pool
   */
  async shutdown() {
    if (this.maintenanceInterval) {
      clearInterval(this.maintenanceInterval);
    }

    // Destroy all connections
    const destroyPromises = this.pool.map(item => this.destroyConnection(item));
    await Promise.allSettled(destroyPromises);

    // Clear waiting queue
    for (const waiter of this.waitingQueue) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error('Connection pool shutting down'));
    }
    this.waitingQueue.length = 0;

    this.initialized = false;
    logger.info('Connection pool shut down');
  }
}

/**
 * Enhanced Performance Optimizer
 */
class PerformanceOptimizer extends EventEmitter {
  constructor(options = {}) {
    super();

    this.config = {
      enableClustering: options.enableClustering !== false,
      enableCaching: options.enableCaching !== false,
      enableCompression: options.enableCompression !== false,
      enableConnectionPooling: options.enableConnectionPooling !== false,
      maxMemoryUsage: options.maxMemoryUsage || 512, // MB
      cacheSize: options.cacheSize || 100, // MB
      workerCount: options.workerCount || os.cpus().length,
      gracefulShutdownTimeout: options.gracefulShutdownTimeout || 30000
    };

    this.cache = null;
    this.messageQueue = null;
    this.connectionPool = null;
    this.workers = new Map();
    this.isClusterMaster = cluster.isMaster;
    this.metrics = {
      startTime: Date.now(),
      requestsProcessed: 0,
      cacheHits: 0,
      cacheMisses: 0,
      memoryPeak: 0,
      cpuUsage: []
    };

    this.monitoringInterval = null;
  }

  /**
   * Initialize clustering
   */
  async initializeCluster() {
    if (!this.config.enableClustering || !cluster.isMaster) {
      return;
    }

    logger.info(`Setting up cluster with ${this.config.workerCount} workers`);

    // Set up cluster settings
    cluster.setupMaster({
      exec: process.argv[1],
      args: process.argv.slice(2),
      silent: false
    });

    // Fork workers
    for (let i = 0; i < this.config.workerCount; i++) {
      const worker = cluster.fork();
      this.workers.set(worker.id, {
        worker,
        startTime: Date.now(),
        restarts: 0,
        memory: 0,
        cpu: 0
      });

      logger.info(`Worker ${worker.id} started with PID ${worker.process.pid}`);
    }

    // Handle worker events
    cluster.on('exit', (worker, code, signal) => {
      const workerInfo = this.workers.get(worker.id);

      logger.warn(`Worker ${worker.id} died (${signal || code}). Restarting...`);

      // Log worker death
      AuditLogger.logSystemEvent({
        type: 'WORKER_DIED',
        workerId: worker.id,
        code,
        signal,
        restarts: workerInfo ? workerInfo.restarts : 0,
        timestamp: Date.now()
      });

      // Remove from workers map
      this.workers.delete(worker.id);

      // Restart worker
      const newWorker = cluster.fork();
      this.workers.set(newWorker.id, {
        worker: newWorker,
        startTime: Date.now(),
        restarts: workerInfo ? workerInfo.restarts + 1 : 1,
        memory: 0,
        cpu: 0
      });

      logger.info(`New worker ${newWorker.id} started with PID ${newWorker.process.pid}`);
    });

    cluster.on('online', (worker) => {
      logger.info(`Worker ${worker.id} is online`);
    });

    cluster.on('listening', (worker, address) => {
      logger.info(`Worker ${worker.id} listening on ${address.address}:${address.port}`);
    });

    // Start monitoring workers
    this.startWorkerMonitoring();

    await AuditLogger.logSystemEvent({
      type: 'CLUSTER_INITIALIZED',
      workerCount: this.config.workerCount,
      timestamp: Date.now()
    });
  }

  /**
   * Initialize cache system
   */
  async initializeCache() {
    if (!this.config.enableCaching) {
      return;
    }

    this.cache = new SmartCache({
      maxSize: this.config.cacheSize * 1024 * 1024, // Convert MB to bytes
      enableCompression: this.config.enableCompression,
      enableMetrics: true
    });

    // Set up cache event handlers
    this.cache.on('hit', (_data) => {
      this.metrics.cacheHits++;
    });

    this.cache.on('miss', (_data) => {
      this.metrics.cacheMisses++;
    });

    this.cache.on('eviction', (data) => {
      logger.debug(`Cache evicted item: ${data.key}`);
    });

    logger.info('Smart cache initialized');
  }

  /**
   * Initialize message queue
   */
  async initializeMessageQueue() {
    this.messageQueue = new MessageQueue({
      maxSize: 10000,
      batchSize: 50,
      processingDelay: 100
    });

    // Override message handler
    this.messageQueue.handleMessage = async (message) => {
      await this.processQueuedMessage(message);
    };

    logger.info('Message queue initialized');
  }

  /**
   * Initialize connection pool
   */
  async initializeConnectionPool(connectionFactory) {
    if (!this.config.enableConnectionPooling || !connectionFactory) {
      return;
    }

    this.connectionPool = new ConnectionPool({
      maxConnections: 100,
      minConnections: 10,
      acquireTimeout: 30000,
      idleTimeout: 300000
    });

    await this.connectionPool.initialize(connectionFactory);

    logger.info('Connection pool initialized');
  }

  /**
   * Process queued message
   */
  async processQueuedMessage(message) {
    try {
      // This would be implemented based on message type
      logger.debug('Processing queued message:', message.type);

      switch (message.type) {
        case 'cache_cleanup':
          await this.performCacheCleanup();
          break;
        case 'memory_optimization':
          await this.optimizeMemory();
          break;
        case 'metric_collection':
          await this.collectMetrics();
          break;
        default:
          logger.warn('Unknown message type:', message.type);
      }

    } catch (error) {
      logger.error('Failed to process queued message:', error);
      throw error;
    }
  }

  /**
   * Start worker monitoring
   */
  startWorkerMonitoring() {
    if (!cluster.isMaster) return;

    this.monitoringInterval = setInterval(async () => {
      for (const [workerId, workerInfo] of this.workers) {
        try {
          // Get worker memory usage
          const memoryUsage = await this.getWorkerMemoryUsage(workerInfo.worker);
          workerInfo.memory = memoryUsage;

          // Check if worker needs restart due to memory leak
          if (memoryUsage > this.config.maxMemoryUsage * 1024 * 1024) {
            logger.warn(`Worker ${workerId} memory usage too high: ${Math.round(memoryUsage / 1024 / 1024)}MB`);

            await AuditLogger.logSystemEvent({
              type: 'WORKER_HIGH_MEMORY',
              workerId,
              memoryUsage,
              threshold: this.config.maxMemoryUsage * 1024 * 1024,
              timestamp: Date.now()
            });

            // Graceful restart
            this.restartWorker(workerId);
          }

        } catch (error) {
          logger.error(`Failed to monitor worker ${workerId}:`, error);
        }
      }
    }, 30000); // Every 30 seconds
  }

  /**
   * Get worker memory usage
   */
  async getWorkerMemoryUsage(worker) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Timeout getting worker memory usage'));
      }, 5000);

      worker.send({ type: 'memory_usage_request' });

      worker.once('message', (message) => {
        clearTimeout(timeout);
        if (message.type === 'memory_usage_response') {
          resolve(message.usage);
        } else {
          reject(new Error('Invalid response'));
        }
      });
    });
  }

  /**
   * Restart worker gracefully
   */
  async restartWorker(workerId) {
    const workerInfo = this.workers.get(workerId);
    if (!workerInfo) return;

    logger.info(`Gracefully restarting worker ${workerId}`);

    // Start replacement worker first
    const newWorker = cluster.fork();

    // Wait for new worker to be ready
    await new Promise((resolve) => {
      newWorker.once('listening', resolve);
      setTimeout(resolve, 10000); // Timeout after 10 seconds
    });

    // Gracefully shut down old worker
    workerInfo.worker.send({ type: 'graceful_shutdown' });

    // Wait for graceful shutdown
    setTimeout(() => {
      if (!workerInfo.worker.isDead()) {
        logger.warn(`Force killing worker ${workerId}`);
        workerInfo.worker.kill('SIGKILL');
      }
    }, this.config.gracefulShutdownTimeout);

    // Update workers map
    this.workers.delete(workerId);
    this.workers.set(newWorker.id, {
      worker: newWorker,
      startTime: Date.now(),
      restarts: workerInfo.restarts + 1,
      memory: 0,
      cpu: 0
    });
  }

  /**
   * Optimize batch processing
   */
  async optimizeBatchProcessing(items, processor, batchSize = 50) {
    const results = [];
    const batches = [];

    // Create batches
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }

    // Process batches in parallel with concurrency limit
    const concurrency = Math.min(4, os.cpus().length);
    const semaphore = new Semaphore(concurrency);

    const promises = batches.map(async (batch, index) => {
      await semaphore.acquire();

      try {
        const batchResult = await processor(batch, index);
        return batchResult;
      } finally {
        semaphore.release();
      }
    });

    const batchResults = await Promise.allSettled(promises);

    // Flatten results
    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.push(...(Array.isArray(result.value) ? result.value : [result.value]));
      } else {
        logger.error('Batch processing failed:', result.reason);
      }
    }

    return results;
  }

  /**
   * Memory optimization
   */
  async optimizeMemory() {
    try {
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      // Clear caches if memory usage is high
      const memoryUsage = process.memoryUsage();
      const memoryPercentage = memoryUsage.heapUsed / memoryUsage.heapTotal;

      if (memoryPercentage > 0.8) {
        logger.warn('High memory usage detected, clearing caches');

        if (this.cache) {
          const cacheSize = this.cache.currentSize;
          this.cache.clear();
          logger.info(`Cleared cache: freed ${Math.round(cacheSize / 1024 / 1024)}MB`);
        }

        // Clear other caches
        this.clearInternalCaches();
      }

    } catch (error) {
      logger.error('Memory optimization failed:', error);
    }
  }

  /**
   * Clear internal caches
   */
  clearInternalCaches() {
    // Clear require cache for non-core modules
    for (const key of Object.keys(require.cache)) {
      if (!key.includes('node_modules') && !key.includes('core')) {
        // eslint-disable-next-line security/detect-object-injection
        delete require.cache[key];
      }
    }
  }

  /**
   * Collect performance metrics
   */
  async collectMetrics() {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    // Update peak memory
    if (memoryUsage.heapUsed > this.metrics.memoryPeak) {
      this.metrics.memoryPeak = memoryUsage.heapUsed;
    }

    // Store CPU usage history
    this.metrics.cpuUsage.push({
      user: cpuUsage.user,
      system: cpuUsage.system,
      timestamp: Date.now()
    });

    // Keep only last 60 measurements (for 30 minutes at 30s intervals)
    if (this.metrics.cpuUsage.length > 60) {
      this.metrics.cpuUsage = this.metrics.cpuUsage.slice(-60);
    }

    // Emit metrics event
    this.emit('metrics', {
      memory: memoryUsage,
      cpu: cpuUsage,
      cache: this.cache ? this.cache.getStats() : null,
      queue: this.messageQueue ? this.messageQueue.getStats() : null,
      pool: this.connectionPool ? this.connectionPool.getStats() : null
    });
  }

  /**
   * Get comprehensive performance stats
   */
  getStats() {
    const uptime = Date.now() - this.metrics.startTime;
    const memoryUsage = process.memoryUsage();

    return {
      uptime,
      memory: {
        current: memoryUsage,
        peak: this.metrics.memoryPeak,
        usage: {
          heap: Math.round(memoryUsage.heapUsed / 1024 / 1024),
          external: Math.round(memoryUsage.external / 1024 / 1024),
          total: Math.round(memoryUsage.heapTotal / 1024 / 1024)
        }
      },
      cluster: cluster.isMaster ? {
        workers: this.workers.size,
        workerStats: Array.from(this.workers.values()).map(w => ({
          id: w.worker.id,
          pid: w.worker.process.pid,
          uptime: Date.now() - w.startTime,
          restarts: w.restarts,
          memory: w.memory
        }))
      } : null,
      cache: this.cache ? this.cache.getStats() : null,
      queue: this.messageQueue ? this.messageQueue.getStats() : null,
      pool: this.connectionPool ? this.connectionPool.getStats() : null,
      requests: this.metrics.requestsProcessed,
      config: this.config
    };
  }

  /**
   * Perform cache cleanup
   */
  async performCacheCleanup() {
    if (this.cache) {
      this.cache.cleanup();
    }
  }

  /**
   * Shutdown performance optimizer
   */
  async shutdown() {
    logger.info('Shutting down performance optimizer...');

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    if (this.cache) {
      this.cache.shutdown();
    }

    if (this.messageQueue) {
      this.messageQueue.shutdown();
    }

    if (this.connectionPool) {
      await this.connectionPool.shutdown();
    }

    // Gracefully shutdown workers if master
    if (cluster.isMaster && this.workers.size > 0) {
      logger.info('Shutting down cluster workers...');

      for (const [_workerId, workerInfo] of this.workers) {
        workerInfo.worker.send({ type: 'graceful_shutdown' });
      }

      // Wait for workers to exit
      await new Promise((resolve) => {
        const checkWorkers = () => {
          if (this.workers.size === 0) {
            resolve();
          } else {
            setTimeout(checkWorkers, 1000);
          }
        };
        checkWorkers();

        // Force exit after timeout
        setTimeout(resolve, this.config.gracefulShutdownTimeout);
      });
    }

    await AuditLogger.logSystemEvent({
      type: 'PERFORMANCE_OPTIMIZER_SHUTDOWN',
      stats: this.getStats(),
      timestamp: Date.now()
    });

    logger.info('Performance optimizer shut down');
  }
}

/**
 * Simple semaphore for concurrency control
 */
class Semaphore {
  constructor(permits) {
    this.permits = permits;
    this.waiting = [];
  }

  async acquire() {
    if (this.permits > 0) {
      this.permits--;
      return;
    }

    return new Promise(resolve => {
      this.waiting.push(resolve);
    });
  }

  release() {
    this.permits++;

    if (this.waiting.length > 0) {
      const resolve = this.waiting.shift();
      this.permits--;
      resolve();
    }
  }
}

module.exports = {
  PerformanceOptimizer,
  SmartCache,
  MessageQueue,
  ConnectionPool,
  Semaphore
};
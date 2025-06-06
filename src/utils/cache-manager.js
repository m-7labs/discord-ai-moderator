/**
 * Advanced Cache Manager with LRU eviction and memory pressure handling
 * Provides multi-layer caching with automatic memory management
 */

const NodeCache = require('node-cache');
const Redis = require('ioredis');
const crypto = require('crypto');
const logger = require('./logger');
const { EventEmitter } = require('events');

class CacheManager extends EventEmitter {
    constructor(options = {}) {
        super();

        this.config = {
            // L1 Cache (Memory) Settings
            l1: {
                enabled: options.l1?.enabled !== false,
                maxSize: options.l1?.maxSize || 100 * 1024 * 1024, // 100MB
                stdTTL: options.l1?.stdTTL || 300, // 5 minutes
                checkperiod: options.l1?.checkperiod || 60,
                useClones: false // Performance optimization
            },

            // L2 Cache (Redis) Settings
            l2: {
                enabled: options.l2?.enabled !== false && process.env.REDIS_URL,
                defaultTTL: options.l2?.defaultTTL || 3600, // 1 hour
                keyPrefix: options.l2?.keyPrefix || 'cache:',
                redis: options.l2?.redis || {
                    host: process.env.REDIS_HOST || 'localhost',
                    port: process.env.REDIS_PORT || 6379,
                    password: process.env.REDIS_PASSWORD,
                    db: process.env.REDIS_CACHE_DB || 1
                }
            },

            // Memory Management
            memory: {
                maxMemoryUsage: options.memory?.maxMemoryUsage || 0.8, // 80% of heap
                checkInterval: options.memory?.checkInterval || 30000, // 30 seconds
                emergencyEvictionRatio: options.memory?.emergencyEvictionRatio || 0.3 // Evict 30%
            },

            // Cache warming
            warming: {
                enabled: options.warming?.enabled || false,
                patterns: options.warming?.patterns || []
            }
        };

        this.stats = {
            hits: { l1: 0, l2: 0 },
            misses: { l1: 0, l2: 0 },
            sets: { l1: 0, l2: 0 },
            evictions: { l1: 0, l2: 0 },
            errors: { l1: 0, l2: 0 }
        };

        this.sizeTracker = new Map();
        this.initialize();
    }

    /**
     * Initialize cache layers
     */
    async initialize() {
        // Initialize L1 cache
        if (this.config.l1.enabled) {
            this.l1Cache = new NodeCache({
                stdTTL: this.config.l1.stdTTL,
                checkperiod: this.config.l1.checkperiod,
                useClones: this.config.l1.useClones,
                deleteOnExpire: true
            });

            // Track cache events
            this.l1Cache.on('expired', (key, value) => {
                this.stats.evictions.l1++;
                this.sizeTracker.delete(key);
                this.emit('eviction', { layer: 'l1', key, reason: 'expired' });
            });

            this.l1Cache.on('del', (key, value) => {
                this.sizeTracker.delete(key);
            });
        }

        // Initialize L2 cache
        if (this.config.l2.enabled) {
            try {
                this.l2Cache = new Redis(this.config.l2.redis);

                this.l2Cache.on('error', (err) => {
                    logger.error('Redis cache error:', err);
                    this.stats.errors.l2++;
                });

                this.l2Cache.on('connect', () => {
                    logger.info('Redis cache connected');
                });

                // Test connection
                await this.l2Cache.ping();
            } catch (error) {
                logger.error('Failed to initialize Redis cache:', error);
                this.config.l2.enabled = false;
            }
        }

        // Start memory monitoring
        this.startMemoryMonitoring();

        // Start cache warming if enabled
        if (this.config.warming.enabled) {
            this.startCacheWarming();
        }
    }

    /**
     * Get value from cache (checks L1, then L2)
     */
    async get(key) {
        const startTime = Date.now();

        // Check L1 cache
        if (this.l1Cache) {
            const value = this.l1Cache.get(key);
            if (value !== undefined) {
                this.stats.hits.l1++;
                this.emit('hit', { layer: 'l1', key, latency: Date.now() - startTime });
                return value;
            }
            this.stats.misses.l1++;
        }

        // Check L2 cache
        if (this.l2Cache && this.config.l2.enabled) {
            try {
                const value = await this.l2Cache.get(this.config.l2.keyPrefix + key);
                if (value) {
                    this.stats.hits.l2++;

                    // Promote to L1
                    if (this.l1Cache) {
                        const parsed = JSON.parse(value);
                        await this.setL1(key, parsed, parsed._ttl);
                    }

                    this.emit('hit', { layer: 'l2', key, latency: Date.now() - startTime });
                    return JSON.parse(value);
                }
                this.stats.misses.l2++;
            } catch (error) {
                logger.error('L2 cache get error:', error);
                this.stats.errors.l2++;
            }
        }

        this.emit('miss', { key, latency: Date.now() - startTime });
        return null;
    }

    /**
     * Set value in cache (sets in both L1 and L2)
     */
    async set(key, value, ttl = null) {
        const startTime = Date.now();

        // Set in L1
        if (this.l1Cache) {
            await this.setL1(key, value, ttl);
        }

        // Set in L2
        if (this.l2Cache && this.config.l2.enabled) {
            await this.setL2(key, value, ttl);
        }

        this.emit('set', { key, latency: Date.now() - startTime });
    }

    /**
     * Set value in L1 cache with size tracking
     */
    async setL1(key, value, ttl = null) {
        try {
            const size = this.calculateSize(value);

            // Check if we have space
            if (await this.ensureSpace(size)) {
                const success = ttl ?
                    this.l1Cache.set(key, value, ttl) :
                    this.l1Cache.set(key, value);

                if (success) {
                    this.sizeTracker.set(key, size);
                    this.stats.sets.l1++;
                }
            }
        } catch (error) {
            logger.error('L1 cache set error:', error);
            this.stats.errors.l1++;
        }
    }

    /**
     * Set value in L2 cache
     */
    async setL2(key, value, ttl = null) {
        try {
            const finalTTL = ttl || this.config.l2.defaultTTL;
            const valueWithMeta = { ...value, _ttl: finalTTL };

            await this.l2Cache.setex(
                this.config.l2.keyPrefix + key,
                finalTTL,
                JSON.stringify(valueWithMeta)
            );

            this.stats.sets.l2++;
        } catch (error) {
            logger.error('L2 cache set error:', error);
            this.stats.errors.l2++;
        }
    }

    /**
     * Delete value from cache
     */
    async delete(key) {
        const promises = [];

        if (this.l1Cache) {
            this.l1Cache.del(key);
        }

        if (this.l2Cache && this.config.l2.enabled) {
            promises.push(
                this.l2Cache.del(this.config.l2.keyPrefix + key)
                    .catch(err => logger.error('L2 cache delete error:', err))
            );
        }

        await Promise.all(promises);
    }

    /**
     * Clear all caches
     */
    async clear() {
        if (this.l1Cache) {
            this.l1Cache.flushAll();
            this.sizeTracker.clear();
        }

        if (this.l2Cache && this.config.l2.enabled) {
            try {
                const keys = await this.l2Cache.keys(this.config.l2.keyPrefix + '*');
                if (keys.length > 0) {
                    await this.l2Cache.del(...keys);
                }
            } catch (error) {
                logger.error('L2 cache clear error:', error);
            }
        }

        this.emit('cleared');
    }

    /**
     * Calculate size of value
     */
    calculateSize(value) {
        // Rough estimation of object size
        const str = JSON.stringify(value);
        return Buffer.byteLength(str, 'utf8');
    }

    /**
     * Get current memory usage
     */
    getCurrentSize() {
        let totalSize = 0;
        for (const size of this.sizeTracker.values()) {
            totalSize += size;
        }
        return totalSize;
    }

    /**
     * Ensure space for new item
     */
    async ensureSpace(requiredSize) {
        const currentSize = this.getCurrentSize();

        if (currentSize + requiredSize > this.config.l1.maxSize) {
            // Need to evict
            const targetSize = this.config.l1.maxSize - requiredSize;
            await this.evictToSize(targetSize);
        }

        return this.getCurrentSize() + requiredSize <= this.config.l1.maxSize;
    }

    /**
     * Evict items to reach target size
     */
    async evictToSize(targetSize) {
        const keys = this.l1Cache.keys();
        const itemsWithAge = [];

        // Get all items with their age
        for (const key of keys) {
            const ttl = this.l1Cache.getTtl(key);
            const age = ttl ? Date.now() - (this.config.l1.stdTTL * 1000 - ttl) : 0;
            itemsWithAge.push({ key, age, size: this.sizeTracker.get(key) || 0 });
        }

        // Sort by age (oldest first)
        itemsWithAge.sort((a, b) => b.age - a.age);

        // Evict until we reach target size
        let currentSize = this.getCurrentSize();
        for (const item of itemsWithAge) {
            if (currentSize <= targetSize) break;

            this.l1Cache.del(item.key);
            currentSize -= item.size;
            this.stats.evictions.l1++;

            this.emit('eviction', { layer: 'l1', key: item.key, reason: 'size' });
        }
    }

    /**
     * Start memory monitoring
     */
    startMemoryMonitoring() {
        this.memoryInterval = setInterval(() => {
            const memoryUsage = process.memoryUsage();
            const heapUsageRatio = memoryUsage.heapUsed / memoryUsage.heapTotal;

            if (heapUsageRatio > this.config.memory.maxMemoryUsage) {
                logger.warn(`High memory usage detected: ${(heapUsageRatio * 100).toFixed(1)}%`);
                this.performEmergencyEviction();
            }

            this.emit('memoryStats', {
                heapUsed: memoryUsage.heapUsed,
                heapTotal: memoryUsage.heapTotal,
                cacheSize: this.getCurrentSize(),
                usage: heapUsageRatio
            });
        }, this.config.memory.checkInterval);
    }

    /**
     * Perform emergency eviction under memory pressure
     */
    async performEmergencyEviction() {
        if (!this.l1Cache) return;

        const keys = this.l1Cache.keys();
        const evictCount = Math.floor(keys.length * this.config.memory.emergencyEvictionRatio);

        logger.warn(`Performing emergency eviction of ${evictCount} items`);

        // Evict random items quickly
        for (let i = 0; i < evictCount && keys.length > 0; i++) {
            const randomIndex = Math.floor(Math.random() * keys.length);
            const key = keys[randomIndex];
            this.l1Cache.del(key);
            keys.splice(randomIndex, 1);
            this.stats.evictions.l1++;
        }

        this.emit('emergencyEviction', { count: evictCount });
    }

    /**
     * Start cache warming
     */
    async startCacheWarming() {
        for (const pattern of this.config.warming.patterns) {
            try {
                await pattern.warm(this);
            } catch (error) {
                logger.error('Cache warming error:', error);
            }
        }
    }

    /**
     * Get cache statistics
     */
    getStats() {
        const l1Stats = this.l1Cache ? {
            keys: this.l1Cache.keys().length,
            size: this.getCurrentSize(),
            maxSize: this.config.l1.maxSize,
            hitRate: this.stats.hits.l1 / (this.stats.hits.l1 + this.stats.misses.l1) || 0
        } : null;

        return {
            ...this.stats,
            l1: l1Stats,
            l2: {
                enabled: this.config.l2.enabled,
                hitRate: this.stats.hits.l2 / (this.stats.hits.l2 + this.stats.misses.l2) || 0
            },
            memory: {
                usage: process.memoryUsage(),
                cacheSize: this.getCurrentSize()
            }
        };
    }

    /**
     * Shutdown cache manager
     */
    async shutdown() {
        if (this.memoryInterval) {
            clearInterval(this.memoryInterval);
        }

        if (this.l1Cache) {
            this.l1Cache.close();
        }

        if (this.l2Cache) {
            await this.l2Cache.quit();
        }

        logger.info('Cache manager shut down');
    }
}

// Singleton instance
let cacheManager = null;

/**
 * Get or create cache manager instance
 */
function getCacheManager(options = {}) {
    if (!cacheManager) {
        cacheManager = new CacheManager(options);
    }
    return cacheManager;
}

/**
 * Cache decorators for easy method caching
 */
function cached(keyGenerator, ttl = 300) {
    return function (target, propertyKey, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = async function (...args) {
            const cache = getCacheManager();
            const key = typeof keyGenerator === 'function' ?
                keyGenerator.apply(this, args) :
                `${propertyKey}:${JSON.stringify(args)}`;

            // Try to get from cache
            const cached = await cache.get(key);
            if (cached !== null) {
                return cached;
            }

            // Call original method
            const result = await originalMethod.apply(this, args);

            // Cache the result
            await cache.set(key, result, ttl);

            return result;
        };

        return descriptor;
    };
}

module.exports = {
    CacheManager,
    getCacheManager,
    cached
};
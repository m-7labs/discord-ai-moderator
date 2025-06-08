/**
 * Tiered Cache - Multi-level caching system for optimized data access
 * Implements L1 (memory) and L2 (persistent) caching with intelligent eviction policies
 */

const logger = require('./logger');

/**
 * LRU Cache implementation for L1 cache
 */
class LRUCache {
    constructor(capacity = 1000) {
        this.capacity = capacity;
        this.cache = new Map();
        this.keyOrder = [];
    }

    get(key) {
        if (!this.cache.has(key)) return null;

        // Move key to the end of the array (most recently used)
        this.keyOrder = this.keyOrder.filter(k => k !== key);
        this.keyOrder.push(key);

        return this.cache.get(key);
    }

    set(key, value) {
        // If key already exists, update its position in keyOrder
        if (this.cache.has(key)) {
            this.keyOrder = this.keyOrder.filter(k => k !== key);
        }
        // If at capacity, remove least recently used item
        else if (this.keyOrder.length >= this.capacity) {
            const lruKey = this.keyOrder.shift();
            this.cache.delete(lruKey);
        }

        // Add new key-value pair
        this.cache.set(key, value);
        this.keyOrder.push(key);
    }

    delete(key) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
            this.keyOrder = this.keyOrder.filter(k => k !== key);
            return true;
        }
        return false;
    }

    clear() {
        this.cache.clear();
        this.keyOrder = [];
    }

    size() {
        return this.cache.size;
    }
}

/**
 * TTL Cache implementation for L2 cache
 */
class TTLCache {
    constructor(defaultTTL = 300000) { // 5 minutes default TTL
        this.cache = new Map();
        this.timers = new Map();
        this.defaultTTL = defaultTTL;
    }

    get(key) {
        if (!this.cache.has(key)) return null;

        const item = this.cache.get(key);
        if (Date.now() > item.expiry) {
            this.delete(key);
            return null;
        }

        return item.value;
    }

    set(key, value, ttl = null) {
        const expiry = Date.now() + (ttl || this.defaultTTL);

        // Clear existing timer if present
        if (this.timers.has(key)) {
            clearTimeout(this.timers.get(key));
        }

        // Set new timer for auto-expiration
        const timer = setTimeout(() => {
            this.delete(key);
        }, ttl || this.defaultTTL);

        this.cache.set(key, { value, expiry });
        this.timers.set(key, timer);
    }

    delete(key) {
        if (this.cache.has(key)) {
            this.cache.delete(key);

            if (this.timers.has(key)) {
                clearTimeout(this.timers.get(key));
                this.timers.delete(key);
            }

            return true;
        }
        return false;
    }

    clear() {
        // Clear all timers
        for (const timer of this.timers.values()) {
            clearTimeout(timer);
        }

        this.cache.clear();
        this.timers.clear();
    }

    size() {
        return this.cache.size;
    }
}

/**
 * Tiered Cache System
 * Combines L1 (memory/LRU) and L2 (TTL-based) caches for optimal performance
 */
class TieredCache {
    constructor(options = {}) {
        this.config = {
            l1Capacity: options.l1Capacity || 1000,
            l2TTL: options.l2TTL || 300000, // 5 minutes
            l1WritePolicy: options.l1WritePolicy || 'write-through', // 'write-through' or 'write-back'
            l1WriteBackInterval: options.l1WriteBackInterval || 60000, // 1 minute
            statsInterval: options.statsInterval || 300000, // 5 minutes
            namespace: options.namespace || 'default'
        };

        // Initialize caches
        this.l1Cache = new LRUCache(this.config.l1Capacity);
        this.l2Cache = new TTLCache(this.config.l2TTL);

        // Statistics
        this.stats = {
            l1Hits: 0,
            l1Misses: 0,
            l2Hits: 0,
            l2Misses: 0,
            sets: 0,
            deletes: 0,
            lastReset: Date.now()
        };

        // Write-back queue for L1 cache if using write-back policy
        this.writeBackQueue = new Map();

        // Start write-back interval if using write-back policy
        if (this.config.l1WritePolicy === 'write-back') {
            this.writeBackInterval = setInterval(() => {
                this.processWriteBackQueue();
            }, this.config.l1WriteBackInterval);
        }

        // Start stats logging interval
        this.statsInterval = setInterval(() => {
            this.logStats();
        }, this.config.statsInterval);

        logger.info(`Tiered cache initialized with namespace: ${this.config.namespace}`, {
            l1Capacity: this.config.l1Capacity,
            l2TTL: this.config.l2TTL,
            writePolicy: this.config.l1WritePolicy
        });
    }

    /**
     * Get a value from the cache
     */
    get(key) {
        const cacheKey = this.getCacheKey(key);

        // Try L1 cache first
        const l1Value = this.l1Cache.get(cacheKey);
        if (l1Value !== null) {
            this.stats.l1Hits++;
            return l1Value;
        }

        this.stats.l1Misses++;

        // Try L2 cache
        const l2Value = this.l2Cache.get(cacheKey);
        if (l2Value !== null) {
            this.stats.l2Hits++;

            // Promote to L1 cache
            this.l1Cache.set(cacheKey, l2Value);

            return l2Value;
        }

        this.stats.l2Misses++;
        return null;
    }

    /**
     * Set a value in the cache
     */
    set(key, value, ttl = null) {
        const cacheKey = this.getCacheKey(key);
        this.stats.sets++;

        // Always set in L1 cache
        this.l1Cache.set(cacheKey, value);

        // Handle L2 cache based on write policy
        if (this.config.l1WritePolicy === 'write-through') {
            // Write-through: immediately write to L2
            this.l2Cache.set(cacheKey, value, ttl);
        } else {
            // Write-back: queue for later write to L2
            this.writeBackQueue.set(cacheKey, { value, ttl });
        }
    }

    /**
     * Delete a value from the cache
     */
    delete(key) {
        const cacheKey = this.getCacheKey(key);
        this.stats.deletes++;

        // Remove from both caches
        const l1Deleted = this.l1Cache.delete(cacheKey);
        const l2Deleted = this.l2Cache.delete(cacheKey);

        // Remove from write-back queue if present
        if (this.writeBackQueue.has(cacheKey)) {
            this.writeBackQueue.delete(cacheKey);
        }

        return l1Deleted || l2Deleted;
    }

    /**
     * Clear the entire cache
     */
    clear() {
        this.l1Cache.clear();
        this.l2Cache.clear();
        this.writeBackQueue.clear();

        // Reset stats
        this.resetStats();

        logger.info(`Tiered cache cleared for namespace: ${this.config.namespace}`);
    }

    /**
     * Get the size of the cache
     */
    size() {
        return {
            l1: this.l1Cache.size(),
            l2: this.l2Cache.size(),
            writeBackQueue: this.writeBackQueue.size
        };
    }

    /**
     * Process the write-back queue
     */
    processWriteBackQueue() {
        if (this.writeBackQueue.size === 0) return;

        const queueSize = this.writeBackQueue.size;
        let processed = 0;

        for (const [key, { value, ttl }] of this.writeBackQueue.entries()) {
            this.l2Cache.set(key, value, ttl);
            this.writeBackQueue.delete(key);
            processed++;
        }

        logger.debug(`Write-back queue processed for namespace: ${this.config.namespace}`, {
            processed,
            queueSize
        });
    }

    /**
     * Generate a namespaced cache key
     */
    getCacheKey(key) {
        return `${this.config.namespace}:${key}`;
    }

    /**
     * Reset cache statistics
     */
    resetStats() {
        this.stats = {
            l1Hits: 0,
            l1Misses: 0,
            l2Hits: 0,
            l2Misses: 0,
            sets: 0,
            deletes: 0,
            lastReset: Date.now()
        };
    }

    /**
     * Log cache statistics
     */
    logStats() {
        const totalRequests = this.stats.l1Hits + this.stats.l1Misses;
        if (totalRequests === 0) return;

        const l1HitRate = (this.stats.l1Hits / totalRequests) * 100;
        const l2HitRate = this.stats.l1Misses > 0 ?
            (this.stats.l2Hits / this.stats.l1Misses) * 100 : 0;
        const overallHitRate = ((this.stats.l1Hits + this.stats.l2Hits) / totalRequests) * 100;

        logger.info(`Cache stats for namespace: ${this.config.namespace}`, {
            totalRequests,
            l1HitRate: `${l1HitRate.toFixed(2)}%`,
            l2HitRate: `${l2HitRate.toFixed(2)}%`,
            overallHitRate: `${overallHitRate.toFixed(2)}%`,
            l1Size: this.l1Cache.size(),
            l2Size: this.l2Cache.size(),
            writeBackQueueSize: this.writeBackQueue.size,
            sets: this.stats.sets,
            deletes: this.stats.deletes,
            uptime: Math.floor((Date.now() - this.stats.lastReset) / 1000) + 's'
        });
    }

    /**
     * Get cache statistics
     */
    getStats() {
        const totalRequests = this.stats.l1Hits + this.stats.l1Misses;
        const l1HitRate = totalRequests > 0 ? (this.stats.l1Hits / totalRequests) * 100 : 0;
        const l2HitRate = this.stats.l1Misses > 0 ? (this.stats.l2Hits / this.stats.l1Misses) * 100 : 0;
        const overallHitRate = totalRequests > 0 ?
            ((this.stats.l1Hits + this.stats.l2Hits) / totalRequests) * 100 : 0;

        return {
            namespace: this.config.namespace,
            l1: {
                hits: this.stats.l1Hits,
                misses: this.stats.l1Misses,
                hitRate: `${l1HitRate.toFixed(2)}%`,
                size: this.l1Cache.size(),
                capacity: this.config.l1Capacity
            },
            l2: {
                hits: this.stats.l2Hits,
                misses: this.stats.l2Misses,
                hitRate: `${l2HitRate.toFixed(2)}%`,
                size: this.l2Cache.size(),
                ttl: this.config.l2TTL
            },
            overall: {
                requests: totalRequests,
                hitRate: `${overallHitRate.toFixed(2)}%`,
                sets: this.stats.sets,
                deletes: this.stats.deletes,
                writeBackQueueSize: this.writeBackQueue.size,
                uptime: Math.floor((Date.now() - this.stats.lastReset) / 1000) + 's'
            },
            config: {
                writePolicy: this.config.l1WritePolicy,
                writeBackInterval: this.config.l1WriteBackInterval
            }
        };
    }

    /**
     * Shutdown the cache
     */
    shutdown() {
        // Process any remaining write-back queue items
        if (this.config.l1WritePolicy === 'write-back') {
            this.processWriteBackQueue();

            if (this.writeBackInterval) {
                clearInterval(this.writeBackInterval);
            }
        }

        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }

        // Log final stats
        this.logStats();

        // Clear caches
        this.l1Cache.clear();
        this.l2Cache.clear();
        this.writeBackQueue.clear();

        logger.info(`Tiered cache shutdown for namespace: ${this.config.namespace}`);
    }
}

module.exports = TieredCache;
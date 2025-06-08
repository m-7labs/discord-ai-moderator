/**
 * Adaptive Query Optimizer - Dynamically optimizes database queries based on system load
 * Implements sophisticated query optimization strategies for high-performance database operations
 */

const os = require('os');
const logger = require('./logger');

/**
 * Adaptive Query Optimizer
 * Optimizes database queries based on current system load and query patterns
 */
class AdaptiveQueryOptimizer {
    constructor(options = {}) {
        this.config = {
            // Load level thresholds
            highLoadThreshold: options.highLoadThreshold || 0.7, // 70% CPU or memory usage is considered high load
            criticalLoadThreshold: options.criticalLoadThreshold || 0.9, // 90% CPU or memory usage is considered critical

            // Query optimization settings
            defaultQueryLimit: options.defaultQueryLimit || 1000,
            highLoadQueryLimit: options.highLoadQueryLimit || 500,
            criticalLoadQueryLimit: options.criticalLoadQueryLimit || 100,

            // Query monitoring
            slowQueryThreshold: options.slowQueryThreshold || 500, // ms
            queryStatsSize: options.queryStatsSize || 100, // Number of recent queries to track

            // Connection management
            maxConnections: options.maxConnections || 100,
            connectionReductionFactor: options.connectionReductionFactor || 0.5,

            // Sampling rate for load checks (to avoid excessive CPU usage from monitoring itself)
            loadCheckSamplingRate: options.loadCheckSamplingRate || 0.1, // 10% of queries trigger a load check

            // Cache settings
            enableQueryCache: options.enableQueryCache !== false,
            queryCacheTTL: options.queryCacheTTL || 60000, // 1 minute
            queryCacheSize: options.queryCacheSize || 1000 // Maximum number of cached query results
        };

        // Current system state
        this.state = {
            loadLevel: 'normal', // 'normal', 'high', or 'critical'
            cpuUsage: 0,
            memoryUsage: 0,
            activeConnections: 0,
            lastLoadCheck: Date.now()
        };

        // Query statistics
        this.queryStats = {
            totalQueries: 0,
            optimizedQueries: 0,
            slowQueries: 0,
            cachedQueries: 0,
            averageQueryTime: 0,
            recentQueries: [] // Array of recent query stats for analysis
        };

        // Query cache
        this.queryCache = new Map();
        this.queryCacheKeys = []; // For LRU eviction

        // Initialize
        this.updateLoadLevel();

        // Start periodic load level updates
        this.loadCheckInterval = setInterval(() => {
            this.updateLoadLevel();
        }, 30000); // Check every 30 seconds
    }

    /**
     * Update the current system load level
     */
    async updateLoadLevel() {
        try {
            // Get CPU usage (average across all cores)
            const cpus = os.cpus();
            let totalIdle = 0;
            let totalTick = 0;

            for (const cpu of cpus) {
                for (const type in cpu.times) {
                    if (Object.prototype.hasOwnProperty.call(cpu.times, type)) {
                        // eslint-disable-next-line security/detect-object-injection
                        totalTick += cpu.times[type];
                    }
                }
                totalIdle += cpu.times.idle;
            }

            const cpuUsage = 1 - (totalIdle / totalTick);

            // Get memory usage
            const totalMem = os.totalmem();
            const freeMem = os.freemem();
            const memoryUsage = (totalMem - freeMem) / totalMem;

            // Update state
            this.state.cpuUsage = cpuUsage;
            this.state.memoryUsage = memoryUsage;

            // Determine load level based on highest resource usage
            const maxUsage = Math.max(cpuUsage, memoryUsage);

            if (maxUsage >= this.config.criticalLoadThreshold) {
                this.state.loadLevel = 'critical';
            } else if (maxUsage >= this.config.highLoadThreshold) {
                this.state.loadLevel = 'high';
            } else {
                this.state.loadLevel = 'normal';
            }

            this.state.lastLoadCheck = Date.now();

            // Log significant load level changes
            if (this.state.loadLevel === 'critical') {
                logger.warn('System under critical load', {
                    cpuUsage: Math.round(cpuUsage * 100) + '%',
                    memoryUsage: Math.round(memoryUsage * 100) + '%',
                    activeConnections: this.state.activeConnections
                });
            }
        } catch (error) {
            logger.error('Error updating load level', { error: error.message });
        }
    }

    /**
     * Optimize a SQL query based on current system load
     */
    optimizeQuery(sql, params = [], options = {}) {
        // Skip optimization for specific queries
        if (options.skipOptimization) {
            return { sql, params };
        }

        // Clone params to avoid modifying the original array
        const newParams = [...params];
        let newSql = sql;

        // Apply different optimizations based on load level
        if (this.state.loadLevel === 'critical' || this.state.loadLevel === 'high') {
            // Add or modify LIMIT clause for SELECT queries
            if (newSql.trim().toUpperCase().startsWith('SELECT') && !newSql.toUpperCase().includes('LIMIT')) {
                const limit = this.state.loadLevel === 'critical'
                    ? this.config.criticalLoadQueryLimit
                    : this.config.highLoadQueryLimit;

                newSql = `${newSql} LIMIT ${limit}`;
                this.queryStats.optimizedQueries++;
            }

            // Add query hints for SQLite
            if (!newSql.includes('INDEXED BY') && !options.skipIndexHints) {
                // Add index hints based on table and where clause patterns
                // This is a simplified approach - in a real system, you'd analyze the schema
                if (newSql.includes('violation_logs') && newSql.includes('WHERE')) {
                    if (newSql.includes('server_id') && newSql.includes('created_at')) {
                        newSql = newSql.replace('FROM violation_logs', 'FROM violation_logs INDEXED BY idx_violation_logs_server_created');
                        this.queryStats.optimizedQueries++;
                    } else if (newSql.includes('user_id')) {
                        newSql = newSql.replace('FROM violation_logs', 'FROM violation_logs INDEXED BY idx_violation_logs_user_created');
                        this.queryStats.optimizedQueries++;
                    }
                }
            }
        }

        return { sql: newSql, params: newParams };
    }

    /**
     * Execute a query with adaptive optimization
     */
    async executeQuery(dbAsync, sql, params = [], options = {}) {
        // Check if we should update load level (based on sampling)
        if (Math.random() < this.config.loadCheckSamplingRate) {
            await this.updateLoadLevel();
        }

        // Track query execution
        this.queryStats.totalQueries++;

        // Check cache for read queries
        const isReadQuery = sql.trim().toUpperCase().startsWith('SELECT');
        if (isReadQuery && this.config.enableQueryCache && !options.skipCache) {
            const cacheKey = this.getCacheKey(sql, params);
            const cachedResult = this.queryCache.get(cacheKey);

            if (cachedResult && cachedResult.expiry > Date.now()) {
                this.queryStats.cachedQueries++;
                return cachedResult.data;
            }
        }

        // Optimize query
        const { sql: optimizedSql, params: optimizedParams } = this.optimizeQuery(sql, params, options);

        // Execute query with timing
        const startTime = Date.now();
        let result;

        try {
            // Determine query method based on the SQL statement
            if (optimizedSql.trim().toUpperCase().startsWith('SELECT')) {
                if (options.singleRow) {
                    result = await dbAsync.get(optimizedSql, optimizedParams);
                } else {
                    result = await dbAsync.all(optimizedSql, optimizedParams);
                }
            } else {
                result = await dbAsync.run(optimizedSql, optimizedParams);
            }

            const endTime = Date.now();
            const queryTime = endTime - startTime;

            // Record query stats
            this.recordQueryStats(optimizedSql, queryTime, result);

            // Cache read query results
            if (isReadQuery && this.config.enableQueryCache && !options.skipCache && queryTime < this.config.slowQueryThreshold) {
                this.cacheQueryResult(sql, params, result);
            }

            return result;
        } catch (error) {
            logger.error('Query execution error', {
                error: error.message,
                sql: optimizedSql,
                loadLevel: this.state.loadLevel
            });
            throw error;
        }
    }

    /**
     * Record statistics for a query
     */
    recordQueryStats(sql, queryTime, result) {
        // Update average query time
        const totalQueries = this.queryStats.totalQueries;
        this.queryStats.averageQueryTime =
            (this.queryStats.averageQueryTime * (totalQueries - 1) + queryTime) / totalQueries;

        // Check for slow query
        if (queryTime > this.config.slowQueryThreshold) {
            this.queryStats.slowQueries++;

            // Log slow query
            logger.warn('Slow query detected', {
                queryTime: `${queryTime}ms`,
                threshold: `${this.config.slowQueryThreshold}ms`,
                sql: sql.substring(0, 100) + (sql.length > 100 ? '...' : ''),
                loadLevel: this.state.loadLevel,
                resultSize: Array.isArray(result) ? result.length : 'N/A'
            });
        }

        // Add to recent queries
        this.queryStats.recentQueries.unshift({
            sql: sql.substring(0, 100) + (sql.length > 100 ? '...' : ''),
            time: queryTime,
            timestamp: Date.now(),
            loadLevel: this.state.loadLevel
        });

        // Trim recent queries list
        if (this.queryStats.recentQueries.length > this.config.queryStatsSize) {
            this.queryStats.recentQueries.pop();
        }
    }

    /**
     * Generate a cache key for a query
     */
    getCacheKey(sql, params) {
        return `${sql}:${JSON.stringify(params)}`;
    }

    /**
     * Cache a query result
     */
    cacheQueryResult(sql, params, result) {
        const cacheKey = this.getCacheKey(sql, params);

        // Manage cache size (LRU eviction)
        if (this.queryCacheKeys.length >= this.config.queryCacheSize) {
            const oldestKey = this.queryCacheKeys.pop();
            this.queryCache.delete(oldestKey);
        }

        // Add to cache
        this.queryCache.set(cacheKey, {
            data: result,
            expiry: Date.now() + this.config.queryCacheTTL
        });

        // Update LRU order
        this.queryCacheKeys.unshift(cacheKey);
    }

    /**
     * Clear the query cache
     */
    clearCache() {
        this.queryCache.clear();
        this.queryCacheKeys = [];
    }

    /**
     * Get optimizer statistics
     */
    getStats() {
        return {
            ...this.queryStats,
            loadLevel: this.state.loadLevel,
            cpuUsage: Math.round(this.state.cpuUsage * 100) + '%',
            memoryUsage: Math.round(this.state.memoryUsage * 100) + '%',
            activeConnections: this.state.activeConnections,
            cacheSize: this.queryCache.size,
            lastLoadCheck: new Date(this.state.lastLoadCheck).toISOString()
        };
    }

    /**
     * Shutdown the optimizer
     */
    shutdown() {
        if (this.loadCheckInterval) {
            clearInterval(this.loadCheckInterval);
        }

        this.clearCache();
        logger.info('Adaptive query optimizer shutdown');
    }
}

module.exports = AdaptiveQueryOptimizer;
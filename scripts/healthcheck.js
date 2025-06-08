
/**
 * Discord AI Moderator - Health Check Script
 * 
 * This script performs a comprehensive health check of the application
 * and its dependencies. It's used by Docker for container health monitoring
 * and can also be run manually for diagnostics.
 */

const http = require('http');
const { MongoClient } = require('mongodb');
const { createClient } = require('redis');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Configuration
const config = {
    app: {
        port: process.env.DASHBOARD_PORT || 3000,
        host: 'localhost',
        endpoint: '/api/health',
        timeout: 5000
    },
    mongodb: {
        enabled: process.env.DB_TYPE === 'MONGODB',
        uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/discord-ai-moderator',
        timeout: 5000
    },
    postgres: {
        enabled: process.env.DB_TYPE === 'POSTGRESQL',
        host: process.env.POSTGRES_HOST || 'localhost',
        port: process.env.POSTGRES_PORT || 5432,
        database: process.env.POSTGRES_DB || 'discord_ai_mod',
        user: process.env.POSTGRES_USER || 'discord_ai_mod_user',
        password: process.env.POSTGRES_PASSWORD || '',
        timeout: 5000
    },
    redis: {
        enabled: process.env.ENABLE_TIERED_CACHE === 'true' || process.env.SESSION_STORE === 'redis',
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || '',
        timeout: 5000
    },
    system: {
        minFreeMem: 100 * 1024 * 1024, // 100 MB
        maxCpuLoad: 0.95 // 95%
    }
};

// Health check results
const results = {
    app: false,
    database: false,
    redis: false,
    system: false,
    details: {}
};

/**
 * Check if the application API is responding
 */
async function checkAppHealth() {
    return new Promise((resolve) => {
        const req = http.request({
            host: config.app.host,
            port: config.app.port,
            path: config.app.endpoint,
            method: 'GET',
            timeout: config.app.timeout
        }, (res) => {
            if (res.statusCode === 200) {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    try {
                        const health = JSON.parse(data);
                        results.details.app = health;
                        results.app = health.status === 'ok';
                        resolve(results.app);
                    } catch (err) {
                        results.details.app = { error: 'Invalid response format' };
                        resolve(false);
                    }
                });
            } else {
                results.details.app = { error: `HTTP ${res.statusCode}` };
                resolve(false);
            }
        });

        req.on('error', (err) => {
            results.details.app = { error: err.message };
            resolve(false);
        });

        req.on('timeout', () => {
            req.destroy();
            results.details.app = { error: 'Request timeout' };
            resolve(false);
        });

        req.end();
    });
}

/**
 * Check MongoDB connection
 */
async function checkMongoDBHealth() {
    if (!config.mongodb.enabled) {
        results.database = true;
        results.details.mongodb = { status: 'disabled' };
        return true;
    }

    const client = new MongoClient(config.mongodb.uri, {
        serverSelectionTimeoutMS: config.mongodb.timeout
    });

    try {
        await client.connect();
        await client.db().admin().ping();
        results.database = true;
        results.details.mongodb = { status: 'connected' };
        return true;
    } catch (err) {
        results.details.mongodb = { error: err.message };
        return false;
    } finally {
        await client.close();
    }
}

/**
 * Check PostgreSQL connection
 */
async function checkPostgresHealth() {
    if (!config.postgres.enabled) {
        if (!config.mongodb.enabled) {
            results.database = false;
            results.details.postgres = { status: 'disabled' };
        }
        return true;
    }

    const pool = new Pool({
        host: config.postgres.host,
        port: config.postgres.port,
        database: config.postgres.database,
        user: config.postgres.user,
        password: config.postgres.password,
        connectionTimeoutMillis: config.postgres.timeout
    });

    try {
        const client = await pool.connect();
        const result = await client.query('SELECT 1');
        client.release();

        results.database = result.rows.length === 1;
        results.details.postgres = { status: 'connected' };
        return true;
    } catch (err) {
        results.details.postgres = { error: err.message };
        return false;
    } finally {
        await pool.end();
    }
}

/**
 * Check Redis connection
 */
async function checkRedisHealth() {
    if (!config.redis.enabled) {
        results.redis = true;
        results.details.redis = { status: 'disabled' };
        return true;
    }

    const client = createClient({
        url: `redis://${config.redis.password ? `:${config.redis.password}@` : ''}${config.redis.host}:${config.redis.port}`
    });

    try {
        await client.connect();
        const pong = await client.ping();
        results.redis = pong === 'PONG';
        results.details.redis = { status: 'connected' };
        return true;
    } catch (err) {
        results.details.redis = { error: err.message };
        return false;
    } finally {
        client.quit();
    }
}

/**
 * Check system resources
 */
function checkSystemHealth() {
    const freeMem = os.freemem();
    const cpuLoad = os.loadavg()[0] / os.cpus().length;

    results.system = freeMem > config.system.minFreeMem && cpuLoad < config.system.maxCpuLoad;
    results.details.system = {
        freeMem: `${Math.round(freeMem / 1024 / 1024)} MB`,
        cpuLoad: cpuLoad.toFixed(2),
        uptime: `${Math.round(os.uptime() / 3600)} hours`
    };

    return results.system;
}

/**
 * Check data directory
 */
function checkDataDirectory() {
    const dataDir = path.join(process.cwd(), 'data');

    try {
        fs.accessSync(dataDir, fs.constants.R_OK | fs.constants.W_OK);
        results.details.dataDir = { status: 'accessible' };
        return true;
    } catch (err) {
        results.details.dataDir = { error: err.message };
        return false;
    }
}

/**
 * Run all health checks
 */
async function runHealthChecks() {
    try {
        const appHealth = await checkAppHealth();
        const mongoHealth = await checkMongoDBHealth();
        const postgresHealth = await checkPostgresHealth();
        const redisHealth = await checkRedisHealth();
        const systemHealth = checkSystemHealth();
        const dataDirHealth = checkDataDirectory();

        const allChecks = appHealth &&
            (mongoHealth || postgresHealth) &&
            redisHealth &&
            systemHealth &&
            dataDirHealth;

        if (allChecks) {
            console.log('Health check passed');
            process.exit(0);
        } else {
            console.error('Health check failed:', JSON.stringify(results, null, 2));
            process.exit(1);
        }
    } catch (err) {
        console.error('Health check error:', err);
        process.exit(1);
    }
}

// Run the health checks
runHealthChecks();
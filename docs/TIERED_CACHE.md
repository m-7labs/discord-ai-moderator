# Tiered Caching System Documentation

This document provides detailed information about the Tiered Caching System implementation in the Discord AI Moderator application.

## Overview

The Tiered Caching System is a sophisticated multi-level caching solution designed to improve application performance by reducing database load and speeding up data access. It implements a two-level caching architecture with intelligent cache policies, comprehensive metrics tracking, and configurable behavior.

## Architecture

### Core Components

1. **TieredCache** (`src/utils/tiered-cache.js`)
   - Main class that manages the tiered cache
   - Coordinates between L1 and L2 caches
   - Implements cache policies and statistics

2. **LRUCache** (Internal Component)
   - Implements the L1 (memory) cache
   - Uses Least Recently Used (LRU) eviction policy
   - Provides fast in-memory access

3. **TTLCache** (Internal Component)
   - Implements the L2 (persistent) cache
   - Uses Time To Live (TTL) expiration
   - Provides longer-term storage

### Cache Levels

#### L1 Cache (Memory)

- Fast in-memory cache using an LRU eviction policy
- Stores frequently accessed data
- Limited capacity based on configuration
- Optimized for speed

#### L2 Cache (Persistent)

- Longer-term storage with TTL expiration
- Can be backed by Redis for persistence across restarts
- Higher capacity than L1
- Optimized for reliability

### Data Flow

1. **Cache Read**
   - Check L1 cache first
   - If not found in L1, check L2 cache
   - If found in L2, promote to L1 and return
   - If not found in either cache, return null

2. **Cache Write (Write-Through)**
   - Write to L1 cache
   - Immediately write to L2 cache
   - Return success

3. **Cache Write (Write-Back)**
   - Write to L1 cache
   - Add to write-back queue for L2
   - Periodically flush queue to L2
   - Return success

## Features

### Write Policies

The tiered cache supports two write policies:

#### Write-Through

- Writes data to both L1 and L2 caches immediately
- Ensures data consistency across cache levels
- Higher write latency but better reliability
- Recommended for critical data

```javascript
const cache = new TieredCache({
  namespace: 'server-config',
  l1WritePolicy: 'write-through'
});
```

#### Write-Back

- Writes data to L1 cache immediately
- Queues writes for L2 cache
- Periodically flushes queue to L2
- Lower write latency but potential data loss on crashes
- Recommended for high-write scenarios

```javascript
const cache = new TieredCache({
  namespace: 'user-data',
  l1WritePolicy: 'write-back',
  l1WriteBackInterval: 10000 // 10 seconds
});
```

### Cache Statistics

The tiered cache tracks comprehensive statistics:

- **Hit Rates**: Percentage of successful cache lookups
- **Miss Rates**: Percentage of failed cache lookups
- **Size**: Current number of items in each cache
- **Operations**: Count of get, set, and delete operations
- **Write-Back Queue**: Size and processing metrics

These statistics can be used to monitor cache performance and tune configuration.

### Namespace Isolation

The tiered cache supports namespace isolation to prevent key collisions:

```javascript
const userCache = new TieredCache({ namespace: 'users' });
const configCache = new TieredCache({ namespace: 'config' });

// These don't conflict despite having the same key
userCache.set('123', userData);
configCache.set('123', configData);
```

## Usage

### Basic Usage

```javascript
const TieredCache = require('./utils/tiered-cache');

// Create a cache instance
const cache = new TieredCache({
  namespace: 'server-config',
  l1Capacity: 500,
  l2TTL: 300000 // 5 minutes
});

// Set a value
cache.set('config:server123', serverConfig);

// Get a value
const config = cache.get('config:server123');

// Delete a value
cache.delete('config:server123');

// Clear the entire cache
cache.clear();

// Get cache size
const size = cache.size();

// Get cache statistics
const stats = cache.getStats();

// Shutdown the cache
cache.shutdown();
```

### Advanced Usage

```javascript
const TieredCache = require('./utils/tiered-cache');

// Create a cache with write-back policy
const cache = new TieredCache({
  namespace: 'user-data',
  l1Capacity: 1000,
  l2TTL: 60000, // 1 minute
  l1WritePolicy: 'write-back',
  l1WriteBackInterval: 10000, // 10 seconds
  statsInterval: 300000 // 5 minutes
});

// Set a value with custom TTL
cache.set('user:123', userData, 120000); // 2 minutes TTL

// Process write-back queue manually
cache.processWriteBackQueue();

// Get cache statistics
const stats = cache.getStats();
console.log(`L1 hit rate: ${stats.l1.hitRate}`);
console.log(`L2 hit rate: ${stats.l2.hitRate}`);
console.log(`Overall hit rate: ${stats.overall.hitRate}`);
```

## Integration with Database

The tiered cache is integrated with the database layer in `src/database.js`:

```javascript
// Create cache instances
const configCache = new TieredCache({
  namespace: 'server-config',
  l1Capacity: 500,
  l2TTL: 300000,
  l1WritePolicy: 'write-through',
  statsInterval: 600000
});

const userCache = new TieredCache({
  namespace: 'user-data',
  l1Capacity: 1000,
  l2TTL: 60000,
  l1WritePolicy: 'write-back',
  l1WriteBackInterval: 10000,
  statsInterval: 600000
});

// Example usage in database functions
async function getServerConfig(serverId) {
  // Check cache first
  const cacheKey = `config:${serverId}`;
  const cached = configCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Get from database
  const config = await dbAsync.get('SELECT * FROM server_configs WHERE server_id = ?', [serverId]);
  
  // Cache the result
  configCache.set(cacheKey, config);
  
  return config;
}
```

## Configuration Options

### TieredCache Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `namespace` | Cache namespace for key isolation | `'default'` |
| `l1Capacity` | Maximum number of items in L1 cache | `1000` |
| `l2TTL` | Time to live for L2 cache items (ms) | `300000` (5 minutes) |
| `l1WritePolicy` | Write policy (`'write-through'` or `'write-back'`) | `'write-through'` |
| `l1WriteBackInterval` | Interval for write-back processing (ms) | `60000` (1 minute) |
| `statsInterval` | Interval for logging statistics (ms) | `300000` (5 minutes) |

### Environment Variables

The tiered cache can be configured using environment variables:

```env
# Tiered Cache Configuration
ENABLE_TIERED_CACHE=true
L1_CACHE_CAPACITY=1000
L2_CACHE_TTL=300000
L1_WRITE_POLICY=write-through
L1_WRITE_BACK_INTERVAL=60000
CACHE_STATS_INTERVAL=300000
```

## Performance Considerations

### Memory Usage

The L1 cache is stored entirely in memory, so its capacity should be set based on available system memory:

- **Small Systems**: 100-500 items
- **Medium Systems**: 500-2000 items
- **Large Systems**: 2000-10000 items

Monitor memory usage and adjust L1 capacity accordingly.

### Write Policy Selection

Choose the appropriate write policy based on your workload:

- **Write-Through**: Use for critical data where consistency is important
- **Write-Back**: Use for high-write scenarios where performance is critical

### TTL Tuning

Adjust the L2 cache TTL based on data volatility:

- **Frequently Changing Data**: Shorter TTL (seconds to minutes)
- **Relatively Stable Data**: Longer TTL (minutes to hours)
- **Static Data**: Very long TTL (hours to days)

### Cache Key Design

Design cache keys carefully:

- Use namespaces to prevent collisions
- Include all relevant identifiers in keys
- Keep keys reasonably short
- Use consistent key formats

## Monitoring and Optimization

### Statistics Monitoring

The tiered cache logs statistics at regular intervals:

```
[INFO] Cache stats for namespace: server-config
{
  "totalRequests": 15243,
  "l1HitRate": "87.45%",
  "l2HitRate": "65.32%",
  "overallHitRate": "95.67%",
  "l1Size": 487,
  "l2Size": 1243,
  "writeBackQueueSize": 0,
  "sets": 3421,
  "deletes": 156,
  "uptime": "3600s"
}
```

Monitor these statistics to identify:

- **Low Hit Rates**: May indicate cache configuration issues
- **High Write-Back Queue**: May indicate L2 write issues
- **Cache Size Imbalance**: May indicate capacity issues

### Cache Tuning

Based on statistics, tune the cache configuration:

1. **L1 Capacity**: If L1 hit rate is low, consider increasing capacity
2. **L2 TTL**: If L2 hit rate is low, consider increasing TTL
3. **Write Policy**: If write performance is an issue, consider write-back
4. **Write-Back Interval**: Adjust based on write-back queue size

## Troubleshooting

### Low Hit Rates

If hit rates are lower than expected:

1. Check cache key design
2. Verify cache invalidation logic
3. Adjust cache capacities and TTLs
4. Review data access patterns

### Memory Issues

If memory usage is too high:

1. Reduce L1 cache capacity
2. Verify no memory leaks in cache usage
3. Consider more aggressive L1 eviction

### Write-Back Queue Growth

If the write-back queue is growing:

1. Check L2 cache connectivity
2. Reduce write-back interval
3. Switch to write-through temporarily
4. Monitor system resources

### Cache Inconsistency

If cache data is inconsistent:

1. Check for proper cache invalidation
2. Verify write policy configuration
3. Check for race conditions in cache access
4. Consider using write-through policy

## Examples

### Server Configuration Cache

```javascript
const TieredCache = require('./utils/tiered-cache');

// Create a cache for server configurations
const configCache = new TieredCache({
  namespace: 'server-config',
  l1Capacity: 500,        // Store up to 500 server configs in memory
  l2TTL: 3600000,         // 1 hour TTL for L2
  l1WritePolicy: 'write-through',
  statsInterval: 600000   // Log stats every 10 minutes
});

// Usage in server config functions
function getServerConfig(serverId) {
  const cacheKey = `config:${serverId}`;
  
  // Try cache first
  const cached = configCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Get from database
  const config = database.getServerConfig(serverId);
  
  // Cache the result
  configCache.set(cacheKey, config);
  
  return config;
}

function updateServerConfig(serverId, config) {
  // Update database
  database.updateServerConfig(serverId, config);
  
  // Update cache
  const cacheKey = `config:${serverId}`;
  configCache.set(cacheKey, config);
}

function deleteServerConfig(serverId) {
  // Delete from database
  database.deleteServerConfig(serverId);
  
  // Delete from cache
  const cacheKey = `config:${serverId}`;
  configCache.delete(cacheKey);
}
```

### User Data Cache

```javascript
const TieredCache = require('./utils/tiered-cache');

// Create a cache for user data
const userCache = new TieredCache({
  namespace: 'user-data',
  l1Capacity: 1000,       // Store up to 1000 users in memory
  l2TTL: 60000,           // 1 minute TTL for L2
  l1WritePolicy: 'write-back',
  l1WriteBackInterval: 10000, // Write back every 10 seconds
  statsInterval: 600000   // Log stats every 10 minutes
});

// Usage in user data functions
function getUserData(userId, serverId) {
  const cacheKey = `user:${userId}:${serverId}`;
  
  // Try cache first
  const cached = userCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Get from database
  const userData = database.getUserData(userId, serverId);
  
  // Cache the result
  userCache.set(cacheKey, userData);
  
  return userData;
}

function updateUserData(userId, serverId, userData) {
  // Update database
  database.updateUserData(userId, serverId, userData);
  
  // Update cache
  const cacheKey = `user:${userId}:${serverId}`;
  userCache.set(cacheKey, userData);
}
```

### Violation Logs Cache

```javascript
const TieredCache = require('./utils/tiered-cache');

// Create a cache for violation logs
const violationCache = new TieredCache({
  namespace: 'violation-logs',
  l1Capacity: 200,        // Store up to 200 recent violations in memory
  l2TTL: 300000,          // 5 minutes TTL for L2
  l1WritePolicy: 'write-through',
  statsInterval: 600000   // Log stats every 10 minutes
});

// Usage in violation log functions
function getRecentViolations(serverId, limit = 10) {
  const cacheKey = `recent:${serverId}:${limit}`;
  
  // Try cache first
  const cached = violationCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  
  // Get from database
  const violations = database.getRecentViolations(serverId, limit);
  
  // Cache the result
  violationCache.set(cacheKey, violations, 60000); // 1 minute TTL
  
  return violations;
}

function logViolation(violation) {
  // Add to database
  database.logViolation(violation);
  
  // Invalidate related cache entries
  const cacheKey = `recent:${violation.serverId}`;
  violationCache.delete(cacheKey);
  violationCache.delete(`${cacheKey}:10`);
  violationCache.delete(`${cacheKey}:20`);
  violationCache.delete(`${cacheKey}:50`);
}
```

## Best Practices

1. **Use Namespaces**: Always use appropriate namespaces to prevent key collisions
2. **Consistent Keys**: Use consistent key formats across your application
3. **Appropriate TTLs**: Set TTLs based on data volatility
4. **Cache Invalidation**: Properly invalidate cache entries when data changes
5. **Error Handling**: Handle cache errors gracefully
6. **Monitoring**: Regularly monitor cache statistics
7. **Tuning**: Adjust configuration based on performance metrics
8. **Shutdown**: Always shut down the cache properly when your application exits
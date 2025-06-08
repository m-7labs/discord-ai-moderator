# Worker Thread Pool Documentation

This document provides detailed information about the Worker Thread Pool implementation in the Discord AI Moderator application.

## Overview

The Worker Thread Pool is a system for offloading CPU-intensive operations to separate threads, preventing the main event loop from being blocked. This improves the application's responsiveness and overall performance, especially for operations like content analysis, text processing, and data validation.

## Architecture

### Core Components

1. **WorkerThreadPool** (`src/utils/worker-thread-pool.js`)
   - Main class that manages the worker thread pool
   - Handles thread creation, scaling, and task distribution
   - Provides a high-level API for executing tasks

2. **Worker Thread Bootstrap** (`src/utils/worker-thread-bootstrap.js`)
   - Entry point for worker threads
   - Handles communication with the main thread
   - Loads and executes task modules

3. **Worker Manager** (`src/utils/worker-manager.js`)
   - High-level API for using the worker thread pool
   - Provides simplified task execution methods
   - Manages worker thread pool lifecycle

4. **Worker Tasks**
   - `src/utils/worker-tasks/system-info.js`: System information collection
   - `src/utils/worker-tasks/content-analysis.js`: Content moderation analysis
   - `src/utils/worker-tasks/text-processing.js`: Text processing and analysis
   - `src/utils/worker-tasks/data-validation.js`: Data validation against schemas

### Communication Flow

1. Main thread creates a worker thread pool
2. Tasks are submitted to the pool with a priority level
3. Pool assigns tasks to available workers based on priority
4. Worker threads execute tasks and return results
5. Main thread receives results and handles them accordingly

## Features

### Adaptive Scaling

The worker thread pool automatically adjusts the number of worker threads based on system load:

- **Minimum Threads**: Always maintains a minimum number of threads
- **Maximum Threads**: Never exceeds a maximum number of threads
- **Scale Up**: Creates additional threads when load is high
- **Scale Down**: Terminates idle threads when load is low

```javascript
// Example configuration
{
  minThreads: 2,
  maxThreads: 8,
  adaptiveScaling: true,
  highLoadThreshold: 0.7,
  criticalLoadThreshold: 0.9
}
```

### Priority-Based Task Queuing

Tasks are queued based on priority levels:

- **Priority 0**: Highest priority (e.g., critical system tasks)
- **Priority 1**: Medium priority (e.g., user-initiated tasks)
- **Priority 2+**: Lower priorities (e.g., background tasks)

The pool processes higher-priority tasks before lower-priority ones, ensuring that critical operations are completed first.

### Error Handling and Recovery

The worker thread pool includes comprehensive error handling:

- **Task Errors**: Errors in task execution are caught and reported
- **Worker Crashes**: Failed workers are automatically replaced
- **Timeout Handling**: Long-running tasks can be terminated
- **Error Thresholds**: Workers with too many errors are replaced

### Performance Monitoring

The pool tracks detailed performance metrics:

- **Worker Utilization**: Percentage of workers that are busy
- **Task Processing Time**: Average and maximum task execution time
- **Queue Wait Time**: Time tasks spend waiting in the queue
- **Error Rates**: Number of task and worker errors
- **CPU Utilization**: System CPU usage

## Usage

### Basic Usage

```javascript
const workerManager = require('./utils/worker-manager');

// Initialize worker manager
await workerManager.initialize();

// Execute a content analysis task
const result = await workerManager.analyzeContent('Text to analyze', {
  checkProfanity: true,
  checkToxicity: true
});

// Execute a text processing task
const processed = await workerManager.processText('Text to process', {
  tokenize: true,
  extractEntities: true
});

// Execute a data validation task
const validation = await workerManager.validateData(data, schema);

// Shutdown worker manager
await workerManager.shutdown();
```

### Advanced Usage

```javascript
const workerManager = require('./utils/worker-manager');

// Initialize with custom configuration
await workerManager.initialize({
  minThreads: 4,
  maxThreads: 16,
  adaptiveScaling: true,
  taskDirectory: path.join(__dirname, 'custom-tasks')
});

// Register a custom task
workerManager.registerTask('custom-task', path.join(__dirname, 'custom-tasks/my-task.js'));

// Execute a task with custom options
const result = await workerManager.executeTask('custom-task', {
  input: 'Custom input data',
  options: {
    option1: true,
    option2: 'value'
  }
}, {
  priority: 0, // Highest priority
  timeout: 10000 // 10 seconds
});

// Get worker pool statistics
const stats = workerManager.getStats();
console.log(`Active workers: ${stats.workers.total}`);
console.log(`Current load: ${stats.workers.load}`);
console.log(`Tasks processed: ${stats.tasks.processed}`);
```

## Creating Custom Worker Tasks

You can create custom worker tasks to extend the functionality of the worker thread pool.

### Task File Structure

```javascript
/**
 * Custom worker task
 */

/**
 * Execute the task
 * @param {Object} data - Task input data
 * @param {Object} context - Execution context
 * @returns {Object} Task result
 */
async function execute(data = {}, context = {}) {
  try {
    // Task implementation
    const result = doSomething(data);
    
    // Return result
    return {
      result,
      meta: {
        processingTime: Date.now() - startTime,
        workerId: context.workerId
      }
    };
  } catch (error) {
    console.error('Error in custom task:', error);
    throw new Error(`Task failed: ${error.message}`);
  }
}

module.exports = { execute };
```

### Task Registration

```javascript
// Register the task
workerManager.registerTask('custom-task', path.join(__dirname, 'custom-tasks/my-task.js'));
```

### Task Execution

```javascript
// Execute the task
const result = await workerManager.executeTask('custom-task', {
  // Task input data
});
```

## Configuration Options

### Worker Thread Pool Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `minThreads` | Minimum number of worker threads | `Math.max(1, Math.floor(os.cpus().length / 4))` |
| `maxThreads` | Maximum number of worker threads | `Math.max(2, os.cpus().length - 1)` |
| `idleTimeout` | Time in ms before idle workers are terminated | `60000` (1 minute) |
| `maxTasksPerWorker` | Maximum tasks per worker before recycling | `100` |
| `taskTimeout` | Default task timeout in ms | `30000` (30 seconds) |
| `monitorInterval` | Interval in ms for monitoring the pool | `5000` (5 seconds) |
| `adaptiveScaling` | Enable/disable adaptive scaling | `true` |
| `highLoadThreshold` | Load threshold for scaling up | `0.7` (70%) |
| `criticalLoadThreshold` | Load threshold for scaling to max | `0.9` (90%) |
| `taskDirectory` | Directory containing task modules | `path.join(__dirname, 'worker-tasks')` |
| `priorityLevels` | Number of priority levels | `3` |
| `statsInterval` | Interval in ms for logging stats | `60000` (1 minute) |
| `errorThreshold` | Errors before worker is terminated | `5` |
| `errorTimeWindow` | Time window in ms for error threshold | `60000` (1 minute) |
| `recoveryInterval` | Interval in ms for worker recovery | `5000` (5 seconds) |
| `warmupEnabled` | Enable/disable pool warmup | `true` |
| `warmupTasks` | Tasks to execute during warmup | `['system-info']` |

### Environment Variables

The worker thread pool can be configured using environment variables:

```env
# Worker Thread Pool Configuration
WORKER_MIN_THREADS=2
WORKER_MAX_THREADS=8
WORKER_ADAPTIVE_SCALING=true
WORKER_IDLE_TIMEOUT=60000
WORKER_TASK_TIMEOUT=30000
WORKER_HIGH_LOAD_THRESHOLD=0.7
WORKER_CRITICAL_LOAD_THRESHOLD=0.9
```

## Performance Considerations

### Thread Count

The optimal number of worker threads depends on your system's CPU cores:

- **Too Few Threads**: May not fully utilize available CPU resources
- **Too Many Threads**: May cause excessive context switching and resource contention

A good starting point is:
- `minThreads`: 25% of available CPU cores
- `maxThreads`: Number of CPU cores - 1

### Task Design

For optimal performance:

1. **Task Granularity**: Design tasks to be neither too small nor too large
2. **Data Transfer**: Minimize data transfer between main thread and workers
3. **Resource Usage**: Be mindful of memory usage in worker tasks
4. **Error Handling**: Implement proper error handling in tasks

### System Resources

Monitor system resources when using the worker thread pool:

- **CPU Usage**: Watch for high CPU utilization
- **Memory Usage**: Monitor memory consumption
- **I/O Operations**: Be careful with file and network operations in workers

## Troubleshooting

### High CPU Usage

If the worker thread pool is causing high CPU usage:

1. Reduce the maximum number of worker threads
2. Adjust the high load threshold to a lower value
3. Optimize worker tasks to be more efficient

### Memory Leaks

If you suspect memory leaks:

1. Check for resource cleanup in worker tasks
2. Reduce the maximum tasks per worker
3. Monitor memory usage over time

### Slow Task Execution

If tasks are executing slowly:

1. Check for bottlenecks in task implementation
2. Verify that tasks are properly designed for parallel execution
3. Monitor system resources during task execution

### Worker Crashes

If workers are crashing frequently:

1. Check for errors in task implementation
2. Verify that tasks are not exceeding available memory
3. Ensure proper error handling in tasks

## Examples

### Content Analysis Example

```javascript
const workerManager = require('./utils/worker-manager');

// Initialize worker manager
await workerManager.initialize();

// Analyze content
const result = await workerManager.analyzeContent('This is some text to analyze', {
  checkProfanity: true,
  checkToxicity: true,
  checkSensitiveData: true,
  checkSpam: true,
  sensitivityLevel: 'medium'
});

console.log('Analysis result:', result);
```

### Text Processing Example

```javascript
const workerManager = require('./utils/worker-manager');

// Initialize worker manager
await workerManager.initialize();

// Process text
const result = await workerManager.processText('This is some text to process', {
  tokenize: true,
  extractEntities: true,
  calculateStats: true,
  summarize: true,
  maxSummaryLength: 100
});

console.log('Processing result:', result);
```

### Data Validation Example

```javascript
const workerManager = require('./utils/worker-manager');

// Initialize worker manager
await workerManager.initialize();

// Define schema
const schema = {
  fields: {
    name: { type: 'string', required: true, minLength: 2 },
    age: { type: 'number', minimum: 0, maximum: 120 },
    email: { type: 'string', pattern: 'email' }
  },
  required: ['name', 'email']
};

// Data to validate
const data = {
  name: 'John Doe',
  age: 30,
  email: 'john.doe@example.com'
};

// Validate data
const validation = await workerManager.validateData(data, schema);

console.log('Validation result:', validation);
```

## Best Practices

1. **Initialize Early**: Initialize the worker thread pool early in your application lifecycle
2. **Proper Shutdown**: Always shut down the worker thread pool when your application exits
3. **Error Handling**: Implement proper error handling for task execution
4. **Resource Monitoring**: Monitor system resources and adjust configuration as needed
5. **Task Design**: Design tasks to be efficient and self-contained
6. **Priority Usage**: Use appropriate priority levels for different types of tasks
7. **Configuration Tuning**: Tune configuration parameters based on your specific workload
/**
 * Worker Manager - High-level API for the worker thread pool
 * Provides a simplified interface for executing CPU-intensive tasks
 */

const path = require('path');
const WorkerThreadPool = require('./worker-thread-pool');
const logger = require('./logger');

// Singleton instance
let workerPool = null;

/**
 * Initialize the worker manager
 * @param {Object} options - Configuration options
 * @returns {Promise<void>}
 */
async function initialize(options = {}) {
    if (workerPool) {
        logger.warn('Worker manager already initialized');
        return;
    }

    const defaultOptions = {
        minThreads: process.env.WORKER_MIN_THREADS ? parseInt(process.env.WORKER_MIN_THREADS, 10) : undefined,
        maxThreads: process.env.WORKER_MAX_THREADS ? parseInt(process.env.WORKER_MAX_THREADS, 10) : undefined,
        taskDirectory: path.join(__dirname, 'worker-tasks'),
        adaptiveScaling: true,
        warmupEnabled: true
    };

    // Merge options
    const mergedOptions = { ...defaultOptions, ...options };

    // Create worker pool
    workerPool = new WorkerThreadPool(mergedOptions);

    // Wait for pool to be ready
    await new Promise((resolve) => {
        workerPool.once('ready', resolve);
    });

    // Register built-in tasks
    registerBuiltInTasks();

    logger.info('Worker manager initialized', {
        minThreads: workerPool.config.minThreads,
        maxThreads: workerPool.config.maxThreads,
        adaptiveScaling: workerPool.config.adaptiveScaling
    });
}

/**
 * Register built-in worker tasks
 */
function registerBuiltInTasks() {
    // System info task is already registered in the worker pool

    // Register content analysis task
    workerPool.registerTask('content-analysis', path.join(__dirname, 'worker-tasks', 'content-analysis.js'));

    // Register text processing task
    workerPool.registerTask('text-processing', path.join(__dirname, 'worker-tasks', 'text-processing.js'));

    // Register image processing task
    workerPool.registerTask('image-processing', path.join(__dirname, 'worker-tasks', 'image-processing.js'));

    // Register data validation task
    workerPool.registerTask('data-validation', path.join(__dirname, 'worker-tasks', 'data-validation.js'));
}

/**
 * Register a custom worker task
 * @param {string} taskType - Task type identifier
 * @param {string} filePath - Path to the task implementation file
 */
function registerTask(taskType, filePath) {
    if (!workerPool) {
        throw new Error('Worker manager not initialized');
    }

    workerPool.registerTask(taskType, filePath);
    logger.debug('Custom task registered', { taskType, filePath });
}

/**
 * Execute a task in the worker pool
 * @param {string} taskType - Task type identifier
 * @param {Object} data - Task input data
 * @param {Object} options - Execution options
 * @returns {Promise<any>} Task result
 */
async function executeTask(taskType, data = {}, options = {}) {
    if (!workerPool) {
        throw new Error('Worker manager not initialized');
    }

    try {
        const startTime = Date.now();
        const result = await workerPool.executeTask(taskType, data, options);
        const duration = Date.now() - startTime;

        logger.debug('Task executed successfully', {
            taskType,
            duration: `${duration}ms`,
            priority: options.priority
        });

        return result;
    } catch (error) {
        logger.error('Task execution failed', {
            taskType,
            error: error.message,
            priority: options.priority
        });

        throw error;
    }
}

/**
 * Get worker pool statistics
 * @returns {Object} Worker pool statistics
 */
function getStats() {
    if (!workerPool) {
        return { initialized: false };
    }

    return workerPool.getStats();
}

/**
 * Shutdown the worker manager
 * @returns {Promise<void>}
 */
async function shutdown() {
    if (!workerPool) {
        logger.warn('Worker manager not initialized, nothing to shutdown');
        return;
    }

    logger.info('Shutting down worker manager');

    await workerPool.shutdown();
    workerPool = null;

    logger.info('Worker manager shutdown complete');
}

/**
 * Check if the worker manager is initialized
 * @returns {boolean} True if initialized
 */
function isInitialized() {
    return workerPool !== null;
}

/**
 * Get the number of active workers
 * @returns {number} Number of active workers
 */
function getWorkerCount() {
    if (!workerPool) {
        return 0;
    }

    const stats = workerPool.getStats();
    return stats.workers.total;
}

/**
 * Get the current worker pool load
 * @returns {number} Load between 0 and 1
 */
function getCurrentLoad() {
    if (!workerPool) {
        return 0;
    }

    const stats = workerPool.getStats();
    const loadStr = stats.workers.load;
    return parseFloat(loadStr) / 100;
}

/**
 * Execute a system info task
 * @returns {Promise<Object>} System information
 */
async function getSystemInfo() {
    return executeTask('system-info', {}, { priority: 0 });
}

/**
 * Execute a content analysis task with high priority
 * @param {string} content - Content to analyze
 * @param {Object} options - Analysis options
 * @returns {Promise<Object>} Analysis results
 */
async function analyzeContent(content, options = {}) {
    return executeTask('content-analysis', { content, options }, { priority: 0 });
}

/**
 * Execute a text processing task
 * @param {string} text - Text to process
 * @param {Object} options - Processing options
 * @returns {Promise<Object>} Processing results
 */
async function processText(text, options = {}) {
    return executeTask('text-processing', { text, options }, { priority: 1 });
}

/**
 * Execute a data validation task
 * @param {Object} data - Data to validate
 * @param {Object} schema - Validation schema
 * @returns {Promise<Object>} Validation results
 */
async function validateData(data, schema) {
    return executeTask('data-validation', { data, schema }, { priority: 1 });
}

module.exports = {
    initialize,
    registerTask,
    executeTask,
    getStats,
    shutdown,
    isInitialized,
    getWorkerCount,
    getCurrentLoad,
    getSystemInfo,
    analyzeContent,
    processText,
    validateData
};
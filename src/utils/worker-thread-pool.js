/**
 * Worker Thread Pool - Enterprise-grade thread pool for CPU-intensive operations
 * Implements an adaptive, self-tuning worker thread pool with intelligent work distribution
 */

const { Worker, isMainThread } = require('worker_threads');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const logger = require('./logger');

/**
 * WorkerThreadPool - Manages a pool of worker threads for CPU-intensive operations
 */
class WorkerThreadPool extends EventEmitter {
    constructor(options = {}) {
        super();

        // Configuration with sensible defaults
        this.config = {
            minThreads: options.minThreads || Math.max(1, Math.floor(os.cpus().length / 4)),
            maxThreads: options.maxThreads || Math.max(2, os.cpus().length - 1),
            idleTimeout: options.idleTimeout || 60000, // 1 minute
            maxTasksPerWorker: options.maxTasksPerWorker || 100,
            taskTimeout: options.taskTimeout || 30000, // 30 seconds
            monitorInterval: options.monitorInterval || 5000, // 5 seconds
            adaptiveScaling: options.adaptiveScaling !== false,
            highLoadThreshold: options.highLoadThreshold || 0.7,
            criticalLoadThreshold: options.criticalLoadThreshold || 0.9,
            taskDirectory: options.taskDirectory || path.join(__dirname, 'worker-tasks'),
            priorityLevels: options.priorityLevels || 3,
            statsInterval: options.statsInterval || 60000, // 1 minute
            errorThreshold: options.errorThreshold || 5,
            errorTimeWindow: options.errorTimeWindow || 60000, // 1 minute
            recoveryInterval: options.recoveryInterval || 5000, // 5 seconds
            warmupEnabled: options.warmupEnabled !== false,
            warmupTasks: options.warmupTasks || ['system-info']
        };

        // Validate configuration
        this.validateConfig();

        // Pool state
        this.workers = new Map(); // Map of worker ID to worker info
        this.availableWorkers = []; // Array of available worker IDs
        this.taskQueue = []; // Queue of pending tasks
        this.priorityQueues = new Map(); // Map of priority level to array of tasks
        this.activeTaskCount = 0;
        this.totalTasksProcessed = 0;
        this.totalTasksQueued = 0;
        this.totalTasksRejected = 0;
        this.totalErrors = 0;
        this.isShuttingDown = false;
        this.taskRegistry = new Map(); // Map of task types to file paths
        this.errorCounts = new Map(); // Map of worker IDs to error counts
        this.taskTimeouts = new Map(); // Map of task IDs to timeout handles

        // Initialize priority queues
        for (let i = 0; i < this.config.priorityLevels; i++) {
            this.priorityQueues.set(i, []);
        }

        // Performance metrics
        this.metrics = {
            avgProcessingTime: 0,
            processingTimes: [],
            maxProcessingTime: 0,
            queueWaitTimes: [],
            avgQueueWaitTime: 0,
            maxQueueWaitTime: 0,
            cpuUtilization: 0,
            lastCalculated: Date.now()
        };

        // Initialize the pool
        this.initialize();
    }

    /**
     * Validate the configuration
     */
    validateConfig() {
        // Ensure min threads is at least 1
        this.config.minThreads = Math.max(1, this.config.minThreads);

        // Ensure max threads is at least min threads
        this.config.maxThreads = Math.max(this.config.minThreads, this.config.maxThreads);

        // Ensure priority levels is at least 1
        this.config.priorityLevels = Math.max(1, this.config.priorityLevels);

        // Ensure timeouts are reasonable
        this.config.idleTimeout = Math.max(5000, this.config.idleTimeout);
        this.config.taskTimeout = Math.max(1000, this.config.taskTimeout);
        this.config.monitorInterval = Math.max(1000, this.config.monitorInterval);

        // Log the configuration
        logger.info('Worker thread pool configuration', {
            minThreads: this.config.minThreads,
            maxThreads: this.config.maxThreads,
            idleTimeout: this.config.idleTimeout,
            adaptiveScaling: this.config.adaptiveScaling,
            priorityLevels: this.config.priorityLevels
        });
    }

    /**
     * Initialize the worker thread pool
     */
    initialize() {
        if (!isMainThread) {
            throw new Error('WorkerThreadPool can only be initialized in the main thread');
        }

        // Register built-in tasks
        this.registerTask('system-info', path.join(__dirname, 'worker-tasks', 'system-info.js'));

        // Create initial workers
        for (let i = 0; i < this.config.minThreads; i++) {
            this.createWorker();
        }

        // Start the monitoring interval
        this.monitorInterval = setInterval(() => {
            this.monitorPool();
        }, this.config.monitorInterval);

        // Start the stats interval
        this.statsInterval = setInterval(() => {
            this.logStats();
        }, this.config.statsInterval);

        // Warm up the pool if enabled
        if (this.config.warmupEnabled) {
            this.warmup();
        }

        logger.info('Worker thread pool initialized', {
            initialWorkers: this.config.minThreads,
            maxWorkers: this.config.maxThreads
        });

        // Emit ready event
        this.emit('ready');
    }

    /**
     * Create a new worker
     */
    createWorker() {
        try {
            // Generate a unique worker ID
            const workerId = crypto.randomUUID();

            // Create the worker
            const worker = new Worker(path.join(__dirname, 'worker-thread-bootstrap.js'), {
                workerData: {
                    workerId,
                    taskDirectory: this.config.taskDirectory
                }
            });

            // Set up worker event handlers
            worker.on('message', (message) => {
                this.handleWorkerMessage(workerId, message);
            });

            worker.on('error', (error) => {
                this.handleWorkerError(workerId, error);
            });

            worker.on('exit', (code) => {
                this.handleWorkerExit(workerId, code);
            });

            // Store worker info
            this.workers.set(workerId, {
                worker,
                id: workerId,
                status: 'idle',
                currentTask: null,
                tasksProcessed: 0,
                errors: 0,
                createdAt: Date.now(),
                lastTaskFinishedAt: null,
                idleTimer: null,
                performance: {
                    avgProcessingTime: 0,
                    processingTimes: []
                }
            });

            // Add to available workers
            this.availableWorkers.push(workerId);

            logger.debug('Worker created', { workerId });

            // Process any pending tasks
            this.processNextTask();

            return workerId;
        } catch (error) {
            logger.error('Error creating worker', { error: error.message });
            return null;
        }
    }

    /**
     * Handle a message from a worker
     */
    handleWorkerMessage(workerId, message) {
        if (!message || typeof message !== 'object') {
            logger.warn('Invalid message from worker', { workerId });
            return;
        }

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            logger.warn('Message from unknown worker', { workerId });
            return;
        }

        switch (message.type) {
            case 'task_result':
                this.handleTaskResult(workerId, message);
                break;
            case 'task_error':
                this.handleTaskError(workerId, message);
                break;
            case 'worker_ready':
                logger.debug('Worker ready', { workerId });
                break;
            case 'worker_status':
                this.updateWorkerStatus(workerId, message.data);
                break;
            default:
                logger.warn('Unknown message type from worker', { workerId, type: message.type });
        }
    }

    /**
     * Handle a task result from a worker
     */
    handleTaskResult(workerId, message) {
        const { taskId, result, processingTime } = message;

        // Clear any task timeout
        if (this.taskTimeouts.has(taskId)) {
            clearTimeout(this.taskTimeouts.get(taskId));
            this.taskTimeouts.delete(taskId);
        }

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            logger.warn('Task result from unknown worker', { workerId, taskId });
            return;
        }

        // Update worker status
        workerInfo.status = 'idle';
        workerInfo.currentTask = null;
        workerInfo.tasksProcessed++;
        workerInfo.lastTaskFinishedAt = Date.now();

        // Update worker performance metrics
        workerInfo.performance.processingTimes.push(processingTime);
        if (workerInfo.performance.processingTimes.length > 100) {
            workerInfo.performance.processingTimes.shift();
        }
        workerInfo.performance.avgProcessingTime = workerInfo.performance.processingTimes.reduce((sum, time) => sum + time, 0) /
            workerInfo.performance.processingTimes.length;

        // Update global metrics
        this.metrics.processingTimes.push(processingTime);
        if (this.metrics.processingTimes.length > 1000) {
            this.metrics.processingTimes.shift();
        }
        this.metrics.avgProcessingTime = this.metrics.processingTimes.reduce((sum, time) => sum + time, 0) /
            this.metrics.processingTimes.length;
        this.metrics.maxProcessingTime = Math.max(this.metrics.maxProcessingTime, processingTime);

        // Decrement active task count
        this.activeTaskCount--;
        this.totalTasksProcessed++;

        // Add worker back to available pool
        this.availableWorkers.push(workerId);

        // Set idle timer
        workerInfo.idleTimer = setTimeout(() => {
            this.handleWorkerIdle(workerId);
        }, this.config.idleTimeout);

        // Find the task in the task registry
        const taskInfo = this.findTask(taskId);
        if (taskInfo) {
            // Resolve the task promise
            taskInfo.resolve(result);

            // Calculate queue wait time
            const queueWaitTime = taskInfo.startTime - taskInfo.queueTime;
            this.metrics.queueWaitTimes.push(queueWaitTime);
            if (this.metrics.queueWaitTimes.length > 1000) {
                this.metrics.queueWaitTimes.shift();
            }
            this.metrics.avgQueueWaitTime = this.metrics.queueWaitTimes.reduce((sum, time) => sum + time, 0) /
                this.metrics.queueWaitTimes.length;
            this.metrics.maxQueueWaitTime = Math.max(this.metrics.maxQueueWaitTime, queueWaitTime);
        }

        // Process next task
        this.processNextTask();
    }

    /**
     * Handle a task error from a worker
     */
    handleTaskError(workerId, message) {
        const { taskId, error } = message;

        // Clear any task timeout
        if (this.taskTimeouts.has(taskId)) {
            clearTimeout(this.taskTimeouts.get(taskId));
            this.taskTimeouts.delete(taskId);
        }

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            logger.warn('Task error from unknown worker', { workerId, taskId });
            return;
        }

        // Update worker status
        workerInfo.status = 'idle';
        workerInfo.currentTask = null;
        workerInfo.errors++;
        workerInfo.lastTaskFinishedAt = Date.now();

        // Increment error count
        this.totalErrors++;

        // Track worker errors for potential termination
        if (!this.errorCounts.has(workerId)) {
            this.errorCounts.set(workerId, {
                count: 0,
                firstErrorTime: Date.now()
            });
        }

        const errorInfo = this.errorCounts.get(workerId);
        errorInfo.count++;

        // Check if worker should be terminated due to errors
        if (errorInfo.count >= this.config.errorThreshold &&
            (Date.now() - errorInfo.firstErrorTime) <= this.config.errorTimeWindow) {
            logger.warn('Worker exceeded error threshold, terminating', {
                workerId,
                errorCount: errorInfo.count,
                timeWindow: Date.now() - errorInfo.firstErrorTime
            });

            this.terminateWorker(workerId);
        } else {
            // Reset error count if outside time window
            if ((Date.now() - errorInfo.firstErrorTime) > this.config.errorTimeWindow) {
                errorInfo.count = 1;
                errorInfo.firstErrorTime = Date.now();
            }

            // Add worker back to available pool
            this.availableWorkers.push(workerId);

            // Set idle timer
            workerInfo.idleTimer = setTimeout(() => {
                this.handleWorkerIdle(workerId);
            }, this.config.idleTimeout);
        }

        // Find the task in the task registry
        const taskInfo = this.findTask(taskId);
        if (taskInfo) {
            // Reject the task promise
            taskInfo.reject(new Error(error || 'Task failed'));
        }

        // Process next task
        this.processNextTask();
    }

    /**
     * Handle a worker error
     */
    handleWorkerError(workerId, error) {
        logger.error('Worker error', { workerId, error: error.message });

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            return;
        }

        // If worker has an active task, reject it
        if (workerInfo.currentTask) {
            const taskInfo = this.findTask(workerInfo.currentTask);
            if (taskInfo) {
                taskInfo.reject(new Error(`Worker error: ${error.message}`));
            }
        }

        // Terminate and replace the worker
        this.terminateWorker(workerId);
        this.createWorker();
    }

    /**
     * Handle a worker exit
     */
    handleWorkerExit(workerId, code) {
        logger.info('Worker exited', { workerId, code });

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            return;
        }

        // If worker has an active task, reject it
        if (workerInfo.currentTask) {
            const taskInfo = this.findTask(workerInfo.currentTask);
            if (taskInfo) {
                taskInfo.reject(new Error(`Worker exited with code ${code}`));
            }
        }

        // Remove worker from pool
        this.workers.delete(workerId);
        this.availableWorkers = this.availableWorkers.filter(id => id !== workerId);
        this.errorCounts.delete(workerId);

        // Create a replacement worker if not shutting down
        if (!this.isShuttingDown && this.workers.size < this.config.minThreads) {
            setTimeout(() => {
                this.createWorker();
            }, this.config.recoveryInterval);
        }
    }

    /**
     * Handle an idle worker
     */
    handleWorkerIdle(workerId) {
        const workerInfo = this.workers.get(workerId);
        if (!workerInfo || workerInfo.status !== 'idle') {
            return;
        }

        // Only terminate if we have more than minThreads workers
        if (this.workers.size > this.config.minThreads) {
            logger.debug('Terminating idle worker', { workerId });
            this.terminateWorker(workerId);
        }
    }

    /**
     * Terminate a worker
     */
    terminateWorker(workerId) {
        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            return;
        }

        // Clear idle timer if exists
        if (workerInfo.idleTimer) {
            clearTimeout(workerInfo.idleTimer);
        }

        // Remove from available workers
        this.availableWorkers = this.availableWorkers.filter(id => id !== workerId);

        // Terminate the worker
        try {
            workerInfo.worker.terminate();
        } catch (error) {
            logger.error('Error terminating worker', { workerId, error: error.message });
        }

        // Remove from workers map
        this.workers.delete(workerId);
    }

    /**
     * Update worker status
     */
    updateWorkerStatus(workerId, status) {
        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            return;
        }

        // Update worker status
        Object.assign(workerInfo, status);
    }

    /**
     * Register a task type
     */
    registerTask(taskType, filePath) {
        if (!taskType || !filePath) {
            throw new Error('Task type and file path are required');
        }

        // Validate file path
        try {
            // eslint-disable-next-line security/detect-non-literal-fs-filename
            require.resolve(filePath);
        } catch (error) {
            throw new Error(`Task file not found: ${filePath}`);
        }

        this.taskRegistry.set(taskType, filePath);
        logger.debug('Task registered', { taskType, filePath });
    }

    /**
     * Execute a task
     */
    executeTask(taskType, data = {}, options = {}) {
        return new Promise((resolve, reject) => {
            if (this.isShuttingDown) {
                reject(new Error('Worker pool is shutting down'));
                return;
            }

            // Validate task type
            if (!this.taskRegistry.has(taskType)) {
                reject(new Error(`Unknown task type: ${taskType}`));
                return;
            }

            // Generate task ID
            const taskId = crypto.randomUUID();

            // Determine priority (0 is highest, config.priorityLevels-1 is lowest)
            const priority = typeof options.priority === 'number' ?
                Math.max(0, Math.min(this.config.priorityLevels - 1, options.priority)) :
                this.config.priorityLevels - 1;

            // Create task info
            const taskInfo = {
                id: taskId,
                type: taskType,
                data,
                priority,
                resolve,
                reject,
                queueTime: Date.now(),
                startTime: null,
                timeout: options.timeout || this.config.taskTimeout
            };

            // Add to appropriate priority queue
            const queue = this.priorityQueues.get(priority) || [];
            queue.push(taskInfo);
            this.priorityQueues.set(priority, queue);
            this.totalTasksQueued++;

            // Process next task if workers are available
            this.processNextTask();
        });
    }

    /**
     * Process the next task in the queue
     */
    processNextTask() {
        // If no available workers, return
        if (this.availableWorkers.length === 0) {
            return;
        }

        // Find the highest priority non-empty queue
        let nextTask = null;
        let priorityQueue = null;

        for (let i = 0; i < this.config.priorityLevels; i++) {
            const queue = this.priorityQueues.get(i) || [];
            if (queue.length > 0) {
                nextTask = queue.shift();
                priorityQueue = i;
                break;
            }
        }

        // If no tasks in any queue, return
        if (!nextTask) {
            return;
        }

        // Get next available worker
        const workerId = this.availableWorkers.shift();
        const workerInfo = this.workers.get(workerId);

        if (!workerInfo) {
            // Worker no longer exists, requeue task and try again
            const queue = this.priorityQueues.get(priorityQueue) || [];
            queue.unshift(nextTask);
            this.priorityQueues.set(priorityQueue, queue);
            this.processNextTask();
            return;
        }

        // Clear idle timer if exists
        if (workerInfo.idleTimer) {
            clearTimeout(workerInfo.idleTimer);
            workerInfo.idleTimer = null;
        }

        // Update worker status
        workerInfo.status = 'busy';
        workerInfo.currentTask = nextTask.id;

        // Update task info
        nextTask.startTime = Date.now();

        // Set task timeout
        const timeoutHandle = setTimeout(() => {
            this.handleTaskTimeout(workerId, nextTask.id);
        }, nextTask.timeout);

        this.taskTimeouts.set(nextTask.id, timeoutHandle);

        // Increment active task count
        this.activeTaskCount++;

        // Send task to worker
        try {
            workerInfo.worker.postMessage({
                type: 'execute_task',
                taskId: nextTask.id,
                taskType: nextTask.type,
                data: nextTask.data
            });
        } catch (error) {
            // Handle error sending message to worker
            logger.error('Error sending task to worker', { workerId, taskId: nextTask.id, error: error.message });

            // Requeue task
            const queue = this.priorityQueues.get(priorityQueue) || [];
            queue.unshift(nextTask);
            this.priorityQueues.set(priorityQueue, queue);

            // Terminate and replace worker
            this.terminateWorker(workerId);
            this.createWorker();

            // Try processing next task
            this.processNextTask();
        }
    }

    /**
     * Handle a task timeout
     */
    handleTaskTimeout(workerId, taskId) {
        logger.warn('Task timed out', { workerId, taskId });

        const workerInfo = this.workers.get(workerId);
        if (!workerInfo) {
            return;
        }

        // Find the task
        const taskInfo = this.findTask(taskId);
        if (taskInfo) {
            // Reject the task promise
            taskInfo.reject(new Error('Task timed out'));
        }

        // Terminate and replace the worker
        this.terminateWorker(workerId);
        this.createWorker();

        // Process next task
        this.processNextTask();
    }

    /**
     * Find a task by ID
     */
    findTask(taskId) {
        // Check all priority queues
        for (const [_, queue] of this.priorityQueues.entries()) {
            // Use find instead of findIndex and direct array access
            const task = queue.find(task => task.id === taskId);
            if (task) {
                return task;
            }
        }

        return null;
    }

    /**
     * Monitor the worker pool
     */
    monitorPool() {
        if (this.isShuttingDown) {
            return;
        }

        // Calculate current load
        const currentLoad = this.calculateLoad();

        // Update CPU utilization metric
        this.updateCpuUtilization();

        // Scale workers based on load if adaptive scaling is enabled
        if (this.config.adaptiveScaling) {
            this.scaleWorkers(currentLoad);
        }

        // Process any pending tasks
        this.processNextTask();
    }

    /**
     * Calculate the current load of the pool
     */
    calculateLoad() {
        const totalWorkers = this.workers.size;
        if (totalWorkers === 0) {
            return 0;
        }

        const busyWorkers = totalWorkers - this.availableWorkers.length;
        return busyWorkers / totalWorkers;
    }

    /**
     * Update CPU utilization metric
     */
    updateCpuUtilization() {
        try {
            const cpus = os.cpus();
            let totalIdle = 0;
            let totalTick = 0;

            for (const cpu of cpus) {
                const times = cpu.times;

                // Safely access properties
                totalIdle += times.idle || 0;
                totalTick += (times.user || 0) + (times.nice || 0) +
                    (times.sys || 0) + (times.idle || 0) +
                    (times.irq || 0);
            }

            const idle = totalIdle / cpus.length;
            const total = totalTick / cpus.length;
            const utilization = 1 - (idle / total);

            this.metrics.cpuUtilization = utilization;
        } catch (error) {
            logger.error('Error calculating CPU utilization', { error: error.message });
        }
    }

    /**
     * Scale workers based on load
     */
    scaleWorkers(currentLoad) {
        // If load is above critical threshold, scale up to max
        if (currentLoad >= this.config.criticalLoadThreshold) {
            const workersToAdd = this.config.maxThreads - this.workers.size;

            if (workersToAdd > 0) {
                logger.info('Scaling up workers due to critical load', {
                    currentLoad,
                    currentWorkers: this.workers.size,
                    targetWorkers: this.config.maxThreads
                });

                for (let i = 0; i < workersToAdd; i++) {
                    this.createWorker();
                }
            }
        }
        // If load is above high threshold, scale up incrementally
        else if (currentLoad >= this.config.highLoadThreshold) {
            const targetWorkers = Math.min(
                this.config.maxThreads,
                Math.ceil(this.workers.size * 1.5)
            );

            const workersToAdd = targetWorkers - this.workers.size;

            if (workersToAdd > 0) {
                logger.info('Scaling up workers due to high load', {
                    currentLoad,
                    currentWorkers: this.workers.size,
                    targetWorkers
                });

                for (let i = 0; i < workersToAdd; i++) {
                    this.createWorker();
                }
            }
        }
        // If load is very low and we have more than min workers, scale down
        else if (currentLoad < 0.3 && this.workers.size > this.config.minThreads) {
            const targetWorkers = Math.max(
                this.config.minThreads,
                Math.floor(this.workers.size * 0.75)
            );

            const workersToRemove = this.workers.size - targetWorkers;

            if (workersToRemove > 0) {
                logger.info('Scaling down workers due to low load', {
                    currentLoad,
                    currentWorkers: this.workers.size,
                    targetWorkers
                });

                // Find idle workers to terminate
                const idleWorkers = Array.from(this.workers.entries())
                    .filter(([_, info]) => info.status === 'idle')
                    .map(([id]) => id)
                    .slice(0, workersToRemove);

                for (const workerId of idleWorkers) {
                    this.terminateWorker(workerId);
                }
            }
        }
    }

    /**
     * Warm up the worker pool
     */
    warmup() {
        logger.info('Warming up worker pool');

        // Execute warmup tasks
        for (const taskType of this.config.warmupTasks) {
            if (this.taskRegistry.has(taskType)) {
                for (let i = 0; i < this.workers.size; i++) {
                    this.executeTask(taskType, { warmup: true }, { priority: 0 })
                        .catch(error => {
                            logger.warn('Warmup task error', { taskType, error: error.message });
                        });
                }
            }
        }
    }

    /**
     * Log pool statistics
     */
    logStats() {
        if (this.isShuttingDown) {
            return;
        }

        const stats = this.getStats();

        logger.info('Worker pool stats', stats);
    }

    /**
     * Get pool statistics
     */
    getStats() {
        const totalWorkers = this.workers.size;
        const busyWorkers = totalWorkers - this.availableWorkers.length;
        const currentLoad = this.calculateLoad();

        // Calculate total queue depth
        let queueDepth = 0;
        for (const [_, queue] of this.priorityQueues.entries()) {
            queueDepth += queue.length;
        }

        return {
            workers: {
                total: totalWorkers,
                busy: busyWorkers,
                idle: this.availableWorkers.length,
                load: `${(currentLoad * 100).toFixed(2)}%`
            },
            tasks: {
                active: this.activeTaskCount,
                processed: this.totalTasksProcessed,
                queued: this.totalTasksQueued,
                rejected: this.totalTasksRejected,
                errors: this.totalErrors,
                queueDepth
            },
            performance: {
                avgProcessingTime: `${this.metrics.avgProcessingTime.toFixed(2)}ms`,
                maxProcessingTime: `${this.metrics.maxProcessingTime.toFixed(2)}ms`,
                avgQueueWaitTime: `${this.metrics.avgQueueWaitTime.toFixed(2)}ms`,
                maxQueueWaitTime: `${this.metrics.maxQueueWaitTime.toFixed(2)}ms`,
                cpuUtilization: `${(this.metrics.cpuUtilization * 100).toFixed(2)}%`
            },
            config: {
                minThreads: this.config.minThreads,
                maxThreads: this.config.maxThreads,
                adaptiveScaling: this.config.adaptiveScaling
            }
        };
    }

    /**
     * Shutdown the worker pool
     */
    async shutdown() {
        if (this.isShuttingDown) {
            return;
        }

        logger.info('Shutting down worker pool');

        this.isShuttingDown = true;

        // Clear intervals
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
        }

        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }

        // Clear all task timeouts
        for (const timeoutHandle of this.taskTimeouts.values()) {
            clearTimeout(timeoutHandle);
        }
        this.taskTimeouts.clear();

        // Reject all pending tasks
        for (const [_, queue] of this.priorityQueues.entries()) {
            for (const task of queue) {
                task.reject(new Error('Worker pool is shutting down'));
            }
            queue.length = 0;
        }

        // Terminate all workers
        const workerIds = Array.from(this.workers.keys());
        for (const workerId of workerIds) {
            this.terminateWorker(workerId);
        }

        // Log final stats
        this.logStats();

        logger.info('Worker pool shutdown complete');

        // Emit shutdown event
        this.emit('shutdown');
    }
}

module.exports = WorkerThreadPool;
/**
 * Worker Thread Bootstrap - Entry point for worker threads
 * Handles communication with the main thread and loads task modules
 */

const { parentPort, workerData } = require('worker_threads');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

// Worker state
const state = {
    workerId: workerData?.workerId || crypto.randomUUID(),
    taskDirectory: workerData?.taskDirectory || path.join(__dirname, 'worker-tasks'),
    taskModules: new Map(),
    activeTask: null,
    tasksProcessed: 0,
    errors: 0,
    startTime: Date.now(),
    lastTaskFinishedAt: null,
    systemInfo: null
};

/**
 * Initialize the worker
 */
function initialize() {
    if (!parentPort) {
        console.error('Worker bootstrap must be run in a worker thread');
        process.exit(1);
    }

    // Set up message handler
    parentPort.on('message', handleMessage);

    // Collect system information
    collectSystemInfo();

    // Notify main thread that worker is ready
    parentPort.postMessage({
        type: 'worker_ready',
        workerId: state.workerId
    });

    // Send initial status
    sendStatus();

    // Set up periodic status updates
    setInterval(() => {
        sendStatus();
    }, 30000); // Every 30 seconds
}

/**
 * Handle a message from the main thread
 */
function handleMessage(message) {
    if (!message || typeof message !== 'object') {
        sendError(null, 'Invalid message format');
        return;
    }

    switch (message.type) {
        case 'execute_task':
            executeTask(message);
            break;
        case 'status_request':
            sendStatus();
            break;
        case 'terminate':
            cleanupAndExit();
            break;
        default:
            sendError(message.taskId, `Unknown message type: ${message.type}`);
    }
}

/**
 * Execute a task
 */
async function executeTask(message) {
    const { taskId, taskType, data } = message;

    if (!taskId || !taskType) {
        sendError(taskId, 'Task ID and type are required');
        return;
    }

    // Set active task
    state.activeTask = {
        id: taskId,
        type: taskType,
        startTime: Date.now()
    };

    try {
        // Load task module if not already loaded
        if (!state.taskModules.has(taskType)) {
            await loadTaskModule(taskType);
        }

        const taskModule = state.taskModules.get(taskType);
        if (!taskModule || typeof taskModule.execute !== 'function') {
            throw new Error(`Invalid task module for type: ${taskType}`);
        }

        // Execute the task and measure performance
        const startTime = process.hrtime.bigint();
        const result = await taskModule.execute(data, { workerId: state.workerId });
        const endTime = process.hrtime.bigint();
        const processingTime = Number(endTime - startTime) / 1_000_000; // Convert to ms

        // Update state
        state.tasksProcessed++;
        state.lastTaskFinishedAt = Date.now();
        state.activeTask = null;

        // Send result back to main thread
        parentPort.postMessage({
            type: 'task_result',
            taskId,
            result,
            processingTime
        });
    } catch (error) {
        // Update error count
        state.errors++;
        state.activeTask = null;

        // Send error back to main thread
        sendError(taskId, error.message || 'Task execution failed');
    }
}

/**
 * Load a task module
 */
async function loadTaskModule(taskType) {
    try {
        // Validate task type to prevent path traversal
        if (!taskType || /[^a-zA-Z0-9_-]/.test(taskType)) {
            throw new Error(`Invalid task type: ${taskType}`);
        }

        // Construct the module path
        const modulePath = path.join(state.taskDirectory, `${taskType}.js`);

        // Check if file exists
        try {
            // eslint-disable-next-line security/detect-non-literal-fs-filename
            await fs.promises.access(modulePath, fs.constants.R_OK);
        } catch (error) {
            throw new Error(`Task module not found: ${modulePath}`);
        }

        // Load the module
        // eslint-disable-next-line security/detect-non-literal-require
        const taskModule = require(modulePath);

        // Validate module interface
        if (typeof taskModule.execute !== 'function') {
            throw new Error(`Task module must export an execute function: ${taskType}`);
        }

        // Store the module
        state.taskModules.set(taskType, taskModule);
    } catch (error) {
        throw new Error(`Failed to load task module ${taskType}: ${error.message}`);
    }
}

/**
 * Send an error message to the main thread
 */
function sendError(taskId, errorMessage) {
    if (parentPort) {
        parentPort.postMessage({
            type: 'task_error',
            taskId,
            error: errorMessage
        });
    }
}

/**
 * Send worker status to the main thread
 */
function sendStatus() {
    if (parentPort) {
        parentPort.postMessage({
            type: 'worker_status',
            data: {
                workerId: state.workerId,
                status: state.activeTask ? 'busy' : 'idle',
                currentTask: state.activeTask,
                tasksProcessed: state.tasksProcessed,
                errors: state.errors,
                uptime: Date.now() - state.startTime,
                lastTaskFinishedAt: state.lastTaskFinishedAt,
                systemInfo: state.systemInfo
            }
        });
    }
}

/**
 * Collect system information
 */
function collectSystemInfo() {
    try {
        const cpus = os.cpus();
        const totalMemory = os.totalmem();
        const freeMemory = os.freemem();

        state.systemInfo = {
            platform: os.platform(),
            arch: os.arch(),
            cpus: {
                model: cpus.length > 0 ? cpus[0].model : 'Unknown',
                count: cpus.length,
                speed: cpus.length > 0 ? cpus[0].speed : 0
            },
            memory: {
                total: totalMemory,
                free: freeMemory,
                usage: ((totalMemory - freeMemory) / totalMemory * 100).toFixed(2) + '%'
            },
            loadAvg: os.loadavg()
        };
    } catch (error) {
        console.error('Error collecting system info:', error);
    }
}

/**
 * Clean up resources and exit
 */
function cleanupAndExit() {
    // Perform any necessary cleanup

    // Exit the worker thread
    process.exit(0);
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught exception in worker:', error);

    // Send error to main thread if we have an active task
    if (state.activeTask) {
        sendError(state.activeTask.id, `Uncaught exception: ${error.message}`);
        state.activeTask = null;
    }

    // Send updated status
    sendStatus();
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason) => {
    const error = reason instanceof Error ? reason : new Error(String(reason));
    console.error('Unhandled rejection in worker:', error);

    // Send error to main thread if we have an active task
    if (state.activeTask) {
        sendError(state.activeTask.id, `Unhandled rejection: ${error.message}`);
        state.activeTask = null;
    }

    // Send updated status
    sendStatus();
});

// Initialize the worker
initialize();
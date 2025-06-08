/**
 * System Info Worker Task
 * Returns detailed system information for monitoring and diagnostics
 */

const os = require('os');
const v8 = require('v8');
const process = require('process');

/**
 * Execute the system info task
 * @param {Object} data - Task input data
 * @param {Object} context - Execution context
 * @returns {Object} System information
 */
async function execute(_data = {}, context = {}) {
    try {
        // Get CPU information
        const cpus = os.cpus();
        const cpuInfo = {
            model: cpus.length > 0 ? cpus[0].model : 'Unknown',
            cores: cpus.length,
            speed: cpus.length > 0 ? `${cpus[0].speed} MHz` : 'Unknown',
            loadAvg: os.loadavg().map(load => load.toFixed(2)),
            architecture: os.arch()
        };

        // Get memory information
        const totalMemory = os.totalmem();
        const freeMemory = os.freemem();
        const usedMemory = totalMemory - freeMemory;
        const memoryInfo = {
            total: formatBytes(totalMemory),
            free: formatBytes(freeMemory),
            used: formatBytes(usedMemory),
            usagePercentage: ((usedMemory / totalMemory) * 100).toFixed(2) + '%'
        };

        // Get V8 heap statistics
        const heapStats = v8.getHeapStatistics();
        const heapInfo = {
            totalHeapSize: formatBytes(heapStats.total_heap_size),
            totalHeapSizeExecutable: formatBytes(heapStats.total_heap_size_executable),
            totalPhysicalSize: formatBytes(heapStats.total_physical_size),
            totalAvailableSize: formatBytes(heapStats.total_available_size),
            usedHeapSize: formatBytes(heapStats.used_heap_size),
            heapSizeLimit: formatBytes(heapStats.heap_size_limit),
            mallocedMemory: formatBytes(heapStats.malloced_memory),
            peakMallocedMemory: formatBytes(heapStats.peak_malloced_memory)
        };

        // Get process information
        const processInfo = {
            pid: process.pid,
            uptime: formatTime(process.uptime()),
            title: process.title,
            nodeVersion: process.version,
            memoryUsage: {
                rss: formatBytes(process.memoryUsage().rss),
                heapTotal: formatBytes(process.memoryUsage().heapTotal),
                heapUsed: formatBytes(process.memoryUsage().heapUsed),
                external: formatBytes(process.memoryUsage().external),
                arrayBuffers: formatBytes(process.memoryUsage().arrayBuffers || 0)
            },
            cpuUsage: process.cpuUsage()
        };

        // Get OS information
        const osInfo = {
            platform: os.platform(),
            type: os.type(),
            release: os.release(),
            hostname: os.hostname(),
            uptime: formatTime(os.uptime()),
            userInfo: safeUserInfo(),
            networkInterfaces: safeNetworkInfo()
        };

        // Combine all information
        return {
            timestamp: new Date().toISOString(),
            cpu: cpuInfo,
            memory: memoryInfo,
            heap: heapInfo,
            process: processInfo,
            os: osInfo,
            workerId: context.workerId || 'unknown'
        };
    } catch (error) {
        console.error('Error in system-info task:', error);
        throw new Error(`Failed to collect system information: ${error.message}`);
    }
}

/**
 * Format bytes to a human-readable string
 * @param {number} bytes - Bytes to format
 * @returns {string} Formatted string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;

    // Use a switch statement instead of array access
    let unit = 'Bytes';
    let value = bytes;

    if (bytes >= k) {
        value = bytes / k;
        unit = 'KB';

        if (value >= k) {
            value = value / k;
            unit = 'MB';

            if (value >= k) {
                value = value / k;
                unit = 'GB';

                if (value >= k) {
                    value = value / k;
                    unit = 'TB';

                    if (value >= k) {
                        value = value / k;
                        unit = 'PB';
                    }
                }
            }
        }
    }

    return parseFloat(value.toFixed(2)) + ' ' + unit;
}

/**
 * Format time in seconds to a human-readable string
 * @param {number} seconds - Seconds to format
 * @returns {string} Formatted string
 */
function formatTime(seconds) {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (remainingSeconds > 0 || parts.length === 0) parts.push(`${remainingSeconds}s`);

    return parts.join(' ');
}

/**
 * Get safe user info (without sensitive data)
 * @returns {Object} Safe user info
 */
function safeUserInfo() {
    try {
        const userInfo = os.userInfo();
        return {
            username: userInfo.username,
            uid: userInfo.uid,
            gid: userInfo.gid,
            shell: userInfo.shell,
            homedir: '[REDACTED]' // Redact home directory for security
        };
    } catch (error) {
        return { error: 'Unable to retrieve user info' };
    }
}

/**
 * Get safe network interface info (without MAC addresses)
 * @returns {Object} Safe network interface info
 */
function safeNetworkInfo() {
    try {
        const interfaces = os.networkInterfaces();
        const safeInterfaces = {};

        // Use a safer approach to build the object
        Object.entries(interfaces).forEach(([name, netInterface]) => {
            // Create a new property using a validated key
            Object.defineProperty(safeInterfaces, name, {
                value: netInterface.map(iface => ({
                    address: iface.address,
                    netmask: iface.netmask,
                    family: iface.family,
                    internal: iface.internal,
                    cidr: iface.cidr,
                    mac: '[REDACTED]' // Redact MAC address for security
                })),
                enumerable: true,
                configurable: true,
                writable: true
            });
        });

        return safeInterfaces;
    } catch (error) {
        return { error: 'Unable to retrieve network info' };
    }
}

module.exports = { execute };
/**
 * Message Queue System for async processing
 * Uses Bull queue with Redis for high-throughput message processing
 */

const Bull = require('bull');
const logger = require('./logger');
const { performance } = require('perf_hooks');

class MessageQueue {
    constructor(options = {}) {
        this.config = {
            redis: options.redis || {
                port: process.env.REDIS_PORT || 6379,
                host: process.env.REDIS_HOST || 'localhost',
                password: process.env.REDIS_PASSWORD || undefined,
                db: process.env.REDIS_DB || 0
            },
            defaultJobOptions: {
                removeOnComplete: 100,
                removeOnFail: 1000,
                attempts: options.attempts || 3,
                backoff: {
                    type: 'exponential',
                    delay: 2000
                }
            },
            concurrency: options.concurrency || 10,
            batchSize: options.batchSize || 50,
            flushInterval: options.flushInterval || 100
        };

        this.queues = new Map();
        this.processors = new Map();
        this.metrics = {
            processed: 0,
            failed: 0,
            retried: 0,
            batched: 0
        };

        this.batchBuffer = new Map();
        this.batchTimers = new Map();

        this.initializeQueues();
    }

    /**
     * Initialize different priority queues
     */
    initializeQueues() {
        const priorities = ['high', 'normal', 'low'];

        for (const priority of priorities) {
            const queue = new Bull(`message-processing-${priority}`, {
                redis: this.config.redis,
                defaultJobOptions: this.config.defaultJobOptions
            });

            // Set up event handlers
            queue.on('completed', (job, result) => {
                this.metrics.processed++;
                logger.debug(`Job ${job.id} completed in ${priority} queue`);
            });

            queue.on('failed', (job, err) => {
                this.metrics.failed++;
                logger.error(`Job ${job.id} failed in ${priority} queue:`, err);
            });

            queue.on('stalled', (job) => {
                logger.warn(`Job ${job.id} stalled in ${priority} queue`);
            });

            this.queues.set(priority, queue);
        }
    }

    /**
     * Add message to queue with priority
     */
    async addMessage(messageData, options = {}) {
        const priority = options.priority || 'normal';
        const queue = this.queues.get(priority);

        if (!queue) {
            throw new Error(`Invalid priority: ${priority}`);
        }

        // Extract key fields for deduplication
        const dedupKey = this.generateDedupKey(messageData);

        // Check if similar message is already queued
        if (await this.isDuplicate(dedupKey)) {
            logger.debug('Duplicate message detected, skipping queue');
            return null;
        }

        // Add to batch buffer if batching is enabled
        if (options.batch && this.shouldBatch(messageData)) {
            return this.addToBatch(messageData, priority);
        }

        // Add directly to queue
        const job = await queue.add('process-message', {
            ...messageData,
            queuedAt: Date.now(),
            priority
        }, {
            delay: options.delay || 0,
            priority: this.getPriorityValue(priority),
            jobId: dedupKey
        });

        return job;
    }

    /**
     * Add message to batch buffer
     */
    async addToBatch(messageData, priority) {
        const batchKey = `${priority}:${messageData.serverId}`;

        if (!this.batchBuffer.has(batchKey)) {
            this.batchBuffer.set(batchKey, []);

            // Set flush timer
            const timer = setTimeout(() => {
                this.flushBatch(batchKey);
            }, this.config.flushInterval);

            this.batchTimers.set(batchKey, timer);
        }

        const batch = this.batchBuffer.get(batchKey);
        batch.push(messageData);

        // Flush if batch is full
        if (batch.length >= this.config.batchSize) {
            await this.flushBatch(batchKey);
        }

        return { batched: true, batchKey };
    }

    /**
     * Flush batch to queue
     */
    async flushBatch(batchKey) {
        const batch = this.batchBuffer.get(batchKey);
        if (!batch || batch.length === 0) return;

        const [priority, serverId] = batchKey.split(':');
        const queue = this.queues.get(priority);

        // Clear timer
        if (this.batchTimers.has(batchKey)) {
            clearTimeout(this.batchTimers.get(batchKey));
            this.batchTimers.delete(batchKey);
        }

        // Create batch job
        const job = await queue.add('process-batch', {
            messages: batch,
            serverId,
            batchSize: batch.length,
            queuedAt: Date.now(),
            priority
        }, {
            priority: this.getPriorityValue(priority)
        });

        this.metrics.batched += batch.length;

        // Clear batch buffer
        this.batchBuffer.delete(batchKey);

        logger.debug(`Flushed batch of ${batch.length} messages for ${batchKey}`);
        return job;
    }

    /**
     * Register message processor
     */
    registerProcessor(priority, processor) {
        const queue = this.queues.get(priority);
        if (!queue) {
            throw new Error(`Invalid priority: ${priority}`);
        }

        // Process individual messages
        queue.process('process-message', this.config.concurrency, async (job) => {
            const startTime = performance.now();

            try {
                const result = await processor(job.data);

                const processingTime = performance.now() - startTime;
                logger.debug(`Processed message in ${processingTime.toFixed(2)}ms`);

                return result;
            } catch (error) {
                logger.error('Message processing error:', error);
                throw error;
            }
        });

        // Process batches
        queue.process('process-batch', Math.ceil(this.config.concurrency / 2), async (job) => {
            const startTime = performance.now();
            const { messages } = job.data;

            try {
                // Process messages in parallel with concurrency limit
                const results = await this.processInParallel(messages, processor, 5);

                const processingTime = performance.now() - startTime;
                logger.debug(`Processed batch of ${messages.length} in ${processingTime.toFixed(2)}ms`);

                return results;
            } catch (error) {
                logger.error('Batch processing error:', error);
                throw error;
            }
        });

        this.processors.set(priority, processor);
    }

    /**
     * Process messages in parallel with concurrency limit
     */
    async processInParallel(messages, processor, concurrency) {
        const results = [];
        const executing = [];

        for (const message of messages) {
            const promise = processor(message).then(result => {
                results.push(result);
            });

            if (messages.length >= concurrency) {
                executing.push(promise);

                if (executing.length >= concurrency) {
                    await Promise.race(executing);
                    executing.splice(executing.findIndex(p => p === promise), 1);
                }
            }
        }

        await Promise.all(executing);
        return results;
    }

    /**
     * Check if message is duplicate
     */
    async isDuplicate(dedupKey) {
        // Check across all queues
        for (const [priority, queue] of this.queues) {
            const job = await queue.getJob(dedupKey);
            if (job && ['waiting', 'active', 'delayed'].includes(await job.getState())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate deduplication key
     */
    generateDedupKey(messageData) {
        return `${messageData.messageId}:${messageData.serverId}:${messageData.channelId}`;
    }

    /**
     * Determine if message should be batched
     */
    shouldBatch(messageData) {
        // Don't batch high-risk content
        if (messageData.riskLevel === 'high') return false;

        // Don't batch if content is too long
        if (messageData.content && messageData.content.length > 1000) return false;

        return true;
    }

    /**
     * Get numeric priority value
     */
    getPriorityValue(priority) {
        const values = {
            high: 1,
            normal: 5,
            low: 10
        };
        return values[priority] || 5;
    }

    /**
     * Get queue statistics
     */
    async getStats() {
        const stats = {
            metrics: this.metrics,
            queues: {},
            batches: {
                active: this.batchBuffer.size,
                buffered: 0
            }
        };

        // Get queue stats
        for (const [priority, queue] of this.queues) {
            const counts = await queue.getJobCounts();
            stats.queues[priority] = counts;
        }

        // Count buffered messages
        for (const batch of this.batchBuffer.values()) {
            stats.batches.buffered += batch.length;
        }

        return stats;
    }

    /**
     * Pause all queues
     */
    async pause() {
        const promises = [];
        for (const queue of this.queues.values()) {
            promises.push(queue.pause());
        }
        await Promise.all(promises);
        logger.info('All message queues paused');
    }

    /**
     * Resume all queues
     */
    async resume() {
        const promises = [];
        for (const queue of this.queues.values()) {
            promises.push(queue.resume());
        }
        await Promise.all(promises);
        logger.info('All message queues resumed');
    }

    /**
     * Clean up completed jobs
     */
    async clean(grace = 3600000) { // 1 hour default
        const promises = [];
        for (const queue of this.queues.values()) {
            promises.push(queue.clean(grace, 'completed'));
            promises.push(queue.clean(grace * 24, 'failed')); // Keep failed jobs longer
        }
        await Promise.all(promises);
        logger.info('Cleaned up old jobs from queues');
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        logger.info('Shutting down message queues...');

        // Flush all batches
        for (const batchKey of this.batchBuffer.keys()) {
            await this.flushBatch(batchKey);
        }

        // Close all queues
        const promises = [];
        for (const queue of this.queues.values()) {
            promises.push(queue.close());
        }
        await Promise.all(promises);

        logger.info('Message queues shut down');
    }
}

// Factory function for creating queue with moderation processor
function createModerationQueue(options = {}) {
    const queue = new MessageQueue(options);

    // Register processors for each priority
    const priorities = ['high', 'normal', 'low'];

    for (const priority of priorities) {
        queue.registerProcessor(priority, async (messageData) => {
            // This will be implemented to call the actual moderation logic
            const { processMessage } = require('../moderator');

            // Create a mock message object that matches Discord.js structure
            const mockMessage = {
                id: messageData.messageId,
                content: messageData.content,
                author: { id: messageData.authorId, bot: false },
                guild: { id: messageData.serverId },
                channel: { id: messageData.channelId },
                createdTimestamp: messageData.timestamp || Date.now()
            };

            // Process the message
            await processMessage(mockMessage);

            return { processed: true, messageId: messageData.messageId };
        });
    }

    return queue;
}

module.exports = {
    MessageQueue,
    createModerationQueue
};
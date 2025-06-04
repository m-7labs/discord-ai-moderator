const { describe, it, beforeEach, afterEach } = require('jest');
const errorManager = require('../src/utils/errorManager');
const logger = require('../src/utils/logger');

// Mock the logger
jest.mock('../src/utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn()
}));

describe('ErrorManager', () => {
  // Reset mocks between tests
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset error manager state
    errorManager.metrics = {
      errors: {},
      totalOperations: 0,
      startTime: Date.now()
    };
    
    errorManager.serviceStatus = {
      discord: { healthy: true, lastCheck: Date.now(), failures: 0 },
      anthropic: { healthy: true, lastCheck: Date.now(), failures: 0 },
      database: { healthy: true, lastCheck: Date.now(), failures: 0 }
    };
    
    errorManager.degradedMode = false;
  });

  describe('handleError', () => {
    it('should log the error and track metrics', async () => {
      const error = new Error('Test error');
      const source = 'test';
      const context = { operation: 'testing' };
      
      await errorManager.handleError(error, source, context);
      
      // Check that error was logged
      expect(logger.error).toHaveBeenCalled();
      
      // Check that metrics were tracked
      expect(errorManager.metrics.errors[source]).toBeDefined();
      expect(errorManager.metrics.errors[source].count).toBe(1);
    });
    
    it('should apply the correct recovery strategy', async () => {
      // Create a test error that should trigger a retry strategy
      const error = new Error('Connection refused');
      error.code = 'ECONNREFUSED';
      
      const source = 'database';
      const retryFunction = jest.fn().mockResolvedValue({ success: true });
      
      const context = {
        operation: 'query',
        retryFunction
      };
      
      const result = await errorManager.handleError(error, source, context);
      
      // Should have tried to retry
      expect(retryFunction).toHaveBeenCalled();
      
      // Should have returned success
      expect(result.success).toBeTruthy();
    });
    
    it('should fall back to pattern analysis for anthropic errors', async () => {
      const error = new Error('API error');
      error.status = 429; // Rate limiting
      
      const source = 'anthropic';
      
      // Mock the pattern analysis dependency
      jest.mock('../src/utils/moderationUtils', () => ({
        patternAnalysis: jest.fn().mockReturnValue({
          isViolation: true,
          action: 'warn'
        })
      }));
      
      const context = {
        operation: 'processWithClaude',
        message: {
          content: 'This is a test message'
        },
        userData: {}
      };
      
      const result = await errorManager.handleError(error, source, context);
      
      // Should use fallback
      expect(result.message).toContain('fallback');
    });
  });
  
  describe('degraded mode', () => {
    it('should enter degraded mode when services are unhealthy', async () => {
      // Mark a service as unhealthy
      errorManager.serviceStatus.anthropic.healthy = false;
      errorManager.serviceStatus.anthropic.failures = 5;
      
      // Run health checks
      await errorManager.runHealthChecks();
      
      // Should be in degraded mode
      expect(errorManager.degradedMode).toBeTruthy();
      expect(logger.warn).toHaveBeenCalled();
    });
    
    it('should exit degraded mode when services become healthy', async () => {
      // Set degraded mode and unhealthy service
      errorManager.degradedMode = true;
      errorManager.serviceStatus.anthropic.healthy = false;
      
      // Now make the service healthy
      errorManager.serviceStatus.anthropic.healthy = true;
      
      // Run health checks
      await errorManager.runHealthChecks();
      
      // Should exit degraded mode
      expect(errorManager.degradedMode).toBeFalsy();
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining('Exiting degraded mode')
      );
    });
  });
  
  describe('error deduplication', () => {
    it('should deduplicate similar errors', async () => {
      const error = new Error('Duplicate error message');
      const source = 'test';
      
      // Generate the same error multiple times
      for (let i = 0; i < 15; i++) {
        await errorManager.handleError(error, source, {});
      }
      
      // Should not log every occurrence
      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.warn).toHaveBeenCalled(); // Should warn about repeated errors
    });
  });
});

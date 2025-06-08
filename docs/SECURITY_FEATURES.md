# Security Features Documentation

This document provides detailed information about the security features implemented in the Discord AI Moderator application.

## Overview

The Discord AI Moderator application implements several advanced security features to protect against common web vulnerabilities, prevent unauthorized access, and ensure data integrity. These features include Content Security Policy (CSP) implementation, IP reputation tracking with dynamic rate limiting, and secure session management with client fingerprinting and rotation.

## Content Security Policy (CSP)

### Overview

Content Security Policy is a security standard that helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks. It works by specifying which content sources are trusted and can be loaded by the browser.

### Implementation

The CSP implementation in the Discord AI Moderator application uses nonce-based validation for inline scripts and strict source restrictions for all content types.

#### Nonce Generation

A cryptographically secure random nonce is generated for each request:

```javascript
const crypto = require('crypto');

function generateNonce() {
  return crypto.randomBytes(16).toString('base64');
}
```

#### CSP Header Configuration

The CSP header is configured with strict rules and the generated nonce:

```javascript
function configureCSP(req, res, next) {
  const nonce = generateNonce();
  req.nonce = nonce;
  
  // Set CSP header
  res.setHeader('Content-Security-Policy', `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net;
    style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com;
    img-src 'self' https://cdn.discordapp.com data:;
    font-src 'self' https://fonts.gstatic.com;
    connect-src 'self' https://discord.com/api/;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    object-src 'none'
  `.replace(/\s+/g, ' ').trim());
  
  next();
}
```

#### Integration with Templates

The nonce is passed to templates and used for inline scripts:

```html
<!-- Example template usage -->
<script nonce="<%= nonce %>">
  // Inline JavaScript
  document.addEventListener('DOMContentLoaded', function() {
    // Initialize application
  });
</script>
```

### Configuration Options

The CSP implementation can be configured through environment variables:

```env
# CSP Configuration
ENABLE_CSP=true
CSP_REPORT_URI=/api/csp-report
CSP_REPORT_ONLY=false
```

### CSP Reporting

The application includes a CSP violation reporting endpoint:

```javascript
app.post('/api/csp-report', (req, res) => {
  const report = req.body['csp-report'] || req.body;
  logger.warn('CSP Violation:', report);
  
  // Store violation in database for analysis
  db.storeCSPViolation(report);
  
  res.status(204).end();
});
```

## IP Reputation Tracking

### Overview

IP reputation tracking monitors client behavior over time to identify potentially malicious actors and apply appropriate restrictions. This system goes beyond simple rate limiting by considering historical behavior patterns.

### Implementation

The IP reputation system tracks various metrics for each client IP address:

#### Reputation Scoring

Each IP address is assigned a reputation score based on its behavior:

```javascript
class IPReputationTracker {
  constructor(options = {}) {
    this.reputationScores = new Map();
    this.activityLogs = new Map();
    this.thresholds = {
      suspicious: options.suspiciousThreshold || -10,
      malicious: options.maliciousThreshold || -50,
      ...
    };
  }
  
  updateReputation(ip, action, value) {
    let score = this.reputationScores.get(ip) || 0;
    
    // Update score based on action
    score += value;
    
    // Log activity
    const activities = this.activityLogs.get(ip) || [];
    activities.push({
      timestamp: Date.now(),
      action,
      value,
      newScore: score
    });
    
    // Trim activity log if too large
    if (activities.length > 100) {
      activities.splice(0, activities.length - 100);
    }
    
    // Store updated values
    this.reputationScores.set(ip, score);
    this.activityLogs.set(ip, activities);
    
    return score;
  }
}
```

#### Tracked Behaviors

The system tracks various behaviors that affect reputation:

| Behavior | Reputation Impact |
|----------|------------------|
| Successful login | +1 |
| Failed login | -1 |
| API rate limit exceeded | -5 |
| Accessing restricted resource | -10 |
| Submitting invalid data | -2 |
| Successful API usage | +0.1 |
| Suspicious pattern detected | -20 |

#### Dynamic Rate Limiting

Rate limits are adjusted based on reputation scores:

```javascript
function getDynamicRateLimit(ip) {
  const reputation = reputationTracker.getReputation(ip);
  
  if (reputation <= thresholds.malicious) {
    return { windowMs: 3600000, max: 10 }; // 10 requests per hour
  } else if (reputation <= thresholds.suspicious) {
    return { windowMs: 60000, max: 20 }; // 20 requests per minute
  } else if (reputation <= thresholds.neutral) {
    return { windowMs: 60000, max: 60 }; // 60 requests per minute
  } else {
    return { windowMs: 60000, max: 100 }; // 100 requests per minute
  }
}
```

#### Integration with Express

The IP reputation system is integrated with Express middleware:

```javascript
// IP reputation middleware
app.use((req, res, next) => {
  const ip = req.ip;
  
  // Get reputation score
  const reputation = reputationTracker.getReputation(ip);
  
  // Apply restrictions based on reputation
  if (reputation <= thresholds.malicious) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Store reputation in request for other middleware
  req.ipReputation = reputation;
  
  // Continue to next middleware
  next();
});
```

### Configuration Options

The IP reputation system can be configured through environment variables:

```env
# IP Reputation Configuration
ENABLE_IP_REPUTATION=true
IP_REPUTATION_SUSPICIOUS_THRESHOLD=-10
IP_REPUTATION_MALICIOUS_THRESHOLD=-50
IP_REPUTATION_RESET_INTERVAL=86400000
```

### Reputation Recovery

IP addresses can recover reputation over time:

```javascript
// Periodically adjust reputation scores
setInterval(() => {
  for (const [ip, score] of reputationTracker.reputationScores.entries()) {
    if (score < 0) {
      // Gradually recover negative reputation
      reputationTracker.updateReputation(ip, 'time-decay', Math.min(1, Math.abs(score) * 0.1));
    }
  }
}, 3600000); // Every hour
```

## Secure Session Management

### Overview

Secure session management ensures that user sessions are protected against hijacking, fixation, and other session-based attacks. The implementation includes client fingerprinting, session rotation, and secure cookie handling.

### Implementation

#### Session Configuration

Sessions are configured with secure defaults:

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  name: 'discord_ai_mod_sid', // Custom session ID name
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  },
  rolling: true, // Reset expiration on activity
  resave: false,
  saveUninitialized: false
}));
```

#### Client Fingerprinting

Each session is associated with a client fingerprint to detect potential session hijacking:

```javascript
function generateClientFingerprint(req) {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.ip
  ];
  
  return crypto
    .createHash('sha256')
    .update(components.join('|'))
    .digest('hex');
}

// Fingerprint verification middleware
app.use((req, res, next) => {
  if (req.session && req.session.fingerprint) {
    const currentFingerprint = generateClientFingerprint(req);
    
    // Verify fingerprint matches
    if (req.session.fingerprint !== currentFingerprint) {
      // Potential session hijacking
      logger.warn('Fingerprint mismatch:', {
        sessionId: req.sessionID,
        storedFingerprint: req.session.fingerprint,
        currentFingerprint
      });
      
      // Destroy session
      req.session.destroy();
      return res.status(403).json({ error: 'Session invalid' });
    }
  } else if (req.session) {
    // Set initial fingerprint
    req.session.fingerprint = generateClientFingerprint(req);
  }
  
  next();
});
```

#### Session Rotation

Sessions are rotated after authentication and periodically to prevent fixation attacks:

```javascript
function rotateSession(req, res, callback) {
  const oldSession = { ...req.session };
  
  // Regenerate session ID
  req.session.regenerate((err) => {
    if (err) {
      logger.error('Session rotation failed:', err);
      return callback(err);
    }
    
    // Copy old session data to new session
    Object.assign(req.session, oldSession);
    
    // Update fingerprint
    req.session.fingerprint = generateClientFingerprint(req);
    
    // Set rotation timestamp
    req.session.rotatedAt = Date.now();
    
    callback();
  });
}

// Rotate session after login
app.post('/api/login', (req, res) => {
  // Authentication logic...
  
  // After successful authentication
  rotateSession(req, res, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Authentication failed' });
    }
    
    // Set authenticated flag
    req.session.authenticated = true;
    req.session.userId = user.id;
    
    res.json({ success: true });
  });
});
```

#### Periodic Session Rotation

Sessions are periodically rotated for long-lived sessions:

```javascript
// Middleware to check session age and rotate if needed
app.use((req, res, next) => {
  if (req.session && req.session.authenticated && req.session.rotatedAt) {
    const sessionAge = Date.now() - req.session.rotatedAt;
    
    // Rotate session if older than 30 minutes
    if (sessionAge > 1800000) {
      return rotateSession(req, res, next);
    }
  }
  
  next();
});
```

### Configuration Options

The session management system can be configured through environment variables:

```env
# Session Configuration
SESSION_SECRET=your-secret-key
SESSION_MAX_AGE=3600000
SESSION_ROTATION_INTERVAL=1800000
SESSION_STORE=redis
```

### Session Monitoring

The application includes session monitoring for security analysis:

```javascript
// Periodically log session statistics
setInterval(() => {
  redisClient.keys('sess:*', (err, keys) => {
    if (err) {
      return logger.error('Session monitoring error:', err);
    }
    
    logger.info('Active sessions:', {
      count: keys.length,
      timestamp: new Date().toISOString()
    });
  });
}, 3600000); // Every hour
```

## Integration of Security Features

### Middleware Chain

The security features are integrated into the Express middleware chain:

```javascript
// Security middleware chain
app.use(helmet()); // Basic security headers
app.use(configureCSP); // Content Security Policy
app.use(sessionMiddleware); // Session management
app.use(fingerprintVerification); // Client fingerprinting
app.use(ipReputationMiddleware); // IP reputation tracking
app.use(dynamicRateLimiter); // Dynamic rate limiting
```

### Security Monitoring

Security events are logged and monitored:

```javascript
// Security event logging
function logSecurityEvent(event, data) {
  logger.warn('Security event:', { event, ...data });
  
  // Store in database for analysis
  db.storeSecurityEvent({
    event,
    data,
    timestamp: new Date()
  });
}

// Example usage
app.use((req, res, next) => {
  res.on('finish', () => {
    // Log suspicious responses
    if (res.statusCode === 403) {
      logSecurityEvent('access-denied', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        reputation: req.ipReputation
      });
    }
  });
  
  next();
});
```

## Best Practices

### Content Security Policy

1. **Use Nonces**: Always use nonces for inline scripts instead of unsafe-inline
2. **Restrict Sources**: Limit content sources to trusted domains
3. **Report Violations**: Configure CSP reporting to detect potential issues
4. **Test Thoroughly**: Verify CSP doesn't break application functionality

### IP Reputation

1. **Gradual Penalties**: Apply increasingly strict restrictions as reputation decreases
2. **Recovery Path**: Allow reputation to recover over time
3. **False Positive Mitigation**: Implement mechanisms to correct false positives
4. **Transparency**: Provide feedback when restrictions are applied

### Session Management

1. **Secure Cookies**: Always use httpOnly, secure, and sameSite attributes
2. **Session Rotation**: Rotate sessions after authentication and periodically
3. **Fingerprinting**: Use client fingerprinting to detect session hijacking
4. **Expiration**: Set appropriate session timeouts based on sensitivity

## Security Headers

In addition to CSP, the application sets various security headers using Helmet:

```javascript
app.use(helmet({
  contentSecurityPolicy: false, // We configure CSP separately
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));
```

### Key Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload | Enforce HTTPS |
| X-Frame-Options | DENY | Prevent clickjacking |
| X-Content-Type-Options | nosniff | Prevent MIME type sniffing |
| Referrer-Policy | strict-origin-when-cross-origin | Limit referrer information |
| X-XSS-Protection | 1; mode=block | Additional XSS protection |
| X-DNS-Prefetch-Control | off | Prevent DNS prefetching |

## Security Monitoring Dashboard

The application includes a security monitoring dashboard for administrators:

```javascript
// Security dashboard route
app.get('/admin/security', requireAdmin, async (req, res) => {
  try {
    // Get security metrics
    const metrics = await db.getSecurityMetrics();
    
    // Render dashboard
    res.render('admin/security', {
      nonce: req.nonce,
      metrics
    });
  } catch (err) {
    logger.error('Security dashboard error:', err);
    res.status(500).render('error', { message: 'Failed to load security dashboard' });
  }
});
```

The dashboard displays:

- Recent security events
- IP reputation statistics
- Session activity
- CSP violation reports
- Rate limiting metrics

## Examples

### Implementing CSP in Routes

```javascript
// Example route with CSP nonce
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', {
    user: req.user,
    nonce: req.nonce, // Pass nonce to template
    servers: req.user.servers
  });
});
```

### Handling IP Reputation in API Routes

```javascript
// API route with reputation-based rate limiting
app.post('/api/analyze', (req, res) => {
  const ip = req.ip;
  const reputation = req.ipReputation;
  
  // Apply stricter validation for low reputation
  if (reputation <= thresholds.suspicious) {
    // Apply additional validation
    const validationResult = validateStrictly(req.body);
    if (!validationResult.valid) {
      // Update reputation for invalid data
      reputationTracker.updateReputation(ip, 'invalid-data', -2);
      return res.status(400).json({ error: validationResult.error });
    }
  }
  
  // Process request
  processAnalysisRequest(req.body)
    .then(result => {
      // Update reputation for successful request
      reputationTracker.updateReputation(ip, 'successful-api', 0.1);
      res.json(result);
    })
    .catch(err => {
      logger.error('Analysis error:', err);
      res.status(500).json({ error: 'Analysis failed' });
    });
});
```

### Secure Session Handling in Authentication

```javascript
// Login route with secure session handling
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate credentials
    const user = await db.getUserByUsername(username);
    if (!user) {
      // Log failed login attempt
      reputationTracker.updateReputation(req.ip, 'failed-login', -1);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const passwordValid = await bcrypt.compare(password, user.passwordHash);
    if (!passwordValid) {
      // Log failed login attempt
      reputationTracker.updateReputation(req.ip, 'failed-login', -1);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Rotate session
    rotateSession(req, res, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Authentication failed' });
      }
      
      // Set session data
      req.session.authenticated = true;
      req.session.userId = user.id;
      req.session.lastActive = Date.now();
      
      // Update reputation for successful login
      reputationTracker.updateReputation(req.ip, 'successful-login', 1);
      
      // Return success
      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          displayName: user.displayName
        }
      });
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});
```

## Security Audit Logging

The application includes comprehensive security audit logging:

```javascript
const auditLogger = require('./utils/audit-logger');

// Audit log middleware
app.use((req, res, next) => {
  // Skip logging for static assets
  if (req.path.startsWith('/static/')) {
    return next();
  }
  
  // Log request
  auditLogger.logRequest({
    timestamp: new Date(),
    ip: req.ip,
    method: req.method,
    path: req.path,
    userId: req.session?.userId || null,
    userAgent: req.headers['user-agent'],
    sessionId: req.sessionID
  });
  
  next();
});

// Log authentication events
function logAuthEvent(type, userId, success, ip, reason = null) {
  auditLogger.logAuthEvent({
    timestamp: new Date(),
    type,
    userId,
    success,
    ip,
    reason,
    userAgent: req.headers['user-agent']
  });
}
```

Audit logs are stored securely and can be reviewed by administrators.

## Conclusion

The security features implemented in the Discord AI Moderator application provide comprehensive protection against common web vulnerabilities and attacks. By combining Content Security Policy, IP reputation tracking, and secure session management, the application maintains a strong security posture while providing a seamless user experience.

These security measures should be regularly reviewed and updated to address emerging threats and vulnerabilities. Security is an ongoing process that requires continuous monitoring, testing, and improvement.
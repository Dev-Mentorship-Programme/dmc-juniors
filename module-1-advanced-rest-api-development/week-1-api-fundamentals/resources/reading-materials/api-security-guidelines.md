# API Security Guidelines

## 📘 Security Fundamentals

### OWASP API Security Top 10
- **[OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/)**
  - Comprehensive threat landscape
  - Risk assessment frameworks
  - Mitigation strategies

#### Critical Vulnerabilities
1. **Broken Object Level Authorization** - Accessing other users' resources
2. **Broken Authentication** - Weak authentication mechanisms
3. **Broken Object Property Level Authorization** - Insufficient property-level access controls
4. **Unrestricted Resource Consumption** - DoS through resource exhaustion
5. **Broken Function Level Authorization** - Access to unauthorized functions
6. **Unrestricted Access to Sensitive Business Flows** - Business logic bypass
7. **Server Side Request Forgery (SSRF)** - Server-initiated malicious requests
8. **Security Misconfiguration** - Insecure default configurations
9. **Improper Inventory Management** - Unknown or unmanaged API endpoints
10. **Unsafe Consumption of APIs** - Third-party API integration risks

### Security-by-Design Principles
- **[Security by Design for APIs](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)**
  - Zero-trust architecture
  - Defense in depth strategy
  - Principle of least privilege
  - Fail-secure defaults

## 🔐 Authentication and Authorization

### Authentication Mechanisms

#### JWT (JSON Web Tokens)
- **[JWT Security Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)**
  - Secure token design
  - Algorithm selection (RS256 recommended)
  - Token expiration strategies
  - Refresh token security

```javascript
// Secure JWT configuration
const jwtConfig = {
  algorithm: 'RS256',           // Asymmetric signing
  expiresIn: '15m',            // Short-lived access tokens
  issuer: 'your-api.com',      // Token issuer
  audience: 'your-api.com',    // Intended audience
  clockTolerance: 60,          // Clock skew tolerance
  ignoreExpiration: false,     // Never ignore expiration
  ignoreNotBefore: false       // Respect nbf claim
};
```

- **[JWT Attack Vectors and Defenses](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)**
  - Algorithm confusion attacks
  - None algorithm vulnerability
  - Key confusion attacks
  - Token sidejacking prevention

#### OAuth 2.1 Implementation
- **[OAuth 2.1 Security Features](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)**
  - PKCE mandatory for all flows
  - Implicit flow removal
  - Refresh token rotation
  - Redirect URI exact matching

```javascript
// OAuth 2.1 PKCE flow
const pkceChallenge = {
  codeVerifier: generateCodeVerifier(),     // 43-128 chars
  codeChallengeMethod: 'S256',              // SHA256 required
  codeChallenge: sha256(codeVerifier),      // Base64URL encoded
  state: generateCryptographicState(),      // CSRF protection
  nonce: generateNonce()                    // Replay protection
};
```

#### API Key Management
- **[API Key Security Best Practices](https://cloud.google.com/endpoints/docs/openapi/when-why-api-key)**
  - Key generation standards
  - Rotation policies
  - Scope limitations
  - Rate limiting integration

### Authorization Patterns

#### Role-Based Access Control (RBAC)
- **[RBAC Implementation Guide](https://auth0.com/blog/role-based-access-control-rbac-and-react-apps/)**
  - Role hierarchy design
  - Permission inheritance
  - Dynamic role assignment
  - Audit trail requirements

```javascript
// RBAC permission matrix
const permissions = {
  admin: ['*'],
  manager: ['users:read', 'users:update', 'reports:read'],
  user: ['profile:read', 'profile:update', 'data:read'],
  guest: ['public:read']
};

// Permission check middleware
function hasPermission(requiredPermission) {
  return (req, res, next) => {
    const userPermissions = getUserPermissions(req.user);
    if (checkPermission(userPermissions, requiredPermission)) {
      next();
    } else {
      res.status(403).json({ error: 'Insufficient permissions' });
    }
  };
}
```

#### Attribute-Based Access Control (ABAC)
- **[ABAC vs RBAC Comparison](https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/)**
  - Dynamic policy evaluation
  - Context-aware decisions
  - Fine-grained controls
  - Complex rule engines

```javascript
// ABAC policy example
const policy = {
  resource: 'user-data',
  action: 'read',
  conditions: {
    'user.department': 'equals:HR',
    'resource.sensitivity': 'lessThan:confidential',
    'request.time': 'businessHours',
    'request.location': 'allowedRegions'
  }
};
```

## 🛡 Input Validation and Sanitization

### Comprehensive Input Validation
- **[Input Validation Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)**
  - Whitelist validation approach
  - Data type enforcement
  - Length and format restrictions
  - Character encoding validation

#### Validation Schemas
```javascript
// Joi validation schema
const userSchema = Joi.object({
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'org'] } })
    .required(),
  password: Joi.string()
    .min(12)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])'))
    .required(),
  age: Joi.number()
    .integer()
    .min(13)
    .max(120),
  phone: Joi.string()
    .pattern(new RegExp('^\+[1-9]\d{1,14}$')) // E.164 format
});
```

### SQL Injection Prevention
- **[SQL Injection Defense Guide](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)**
  - Parameterized queries
  - Stored procedures
  - Input validation
  - Least privilege database access

```javascript
// Secure database queries
// ❌ Vulnerable
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ Secure - Parameterized query
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);

// ✅ Secure - ORM usage
const user = await User.findById(userId);
```

### NoSQL Injection Prevention
- **[NoSQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)**
  - Query structure validation
  - Input type checking
  - MongoDB-specific defenses

```javascript
// NoSQL injection prevention
function sanitizeMongoQuery(query) {
  if (query && typeof query === 'object') {
    for (let key in query) {
      // Remove operator injection attempts
      if (key.startsWith('$')) {
        delete query[key];
      }
      // Recursively sanitize nested objects
      if (typeof query[key] === 'object') {
        sanitizeMongoQuery(query[key]);
      }
    }
  }
  return query;
}
```

### XSS Prevention
- **[Cross-Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)**
  - Output encoding strategies
  - Context-aware escaping
  - Content Security Policy
  - Input sanitization

```javascript
// XSS prevention middleware
const xss = require('xss');

function sanitizeInput(req, res, next) {
  // Sanitize request body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  // Sanitize query parameters
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  next();
}

function sanitizeObject(obj) {
  for (let key in obj) {
    if (typeof obj[key] === 'string') {
      obj[key] = xss(obj[key]);
    } else if (typeof obj[key] === 'object') {
      obj[key] = sanitizeObject(obj[key]);
    }
  }
  return obj;
}
```

## 🔒 Encryption and Data Protection

### Data Encryption at Rest
- **[Database Encryption Strategies](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)**
  - Full database encryption
  - Column-level encryption
  - Key management systems
  - Performance considerations

```javascript
// Field-level encryption
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';

class FieldEncryption {
  constructor(masterKey) {
    this.masterKey = masterKey;
  }

  encrypt(plaintext) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, this.masterKey, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encryptedData) {
    const decipher = crypto.createDecipher(
      algorithm, 
      this.masterKey, 
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

### Data Encryption in Transit
- **[TLS Configuration Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)**
  - TLS 1.3 implementation
  - Certificate management
  - Perfect Forward Secrecy
  - HTTP Strict Transport Security

```javascript
// Secure TLS configuration
const httpsOptions = {
  key: fs.readFileSync('private-key.pem'),
  cert: fs.readFileSync('certificate.pem'),
  ca: fs.readFileSync('ca-cert.pem'),
  
  // TLS configuration
  secureProtocol: 'TLSv1_3_method',
  honorCipherOrder: true,
  ciphers: [
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305'
  ].join(':'),
  
  // Security headers
  requestCert: false,
  rejectUnauthorized: true
};
```

### Key Management
- **[Cryptographic Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)**
  - Key generation standards
  - Key rotation policies
  - Hardware security modules
  - Key escrow considerations

```javascript
// Key rotation strategy
class KeyManager {
  constructor() {
    this.currentKey = null;
    this.previousKeys = [];
    this.rotationInterval = 30 * 24 * 60 * 60 * 1000; // 30 days
  }

  async rotateKeys() {
    if (this.currentKey) {
      this.previousKeys.push(this.currentKey);
    }
    
    this.currentKey = {
      id: generateKeyId(),
      key: generateSecureKey(),
      createdAt: Date.now()
    };
    
    // Schedule next rotation
    setTimeout(() => this.rotateKeys(), this.rotationInterval);
    
    // Clean up old keys (keep only last 3)
    this.previousKeys = this.previousKeys.slice(-3);
  }
}
```

## 🛡 Security Headers and Middleware

### Essential Security Headers
- **[Security Headers Best Practices](https://owasp.org/www-project-secure-headers/)**
  - Complete header configuration
  - Browser compatibility considerations
  - Performance impact analysis

```javascript
// Comprehensive security headers
const securityHeaders = {
  // HTTPS enforcement
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  
  // XSS protection
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': `
    default-src 'self';
    script-src 'self' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
  `.replace(/\s+/g, ' ').trim(),
  
  // Content type protection
  'X-Content-Type-Options': 'nosniff',
  
  // Clickjacking protection
  'X-Frame-Options': 'DENY',
  
  // Referrer policy
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Feature policy
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  
  // Remove server information
  'Server': ''
};
```

### CORS Security Configuration
- **[CORS Security Best Practices](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)**
  - Origin validation
  - Credential handling
  - Preflight optimization

```javascript
// Secure CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://app.yourdomain.com',
      'https://admin.yourdomain.com'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 200
};
```

## 🔍 Security Monitoring and Logging

### Security Event Logging
- **[Security Logging Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)**
  - Event categorization
  - Log data protection
  - Retention policies
  - Incident response integration

```javascript
// Security event logger
class SecurityLogger {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ 
          filename: 'security.log',
          level: 'warn'
        })
      ]
    });
  }

  logAuthenticationEvent(event, user, ip, userAgent) {
    this.logger.warn({
      type: 'authentication',
      event: event,
      userId: user?.id || 'anonymous',
      ip: this.hashIP(ip),
      userAgent: userAgent,
      timestamp: new Date().toISOString()
    });
  }

  logAuthorizationViolation(user, resource, action) {
    this.logger.error({
      type: 'authorization_violation',
      userId: user.id,
      resource: resource,
      action: action,
      timestamp: new Date().toISOString()
    });
  }

  hashIP(ip) {
    // Hash IP for privacy while maintaining ability to detect patterns
    return crypto.createHash('sha256').update(ip + process.env.IP_SALT).digest('hex');
  }
}
```

### Intrusion Detection
- **[API Intrusion Detection Patterns](https://owasp.org/www-project-application-security-verification-standard/)**
  - Behavioral analysis
  - Anomaly detection
  - Automated response systems

```javascript
// Intrusion detection system
class IntrusionDetector {
  constructor() {
    this.suspiciousActivities = new Map();
    this.alertThresholds = {
      failedLoginAttempts: 5,
      unusualAPIUsage: 100,
      sqlInjectionAttempts: 1,
      xssAttempts: 1
    };
  }

  analyzeRequest(req) {
    const clientId = this.getClientIdentifier(req);
    const activity = this.suspiciousActivities.get(clientId) || {
      failedLogins: 0,
      apiCalls: 0,
      injectionAttempts: 0,
      lastActivity: Date.now()
    };

    // Check for suspicious patterns
    if (this.detectSQLInjection(req)) {
      activity.injectionAttempts++;
      this.handleThreat('sql_injection', clientId, req);
    }

    if (this.detectXSSAttempts(req)) {
      activity.injectionAttempts++;
      this.handleThreat('xss_attempt', clientId, req);
    }

    this.suspiciousActivities.set(clientId, activity);
  }

  handleThreat(threatType, clientId, req) {
    // Log the threat
    securityLogger.logSecurityThreat(threatType, clientId, req);
    
    // Automated response
    if (threatType === 'sql_injection' || threatType === 'xss_attempt') {
      this.temporaryBan(clientId, 3600000); // 1 hour ban
      this.notifySecurityTeam(threatType, clientId, req);
    }
  }
}
```

## 🚨 Incident Response

### Security Incident Classification
- **[Incident Response Framework](https://owasp.org/www-project-incident-response/)**
  - Severity classification
  - Response procedures
  - Communication protocols
  - Recovery strategies

```javascript
// Incident response system
const incidentClassification = {
  CRITICAL: {
    severity: 1,
    responseTime: '15 minutes',
    escalation: ['security-team', 'management', 'legal'],
    examples: ['data breach', 'system compromise', 'service unavailable']
  },
  HIGH: {
    severity: 2,
    responseTime: '1 hour',
    escalation: ['security-team', 'development-team'],
    examples: ['privilege escalation', 'authentication bypass']
  },
  MEDIUM: {
    severity: 3,
    responseTime: '4 hours',
    escalation: ['security-team'],
    examples: ['suspicious activity', 'configuration errors']
  },
  LOW: {
    severity: 4,
    responseTime: '24 hours',
    escalation: ['development-team'],
    examples: ['minor security findings', 'informational alerts']
  }
};
```

### Automated Incident Response
- **[Security Orchestration and Automated Response (SOAR)](https://www.gartner.com/en/information-technology/glossary/security-orchestration-automated-response-soar)**
  - Playbook automation
  - Threat intelligence integration
  - Response coordination

## 🔄 Security Testing

### Security Test Categories
- **[API Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)**
  - Authentication testing
  - Authorization testing
  - Input validation testing
  - Session management testing

```javascript
// Security test suite example
describe('API Security Tests', () => {
  describe('Authentication', () => {
    it('should reject requests without valid token', async () => {
      const response = await request(app)
        .get('/api/protected-resource')
        .expect(401);
    });

    it('should reject expired tokens', async () => {
      const expiredToken = generateExpiredToken();
      const response = await request(app)
        .get('/api/protected-resource')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });
  });

  describe('Authorization', () => {
    it('should prevent privilege escalation', async () => {
      const userToken = generateUserToken();
      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });
  });

  describe('Input Validation', () => {
    it('should prevent SQL injection', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      const response = await request(app)
        .post('/api/search')
        .send({ query: maliciousInput })
        .expect(400);
    });
  });
});
```

### Penetration Testing
- **[API Penetration Testing Methodology](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/12-API_Testing/)**
  - Automated vulnerability scanning
  - Manual security testing
  - Business logic testing
  - Infrastructure testing

## ✅ Security Implementation Checklist

### Authentication & Authorization
- [ ] Strong password policies implemented
- [ ] Multi-factor authentication available
- [ ] JWT tokens properly secured (RS256, short expiration)
- [ ] API keys have proper scopes and expiration
- [ ] Role-based access control implemented
- [ ] Session management is secure
- [ ] Account lockout policies configured

### Input Validation & Sanitization
- [ ] All inputs validated against whitelist
- [ ] SQL injection prevention measures
- [ ] NoSQL injection prevention measures
- [ ] XSS prevention implemented
- [ ] File upload security controls
- [ ] Rate limiting on sensitive endpoints

### Encryption & Data Protection
- [ ] Data encrypted at rest (AES-256)
- [ ] TLS 1.3 enforced for all communications
- [ ] Cryptographic keys properly managed
- [ ] Sensitive data properly hashed (bcrypt/Argon2)
- [ ] Key rotation procedures implemented

### Security Headers & Configuration
- [ ] All security headers implemented
- [ ] CORS properly configured
- [ ] Server information hidden
- [ ] Default passwords changed
- [ ] Unnecessary services disabled
- [ ] Security patches up to date

### Monitoring & Logging
- [ ] Security events logged
- [ ] Log integrity protected
- [ ] Anomaly detection implemented
- [ ] Incident response procedures defined
- [ ] Security metrics dashboard created
- [ ] Regular security assessments scheduled

### Testing & Validation
- [ ] Security tests in CI/CD pipeline
- [ ] Regular penetration testing scheduled
- [ ] Vulnerability scanning automated
- [ ] Security code review process
- [ ] Third-party security audit completed

---

*📚 This comprehensive security guide should be used alongside the practical examples in our [exercises](../exercises/) and [examples](../examples/) directories.*

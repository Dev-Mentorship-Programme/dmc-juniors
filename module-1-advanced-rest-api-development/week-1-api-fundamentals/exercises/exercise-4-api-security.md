# Exercise 4: Comprehensive API Security Implementation

## Objective
Build a production-ready secure API system implementing multiple layers of security controls, authentication mechanisms, and protection against common vulnerabilities.

## Scenario
You're developing a financial services API that handles sensitive user data and transactions. The API must comply with security standards and protect against various attack vectors.

## Security Requirements

### Compliance Standards
- OWASP API Security Top 10
- PCI DSS Level 1 (for payment processing)
- SOC 2 Type II compliance
- GDPR compliance for data protection

## Tasks

### Task 1: Authentication and Authorization

#### Multi-Factor Authentication System
Implement a complete MFA system:

```javascript
// Authentication flows to implement
const authFlows = {
  basic: 'username + password',
  mfa: 'username + password + TOTP/SMS',
  oauth2: 'OAuth 2.0 with PKCE',
  jwt: 'Stateless JWT with refresh tokens',
  apiKey: 'API key with scopes and expiration'
};
```

**Requirements:**
- JWT token implementation with RS256 signing
- Refresh token rotation
- TOTP (Time-based One-Time Password) support
- SMS-based 2FA with rate limiting
- OAuth 2.0 with PKCE flow
- API key management with scopes

#### Role-Based Access Control (RBAC)
```javascript
const roles = {
  user: {
    permissions: ['read:profile', 'update:profile', 'read:transactions'],
    resources: ['users/{userId}', 'transactions/{userId}/*']
  },
  admin: {
    permissions: ['*'],
    resources: ['*']
  },
  auditor: {
    permissions: ['read:*', 'export:audit-logs'],
    resources: ['users/*', 'transactions/*', 'audit/*']
  }
};
```

#### Permission-Based Authorization
- Implement fine-grained permissions
- Resource-based access control
- Dynamic permission evaluation
- Permission inheritance

### Task 2: Input Validation and Sanitization

#### Comprehensive Input Validation
```javascript
// Validation schemas to implement
const validationSchemas = {
  user: {
    email: 'valid email format + domain validation',
    password: '12+ chars, special chars, numbers, mixed case',
    phone: 'E.164 format with country code validation',
    amount: 'positive number with precision limits',
    currency: 'ISO 4217 currency code',
    accountNumber: 'bank account format validation'
  }
};
```

**Security Controls:**
- SQL injection prevention
- NoSQL injection prevention
- XSS protection with output encoding
- LDAP injection prevention
- XML external entity (XXE) prevention
- Path traversal protection

#### Advanced Sanitization
```javascript
// Sanitization layers
const sanitization = {
  input: 'HTML encoding, script removal, special chars',
  database: 'Parameterized queries, ORM protection',
  output: 'Context-aware encoding (HTML, JS, CSS, URL)',
  logging: 'Sensitive data redaction'
};
```

### Task 3: Encryption and Data Protection

#### Data Encryption at Rest
```javascript
// Encryption requirements
const encryptionConfig = {
  algorithm: 'AES-256-GCM',
  keyManagement: 'AWS KMS / Azure Key Vault',
  dataTypes: {
    pii: 'Full encryption required',
    financial: 'Full encryption + tokenization',
    logs: 'Selective field encryption',
    backups: 'Full database encryption'
  }
};
```

#### Data Encryption in Transit
- TLS 1.3 minimum requirement
- Certificate pinning
- HSTS headers implementation
- Perfect Forward Secrecy (PFS)

#### Field-Level Encryption
```javascript
// Implement encryption for sensitive fields
const encryptedFields = {
  ssn: 'AES-256-GCM with unique IV',
  creditCard: 'Tokenization with external vault',
  bankAccount: 'Format-preserving encryption',
  address: 'Searchable encryption'
};
```

### Task 4: Security Headers and Middleware

#### Security Headers Implementation
```javascript
const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  'X-XSS-Protection': '1; mode=block'
};
```

#### CORS Configuration
```javascript
const corsConfig = {
  origin: ['https://app.example.com', 'https://admin.example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false
};
```

### Task 5: Advanced Security Features

#### API Security Monitoring
```javascript
// Security events to monitor
const securityEvents = {
  authentication: {
    failed_login: 'Track failed attempts per IP/user',
    account_lockout: 'Monitor suspicious lockout patterns',
    mfa_bypass: 'Detect MFA bypass attempts'
  },
  authorization: {
    privilege_escalation: 'Detect unauthorized access attempts',
    resource_access: 'Monitor access to sensitive resources',
    scope_violations: 'Track API scope violations'
  },
  data_access: {
    bulk_operations: 'Monitor large data exports',
    sensitive_queries: 'Track PII access patterns',
    unusual_patterns: 'Detect anomalous data access'
  }
};
```

#### Threat Detection
- Brute force attack detection
- Account enumeration prevention
- Time-based attack detection
- Anomaly detection for user behavior
- Geographic access pattern analysis

#### API Rate Limiting for Security
```javascript
// Security-focused rate limiting
const securityLimits = {
  authentication: {
    login: '5 attempts per 15 minutes per IP',
    password_reset: '3 attempts per hour per email',
    mfa_verification: '10 attempts per hour per user'
  },
  sensitive_operations: {
    password_change: '2 per hour per user',
    account_settings: '10 per hour per user',
    data_export: '1 per day per user'
  }
};
```

### Task 6: Secure Session Management

#### Session Security
```javascript
const sessionConfig = {
  name: 'sessionId',
  secret: 'cryptographically-strong-secret',
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000, // 1 hour
    path: '/'
  },
  rolling: true,
  saveUninitialized: false,
  resave: false
};
```

#### JWT Security Best Practices
- Short-lived access tokens (15 minutes)
- Refresh token rotation
- Token blacklisting capability
- Audience and issuer validation
- Key rotation strategy

### Task 7: Vulnerability Prevention

#### SQL Injection Prevention
```javascript
// Example secure database queries
const secureQueries = {
  parameterized: 'SELECT * FROM users WHERE id = $1',
  orm: 'User.findById(userId)', // Using ORM
  whitelist: 'Whitelist allowed table/column names',
  escaping: 'Proper input escaping for dynamic queries'
};
```

#### File Upload Security
```javascript
const fileUploadSecurity = {
  validation: {
    fileType: 'Whitelist allowed MIME types',
    fileSize: 'Maximum 10MB per file',
    filename: 'Sanitize and validate filename',
    content: 'Scan for malware and viruses'
  },
  storage: {
    location: 'Outside web root directory',
    naming: 'Generate unique filenames',
    permissions: 'Restrict file permissions',
    scanning: 'Antivirus scanning before storage'
  }
};
```

## Advanced Security Implementation

### Task 8: Security Logging and Monitoring

#### Audit Trail Implementation
```javascript
const auditEvents = {
  authentication: ['login', 'logout', 'failed_login', 'password_change'],
  authorization: ['permission_denied', 'role_change', 'privilege_escalation'],
  data_access: ['create', 'read', 'update', 'delete', 'export'],
  system: ['config_change', 'security_event', 'error', 'performance']
};
```

#### Security Information and Event Management (SIEM)
- Structured logging with correlation IDs
- Real-time security alerting
- Automated threat response
- Compliance reporting

### Task 9: API Security Testing

#### Security Test Suite
```javascript
// Security tests to implement
const securityTests = {
  authentication: [
    'Bypass authentication tests',
    'Weak password policy tests',
    'Session fixation tests',
    'Concurrent session tests'
  ],
  authorization: [
    'Horizontal privilege escalation',
    'Vertical privilege escalation',
    'Direct object reference tests',
    'Missing access controls'
  ],
  input_validation: [
    'SQL injection tests',
    'XSS payload tests',
    'Command injection tests',
    'Path traversal tests'
  ]
};
```

## Implementation Structure

```
exercise-4/
├── server.js                  # Main application entry
├── middleware/
│   ├── authentication.js      # Auth middleware
│   ├── authorization.js       # RBAC implementation
│   ├── validation.js          # Input validation
│   ├── security.js            # Security headers
│   └── monitoring.js          # Security monitoring
├── auth/
│   ├── jwt.js                 # JWT implementation
│   ├── mfa.js                 # Multi-factor auth
│   ├── oauth.js               # OAuth 2.0 flow
│   └── apiKey.js              # API key management
├── encryption/
│   ├── fieldLevel.js          # Field encryption
│   ├── keyManagement.js       # Key rotation
│   └── tokenization.js        # Data tokenization
├── security/
│   ├── headers.js             # Security headers
│   ├── cors.js                # CORS configuration
│   ├── rateLimit.js           # Security rate limiting
│   └── monitoring.js          # Threat detection
├── validation/
│   ├── schemas.js             # Validation schemas
│   ├── sanitization.js        # Input sanitization
│   └── custom.js              # Custom validators
├── utils/
│   ├── crypto.js              # Cryptographic utilities
│   ├── logger.js              # Security logging
│   └── alerts.js              # Security alerting
└── tests/
    ├── security/              # Security test suite
    ├── penetration/           # Penetration tests
    └── compliance/            # Compliance tests
```

## Validation Criteria
- [ ] All authentication flows work securely
- [ ] RBAC system prevents unauthorized access
- [ ] Input validation prevents injection attacks
- [ ] Encryption protects data at rest and in transit
- [ ] Security headers are properly configured
- [ ] Session management is secure
- [ ] Security monitoring detects threats
- [ ] Audit logging captures all security events
- [ ] Vulnerability prevention measures are effective
- [ ] Security tests pass comprehensive suite

## Testing Scenarios
1. **Authentication bypass attempts**
2. **Privilege escalation attacks**
3. **Injection attack vectors**
4. **Session hijacking attempts**
5. **Cross-site scripting (XSS) attacks**
6. **Cross-site request forgery (CSRF)**
7. **Brute force attacks**
8. **Data exfiltration attempts**
9. **API abuse and DoS attacks**
10. **Compliance validation**

## Bonus Challenges
1. Implement OAuth 2.1 with latest security features
2. Add WebAuthn/FIDO2 support
3. Build zero-trust architecture
4. Implement homomorphic encryption
5. Add blockchain-based audit trail
6. Create automated penetration testing
7. Build security orchestration automation
8. Implement privacy-preserving analytics

## Performance Requirements
- Authentication: < 100ms per request
- Authorization: < 50ms per permission check
- Encryption: < 10ms per field operation
- Security monitoring: < 1ms overhead
- Audit logging: < 5ms per event

## Files to Submit
```
exercise-4/
├── (Full directory structure as shown above)
├── docker-compose.yml         # Security infrastructure
├── security-policy.md        # Security documentation
├── compliance-report.md       # Compliance checklist
├── package.json
└── README.md
```

## Expected Time
6-8 hours

## Resources
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [JWT Security Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

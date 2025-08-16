/**
 * API Security Fundamentals Example
 * Module 1 - Week 1: API Security Fundamentals
 * 
 * This example demonstrates essential API security practices:
 * 1. Input validation and sanitization
 * 2. Authentication and authorization
 * 3. Security headers
 * 4. HTTPS enforcement
 * 5. CORS configuration
 * 6. SQL injection prevention
 * 7. XSS protection
 * 8. Data encryption
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');

const app = express();

// =================================================================
// SECURITY CONFIGURATION
// =================================================================

// JWT Secret (in production, use environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
const IV_LENGTH = 16; // AES block size

// =================================================================
// SECURITY MIDDLEWARE
// =================================================================

// 1. Helmet - Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests from specific domains
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://yourdomain.com'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
};

app.use(cors(corsOptions));

// 3. Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP',
    retryAfter: '15 minutes'
  }
});

app.use('/api/', limiter);

// 4. Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Compression
app.use(compression());

// 6. NoSQL injection prevention
app.use(mongoSanitize({
  replaceWith: '_'
}));

// 7. HTTPS enforcement middleware (for production)
const enforceHTTPS = (req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
};

app.use(enforceHTTPS);

// =================================================================
// INPUT VALIDATION AND SANITIZATION
// =================================================================

// Comprehensive input validation middleware
const validateInput = (schema) => {
  return (req, res, next) => {
    const errors = [];

    // Validate each field according to schema
    for (const [field, rules] of Object.entries(schema)) {
      const value = req.body[field];

      // Required field validation
      if (rules.required && (!value || value.trim() === '')) {
        errors.push(`${field} is required`);
        continue;
      }

      // Skip further validation if field is not required and empty
      if (!value && !rules.required) continue;

      // Type validation
      if (rules.type === 'email' && !validator.isEmail(value)) {
        errors.push(`${field} must be a valid email`);
      }

      if (rules.type === 'string') {
        if (rules.minLength && value.length < rules.minLength) {
          errors.push(`${field} must be at least ${rules.minLength} characters`);
        }
        if (rules.maxLength && value.length > rules.maxLength) {
          errors.push(`${field} must be no more than ${rules.maxLength} characters`);
        }
        if (rules.pattern && !rules.pattern.test(value)) {
          errors.push(`${field} format is invalid`);
        }
      }

      if (rules.type === 'number') {
        const numValue = Number(value);
        if (isNaN(numValue)) {
          errors.push(`${field} must be a number`);
        } else {
          if (rules.min !== undefined && numValue < rules.min) {
            errors.push(`${field} must be at least ${rules.min}`);
          }
          if (rules.max !== undefined && numValue > rules.max) {
            errors.push(`${field} must be no more than ${rules.max}`);
          }
        }
      }

      // Custom validation functions
      if (rules.validate && typeof rules.validate === 'function') {
        const customError = rules.validate(value);
        if (customError) {
          errors.push(customError);
        }
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors
      });
    }

    // Sanitize inputs
    for (const [field, rules] of Object.entries(schema)) {
      if (req.body[field] && rules.sanitize) {
        req.body[field] = sanitizeInput(req.body[field], rules.sanitize);
      }
    }

    next();
  };
};

// Input sanitization function
const sanitizeInput = (input, sanitizeRules) => {
  let sanitized = input;

  if (sanitizeRules.includes('trim')) {
    sanitized = sanitized.trim();
  }

  if (sanitizeRules.includes('escape')) {
    sanitized = validator.escape(sanitized);
  }

  if (sanitizeRules.includes('xss')) {
    sanitized = xss(sanitized);
  }

  if (sanitizeRules.includes('toLowerCase')) {
    sanitized = sanitized.toLowerCase();
  }

  return sanitized;
};

// =================================================================
// AUTHENTICATION AND AUTHORIZATION
// =================================================================

// Mock user database (in production, use a real database)
const users = [
  {
    id: 1,
    email: 'admin@example.com',
    password: '$2b$10$6Z0xHpGUzqKfXhHFb5KzzeE.nSZ.zS1FrQZ5KzKfXhHFb5KzzeE.nS', // "admin123"
    role: 'admin',
    apiKey: 'ak_admin_12345',
    isActive: true
  },
  {
    id: 2,
    email: 'user@example.com',
    password: '$2b$10$7A1yIqHVzrLgYiIGc6Laa.fTa.aT2GsRa6Laa.7A1yIqHVzrLgYiIG', // "user123"
    role: 'user',
    apiKey: 'ak_user_67890',
    isActive: true
  }
];

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      message: 'Please provide a valid JWT token'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid token',
        message: 'Token is expired or invalid'
      });
    }
    req.user = user;
    next();
  });
};

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required',
      message: 'Please provide a valid API key in X-API-Key header'
    });
  }

  const user = users.find(u => u.apiKey === apiKey && u.isActive);

  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Invalid API key',
      message: 'API key is invalid or inactive'
    });
  }

  req.user = user;
  next();
};

// Role-based authorization middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        message: `Requires one of: ${roles.join(', ')}`
      });
    }

    next();
  };
};

// =================================================================
// ENCRYPTION/DECRYPTION UTILITIES
// =================================================================

// Encrypt sensitive data
const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

// Decrypt sensitive data
const decrypt = (encryptedData) => {
  try {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    throw new Error('Failed to decrypt data');
  }
};

// =================================================================
// SECURE API ENDPOINTS
// =================================================================

// Login endpoint with security measures
app.post('/api/auth/login', 
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // 5 attempts per 15 minutes
    message: { error: 'Too many login attempts' }
  }),
  validateInput({
    email: {
      required: true,
      type: 'email',
      sanitize: ['trim', 'toLowerCase']
    },
    password: {
      required: true,
      type: 'string',
      minLength: 6,
      sanitize: ['trim']
    }
  }),
  async (req, res) => {
    try {
      const { email, password } = req.body;

      // Find user
      const user = users.find(u => u.email === email && u.isActive);
      if (!user) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      // Generate JWT
      const token = jwt.sign(
        { 
          id: user.id, 
          email: user.email, 
          role: user.role 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            email: user.email,
            role: user.role
          }
        }
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
);

// Secure user registration
app.post('/api/auth/register',
  validateInput({
    email: {
      required: true,
      type: 'email',
      sanitize: ['trim', 'toLowerCase']
    },
    password: {
      required: true,
      type: 'string',
      minLength: 8,
      validate: (value) => {
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value)) {
          return 'Password must contain at least one lowercase letter, one uppercase letter, and one number';
        }
        return null;
      }
    },
    firstName: {
      required: true,
      type: 'string',
      maxLength: 50,
      sanitize: ['trim', 'xss']
    },
    lastName: {
      required: true,
      type: 'string',
      maxLength: 50,
      sanitize: ['trim', 'xss']
    }
  }),
  async (req, res) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = users.find(u => u.email === email);
      if (existingUser) {
        return res.status(409).json({
          success: false,
          error: 'User already exists'
        });
      }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Generate API key
      const apiKey = `ak_${crypto.randomBytes(16).toString('hex')}`;

      // Create user (in production, save to database)
      const newUser = {
        id: users.length + 1,
        email,
        password: hashedPassword,
        firstName: encrypt(firstName), // Encrypt PII
        lastName: encrypt(lastName),   // Encrypt PII
        role: 'user',
        apiKey,
        isActive: true,
        createdAt: new Date().toISOString()
      };

      users.push(newUser);

      res.status(201).json({
        success: true,
        data: {
          id: newUser.id,
          email: newUser.email,
          apiKey: newUser.apiKey,
          role: newUser.role
        },
        message: 'User registered successfully'
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Registration failed'
      });
    }
  }
);

// Protected endpoint - JWT authentication
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    data: {
      id: user.id,
      email: user.email,
      firstName: user.firstName ? decrypt(user.firstName) : null,
      lastName: user.lastName ? decrypt(user.lastName) : null,
      role: user.role
    }
  });
});

// Admin-only endpoint
app.get('/api/admin/users', authenticateToken, authorize('admin'), (req, res) => {
  const publicUserData = users.map(user => ({
    id: user.id,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt
  }));

  res.json({
    success: true,
    data: publicUserData
  });
});

// API Key protected endpoint
app.get('/api/data', authenticateApiKey, (req, res) => {
  res.json({
    success: true,
    data: {
      message: 'Sensitive data accessible via API key',
      user: {
        id: req.user.id,
        role: req.user.role
      },
      timestamp: new Date().toISOString()
    }
  });
});

// Input sanitization demonstration
app.post('/api/comments',
  authenticateToken,
  validateInput({
    content: {
      required: true,
      type: 'string',
      maxLength: 1000,
      sanitize: ['trim', 'xss']
    },
    title: {
      required: false,
      type: 'string',
      maxLength: 200,
      sanitize: ['trim', 'xss']
    }
  }),
  (req, res) => {
    const { content, title } = req.body;

    // Additional XSS protection
    const sanitizedContent = xss(content, {
      whiteList: {
        p: [],
        br: [],
        strong: [],
        em: [],
        u: []
      }
    });

    res.json({
      success: true,
      data: {
        id: Date.now(),
        title: title || null,
        content: sanitizedContent,
        author: req.user.id,
        createdAt: new Date().toISOString()
      },
      message: 'Comment created successfully (content sanitized)'
    });
  }
);

// =================================================================
// SECURITY HEADERS AND MONITORING
// =================================================================

// Security information endpoint
app.get('/api/security/info', (req, res) => {
  res.json({
    security: {
      https: req.secure || req.headers['x-forwarded-proto'] === 'https',
      headers: {
        helmet: 'enabled',
        cors: 'configured',
        csp: 'enabled',
        hsts: 'enabled'
      },
      authentication: {
        jwt: 'supported',
        apiKey: 'supported',
        rateLimiting: 'enabled'
      },
      validation: {
        inputSanitization: 'enabled',
        xssProtection: 'enabled',
        nosqlInjectionPrevention: 'enabled'
      },
      encryption: {
        piiEncryption: 'enabled',
        passwordHashing: 'bcrypt',
        algorithm: 'AES-256-CBC'
      }
    },
    recommendations: [
      'Use HTTPS in production',
      'Implement proper logging and monitoring',
      'Regular security audits',
      'Keep dependencies updated',
      'Use environment variables for secrets'
    ]
  });
});

// Security headers check endpoint
app.get('/api/security/headers', (req, res) => {
  const securityHeaders = {
    'content-security-policy': res.get('Content-Security-Policy') ? 'present' : 'missing',
    'strict-transport-security': res.get('Strict-Transport-Security') ? 'present' : 'missing',
    'x-content-type-options': res.get('X-Content-Type-Options') ? 'present' : 'missing',
    'x-frame-options': res.get('X-Frame-Options') ? 'present' : 'missing',
    'x-xss-protection': res.get('X-XSS-Protection') ? 'present' : 'missing'
  };

  res.json({
    success: true,
    securityHeaders,
    requestHeaders: {
      userAgent: req.get('User-Agent'),
      origin: req.get('Origin'),
      referer: req.get('Referer')
    }
  });
});

// =================================================================
// ERROR HANDLING
// =================================================================

// Global error handler
app.use((err, req, res, next) => {
  // Log error (in production, use proper logging)
  console.error('Error:', err.message);

  // Don't expose error details in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }

  res.status(500).json({
    success: false,
    error: err.message,
    stack: err.stack
  });
});

// CORS error handler
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: 'CORS policy violation',
      message: 'Origin not allowed'
    });
  }
  next(err);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: 'Endpoint not found',
    availableEndpoints: [
      'POST /api/auth/login',
      'POST /api/auth/register',
      'GET /api/profile (requires JWT)',
      'GET /api/admin/users (requires admin role)',
      'GET /api/data (requires API key)',
      'POST /api/comments (requires JWT)',
      'GET /api/security/info',
      'GET /api/security/headers'
    ]
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🔒 API Security Example Server running on port ${PORT}`);
  console.log('\n🛡️  Security Features Enabled:');
  console.log('  ✅ Helmet security headers');
  console.log('  ✅ CORS protection');
  console.log('  ✅ Rate limiting');
  console.log('  ✅ Input validation and sanitization');
  console.log('  ✅ JWT authentication');
  console.log('  ✅ API key authentication');
  console.log('  ✅ Role-based authorization');
  console.log('  ✅ Password hashing (bcrypt)');
  console.log('  ✅ PII encryption');
  console.log('  ✅ XSS protection');
  console.log('  ✅ NoSQL injection prevention');
  console.log('\n📚 Test endpoints:');
  console.log(`  POST http://localhost:${PORT}/api/auth/register`);
  console.log(`  POST http://localhost:${PORT}/api/auth/login`);
  console.log(`  GET  http://localhost:${PORT}/api/security/info`);
});

module.exports = app;

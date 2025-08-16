/**
 * Rate Limiting and Throttling Example
 * Module 1 - Week 1: Rate Limiting and Throttling
 * 
 * This example demonstrates different rate limiting strategies:
 * 1. Basic IP-based rate limiting
 * 2. User-based rate limiting
 * 3. Endpoint-specific rate limiting
 * 4. Sliding window rate limiting
 * 5. Token bucket algorithm
 * 6. Distributed rate limiting with Redis
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const redis = require('redis');
const { RateLimiterRedis, RateLimiterMemory } = require('rate-limiter-flexible');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =================================================================
// BASIC IP-BASED RATE LIMITING
// =================================================================

// Global rate limiter - applies to all routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply global rate limiting to all API routes
app.use('/api/', globalLimiter);

// =================================================================
// ENDPOINT-SPECIFIC RATE LIMITING
// =================================================================

// Strict rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs for auth endpoints
  message: {
    error: 'Too many authentication attempts',
    retryAfter: '15 minutes'
  },
  skipSuccessfulRequests: true, // Don't count successful requests
});

// Moderate rate limiting for data creation
const createLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: {
    error: 'Too many create requests',
    retryAfter: '1 minute'
  }
});

// Lenient rate limiting for read operations
const readLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: {
    error: 'Too many read requests',
    retryAfter: '1 minute'
  }
});

// =================================================================
// PROGRESSIVE DELAY (THROTTLING)
// =================================================================

// Slow down requests instead of blocking them
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 2, // Allow 2 requests per windowMs without delay
  delayMs: 500, // Add 500ms delay per request after delayAfter
  maxDelayMs: 20000, // Maximum delay of 20 seconds
});

// =================================================================
// USER-BASED RATE LIMITING
// =================================================================

// Mock user authentication middleware
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // In real application, verify JWT token
    req.user = { id: token, role: token === 'premium' ? 'premium' : 'basic' };
  }
  next();
};

// Dynamic rate limiting based on user type
const userBasedLimiter = (req, res, next) => {
  if (!req.user) {
    // Anonymous users: 10 requests per hour
    return rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 10,
      keyGenerator: (req) => req.ip,
      message: {
        error: 'Rate limit exceeded for anonymous users',
        suggestion: 'Please authenticate for higher limits'
      }
    })(req, res, next);
  }

  if (req.user.role === 'premium') {
    // Premium users: 1000 requests per hour
    return rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 1000,
      keyGenerator: (req) => req.user.id,
      message: {
        error: 'Rate limit exceeded for premium user'
      }
    })(req, res, next);
  } else {
    // Basic authenticated users: 100 requests per hour
    return rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 100,
      keyGenerator: (req) => req.user.id,
      message: {
        error: 'Rate limit exceeded for basic user',
        suggestion: 'Upgrade to premium for higher limits'
      }
    })(req, res, next);
  }
};

// =================================================================
// ADVANCED RATE LIMITING WITH rate-limiter-flexible
// =================================================================

// Memory-based rate limiter with more advanced features
const advancedRateLimiter = new RateLimiterMemory({
  keyPrefix: 'middleware',
  points: 5, // 5 requests
  duration: 60, // 1 minute
  blockDuration: 60, // Block for 1 minute if limit exceeded
});

// Sliding window rate limiter
const slidingWindowLimiter = new RateLimiterMemory({
  keyPrefix: 'sliding_window',
  points: 10, // 10 requests
  duration: 60, // per 60 seconds
  blockDuration: 60, // block for 60 seconds
  execEvenly: true, // Spread requests evenly across the duration
});

// Rate limiter middleware factory
const rateLimitMiddleware = (limiter, keyGenerator = (req) => req.ip) => {
  return async (req, res, next) => {
    try {
      const key = keyGenerator(req);
      await limiter.consume(key);
      next();
    } catch (resRateLimiter) {
      const secs = Math.round(resRateLimiter.msBeforeNext / 1000) || 1;
      res.set('Retry-After', String(secs));
      res.set('X-RateLimit-Limit', limiter.points);
      res.set('X-RateLimit-Remaining', resRateLimiter.remainingPoints || 0);
      res.set('X-RateLimit-Reset', new Date(Date.now() + resRateLimiter.msBeforeNext));
      
      res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: secs,
        limit: limiter.points,
        remaining: resRateLimiter.remainingPoints || 0
      });
    }
  };
};

// =================================================================
// REDIS-BASED DISTRIBUTED RATE LIMITING
// =================================================================

let redisRateLimiter;

// Initialize Redis rate limiter (optional - falls back to memory if Redis unavailable)
const initializeRedisRateLimiter = async () => {
  try {
    const redisClient = redis.createClient({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
    });

    await redisClient.connect();

    redisRateLimiter = new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'distributed_rl',
      points: 50, // 50 requests
      duration: 60, // per 60 seconds
      blockDuration: 60, // block for 60 seconds
    });

    console.log('✅ Redis rate limiter initialized');
  } catch (error) {
    console.warn('⚠️  Redis unavailable, falling back to memory rate limiter');
    redisRateLimiter = new RateLimiterMemory({
      keyPrefix: 'memory_rl',
      points: 50,
      duration: 60,
      blockDuration: 60,
    });
  }
};

// =================================================================
// TOKEN BUCKET IMPLEMENTATION
// =================================================================

class TokenBucket {
  constructor(capacity, tokensPerInterval, interval) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.tokensPerInterval = tokensPerInterval;
    this.interval = interval;
    this.lastRefill = Date.now();
  }

  consume(tokens = 1) {
    this.refill();

    if (tokens <= this.tokens) {
      this.tokens -= tokens;
      return true;
    }

    return false;
  }

  refill() {
    const now = Date.now();
    const timePassed = now - this.lastRefill;
    const tokensToAdd = Math.floor((timePassed / this.interval) * this.tokensPerInterval);

    if (tokensToAdd > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }

  getTokens() {
    this.refill();
    return this.tokens;
  }
}

// Token bucket storage (in production, use Redis or database)
const tokenBuckets = new Map();

const tokenBucketMiddleware = (capacity, tokensPerInterval, interval) => {
  return (req, res, next) => {
    const key = req.ip;
    
    if (!tokenBuckets.has(key)) {
      tokenBuckets.set(key, new TokenBucket(capacity, tokensPerInterval, interval));
    }

    const bucket = tokenBuckets.get(key);

    if (bucket.consume(1)) {
      res.set('X-RateLimit-Bucket-Tokens', bucket.getTokens());
      res.set('X-RateLimit-Bucket-Capacity', capacity);
      next();
    } else {
      res.status(429).json({
        error: 'Rate limit exceeded - no tokens available',
        tokensRemaining: bucket.getTokens(),
        capacity: capacity
      });
    }
  };
};

// =================================================================
// API ENDPOINTS WITH DIFFERENT RATE LIMITING STRATEGIES
// =================================================================

// Public endpoint with basic rate limiting
app.get('/api/public/data', readLimiter, (req, res) => {
  res.json({
    message: 'Public data endpoint',
    rateLimitStrategy: 'Basic IP-based limiting',
    timestamp: new Date().toISOString()
  });
});

// Authentication endpoint with strict rate limiting
app.post('/api/auth/login', authLimiter, (req, res) => {
  res.json({
    message: 'Login endpoint (demo)',
    rateLimitStrategy: 'Strict authentication limiting',
    token: 'demo-token'
  });
});

// User-based rate limited endpoint
app.get('/api/user/profile', authenticateUser, userBasedLimiter, (req, res) => {
  res.json({
    message: 'User profile data',
    rateLimitStrategy: 'User-based limiting',
    user: req.user || 'anonymous',
    timestamp: new Date().toISOString()
  });
});

// Progressive delay endpoint
app.get('/api/throttled', speedLimiter, (req, res) => {
  res.json({
    message: 'Throttled endpoint with progressive delays',
    rateLimitStrategy: 'Progressive delay throttling',
    timestamp: new Date().toISOString()
  });
});

// Advanced rate limiter endpoint
app.get('/api/advanced', rateLimitMiddleware(advancedRateLimiter), (req, res) => {
  res.json({
    message: 'Advanced rate limited endpoint',
    rateLimitStrategy: 'rate-limiter-flexible with blocking',
    timestamp: new Date().toISOString()
  });
});

// Sliding window rate limiter
app.get('/api/sliding', rateLimitMiddleware(slidingWindowLimiter), (req, res) => {
  res.json({
    message: 'Sliding window rate limited endpoint',
    rateLimitStrategy: 'Sliding window with even distribution',
    timestamp: new Date().toISOString()
  });
});

// Token bucket endpoint
app.get('/api/token-bucket', tokenBucketMiddleware(10, 5, 1000), (req, res) => {
  res.json({
    message: 'Token bucket rate limited endpoint',
    rateLimitStrategy: 'Token bucket algorithm',
    timestamp: new Date().toISOString()
  });
});

// Distributed rate limiter (requires Redis)
app.get('/api/distributed', async (req, res, next) => {
  if (!redisRateLimiter) {
    return res.status(503).json({
      error: 'Distributed rate limiter not available',
      message: 'Redis connection required'
    });
  }

  rateLimitMiddleware(redisRateLimiter)(req, res, next);
}, (req, res) => {
  res.json({
    message: 'Distributed rate limited endpoint',
    rateLimitStrategy: 'Redis-based distributed limiting',
    timestamp: new Date().toISOString()
  });
});

// Create operation with specific limiting
app.post('/api/users', createLimiter, (req, res) => {
  res.json({
    message: 'User creation endpoint (demo)',
    rateLimitStrategy: 'Create operation limiting',
    data: req.body,
    timestamp: new Date().toISOString()
  });
});

// =================================================================
// RATE LIMIT MONITORING AND ANALYTICS
// =================================================================

// Rate limit status endpoint
app.get('/api/rate-limit/status', (req, res) => {
  const ip = req.ip;
  
  res.json({
    ip: ip,
    globalLimit: {
      windowMs: 15 * 60 * 1000,
      max: 100,
      strategy: 'sliding-window'
    },
    endpointLimits: {
      '/api/auth/login': { max: 5, windowMs: 15 * 60 * 1000 },
      '/api/users': { max: 10, windowMs: 60 * 1000 },
      '/api/public/data': { max: 60, windowMs: 60 * 1000 }
    },
    userBasedLimits: {
      anonymous: { max: 10, windowMs: 60 * 60 * 1000 },
      basic: { max: 100, windowMs: 60 * 60 * 1000 },
      premium: { max: 1000, windowMs: 60 * 60 * 1000 }
    },
    timestamp: new Date().toISOString()
  });
});

// Rate limit configuration endpoint
app.get('/api/rate-limit/config', (req, res) => {
  res.json({
    strategies: [
      {
        name: 'Fixed Window',
        description: 'Simple counter reset at fixed intervals',
        endpoints: ['/api/public/data', '/api/auth/login']
      },
      {
        name: 'Sliding Window',
        description: 'More accurate rate limiting with rolling window',
        endpoints: ['/api/advanced', '/api/sliding']
      },
      {
        name: 'Token Bucket',
        description: 'Allows burst traffic up to bucket capacity',
        endpoints: ['/api/token-bucket']
      },
      {
        name: 'Progressive Delay',
        description: 'Adds delay instead of blocking requests',
        endpoints: ['/api/throttled']
      },
      {
        name: 'User-based',
        description: 'Different limits based on user authentication',
        endpoints: ['/api/user/profile']
      }
    ],
    headers: {
      'X-RateLimit-Limit': 'Number of allowed requests',
      'X-RateLimit-Remaining': 'Number of remaining requests',
      'X-RateLimit-Reset': 'Time when the rate limit resets',
      'Retry-After': 'Seconds to wait before making another request'
    }
  });
});

// =================================================================
// ERROR HANDLING AND MONITORING
// =================================================================

// Rate limit exceeded handler
app.use((err, req, res, next) => {
  if (err.statusCode === 429) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests, please slow down',
      timestamp: new Date().toISOString(),
      endpoint: req.path,
      ip: req.ip
    });
  }
  next(err);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'Endpoint not found',
    availableEndpoints: [
      'GET /api/public/data - Basic rate limiting',
      'POST /api/auth/login - Strict authentication limiting',
      'GET /api/user/profile - User-based limiting (requires Authorization header)',
      'GET /api/throttled - Progressive delay throttling',
      'GET /api/advanced - Advanced rate limiting with blocking',
      'GET /api/sliding - Sliding window rate limiting',
      'GET /api/token-bucket - Token bucket algorithm',
      'GET /api/distributed - Distributed rate limiting (requires Redis)',
      'POST /api/users - Create operation limiting',
      'GET /api/rate-limit/status - Rate limit status information',
      'GET /api/rate-limit/config - Rate limiting configuration'
    ]
  });
});

// =================================================================
// SERVER INITIALIZATION
// =================================================================

const PORT = process.env.PORT || 3000;

// Initialize Redis rate limiter
initializeRedisRateLimiter().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Rate Limiting Example Server running on port ${PORT}`);
    console.log('\n📚 Available endpoints:');
    console.log(`  GET  http://localhost:${PORT}/api/public/data`);
    console.log(`  POST http://localhost:${PORT}/api/auth/login`);
    console.log(`  GET  http://localhost:${PORT}/api/user/profile`);
    console.log(`  GET  http://localhost:${PORT}/api/throttled`);
    console.log(`  GET  http://localhost:${PORT}/api/advanced`);
    console.log(`  GET  http://localhost:${PORT}/api/sliding`);
    console.log(`  GET  http://localhost:${PORT}/api/token-bucket`);
    console.log(`  GET  http://localhost:${PORT}/api/distributed`);
    console.log(`  POST http://localhost:${PORT}/api/users`);
    console.log('\n📊 Monitoring endpoints:');
    console.log(`  GET  http://localhost:${PORT}/api/rate-limit/status`);
    console.log(`  GET  http://localhost:${PORT}/api/rate-limit/config`);
    console.log('\n💡 Test with curl:');
    console.log(`  curl http://localhost:${PORT}/api/public/data`);
    console.log(`  curl -H "Authorization: Bearer premium" http://localhost:${PORT}/api/user/profile`);
  });
});

module.exports = app;

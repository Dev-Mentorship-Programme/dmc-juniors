import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
// express-slow-down lacks official types in some versions; use require type fallback
// eslint-disable-next-line @typescript-eslint/no-var-requires
const slowDown = require('express-slow-down');
import { createClient } from 'redis';
import { RateLimiterRedis, RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests from this IP',
    retryAfter: '15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', globalLimiter);

// Endpoint-specific rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many authentication attempts', retryAfter: '15 minutes' },
  skipSuccessfulRequests: true,
});

const createLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many create requests', retryAfter: '1 minute' },
});

const readLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many read requests', retryAfter: '1 minute' },
});

// Progressive delay
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 2,
  delayMs: 500,
  maxDelayMs: 20000,
});

// Mock auth
type AuthedRequest = Request & { user?: { id: string; role: 'basic' | 'premium' } };
const authenticateUser = (req: AuthedRequest, _res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    req.user = { id: token, role: token === 'premium' ? 'premium' : 'basic' };
  }
  next();
};

// User-based limiter
const userBasedLimiter = (req: AuthedRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    return rateLimit({ windowMs: 60 * 60 * 1000, max: 10, keyGenerator: (r: Request) => String(r.ip || req.ip || 'anonymous'), message: { error: 'Rate limit exceeded for anonymous users', suggestion: 'Please authenticate for higher limits' } })(req, res, next);
  }
  if (req.user.role === 'premium') {
    return rateLimit({ windowMs: 60 * 60 * 1000, max: 1000, keyGenerator: () => String(req.user!.id), message: { error: 'Rate limit exceeded for premium user' } })(req, res, next);
  }
  return rateLimit({ windowMs: 60 * 60 * 1000, max: 100, keyGenerator: () => String(req.user!.id), message: { error: 'Rate limit exceeded for basic user', suggestion: 'Upgrade to premium for higher limits' } })(req, res, next);
};

// rate-limiter-flexible
const advancedRateLimiter = new RateLimiterMemory({ keyPrefix: 'middleware', points: 5, duration: 60, blockDuration: 60 });
const slidingWindowLimiter = new RateLimiterMemory({ keyPrefix: 'sliding_window', points: 10, duration: 60, blockDuration: 60, execEvenly: true });

type KeyGen = (req: Request) => string;
const rateLimitMiddleware = (limiter: RateLimiterMemory | RateLimiterRedis, keyGenerator: KeyGen = (r: Request) => String(r.ip)) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
  const key = keyGenerator(req) || String(req.ip);
      await limiter.consume(key);
      next();
    } catch (e) {
      const resRateLimiter = e as RateLimiterRes;
      const secs = Math.round((resRateLimiter.msBeforeNext || 1000) / 1000) || 1;
      res.set('Retry-After', String(secs));
      res.set('X-RateLimit-Limit', String((limiter as any).points));
      res.set('X-RateLimit-Remaining', String(resRateLimiter.remainingPoints ?? 0));
      res.set('X-RateLimit-Reset', new Date(Date.now() + (resRateLimiter.msBeforeNext || 0)).toISOString());
      res.status(429).json({ error: 'Rate limit exceeded', retryAfter: secs, limit: (limiter as any).points, remaining: resRateLimiter.remainingPoints ?? 0 });
    }
  };
};

let redisRateLimiter: RateLimiterRedis | RateLimiterMemory | undefined;
const initializeRedisRateLimiter = async () => {
  try {
    const client = createClient({
      url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
    });
    await client.connect();
    redisRateLimiter = new RateLimiterRedis({ storeClient: client as any, keyPrefix: 'distributed_rl', points: 50, duration: 60, blockDuration: 60 });
    console.log('✅ Redis rate limiter initialized');
  } catch {
    console.warn('⚠️  Redis unavailable, falling back to memory rate limiter');
    redisRateLimiter = new RateLimiterMemory({ keyPrefix: 'memory_rl', points: 50, duration: 60, blockDuration: 60 });
  }
};

// Token Bucket
class TokenBucket {
  private capacity: number;
  private tokens: number;
  private tokensPerInterval: number;
  private interval: number;
  private lastRefill: number;

  constructor(capacity: number, tokensPerInterval: number, interval: number) {
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

const tokenBuckets = new Map<string, TokenBucket>();
const tokenBucketMiddleware = (capacity: number, tokensPerInterval: number, interval: number) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = String(req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown');
    if (!tokenBuckets.has(key)) {
      tokenBuckets.set(key, new TokenBucket(capacity, tokensPerInterval, interval));
    }
    const bucket = tokenBuckets.get(key)!;
    if (bucket.consume(1)) {
      res.set('X-RateLimit-Bucket-Tokens', String(bucket.getTokens()));
      res.set('X-RateLimit-Bucket-Capacity', String(capacity));
      next();
    } else {
      res.status(429).json({ error: 'Rate limit exceeded - no tokens available', tokensRemaining: bucket.getTokens(), capacity });
    }
  };
};

// Endpoints
app.get('/api/public/data', readLimiter, (_req: Request, res: Response) => {
  res.json({ message: 'Public data endpoint', rateLimitStrategy: 'Basic IP-based limiting', timestamp: new Date().toISOString() });
});

app.post('/api/auth/login', authLimiter, (req: Request, res: Response) => {
  res.json({ message: 'Login endpoint (demo)', rateLimitStrategy: 'Strict authentication limiting', token: 'demo-token' });
});

app.get('/api/user/profile', authenticateUser, userBasedLimiter, (req: AuthedRequest, res: Response) => {
  res.json({ message: 'User profile data', rateLimitStrategy: 'User-based limiting', user: req.user || 'anonymous', timestamp: new Date().toISOString() });
});

app.get('/api/throttled', speedLimiter, (_req: Request, res: Response) => {
  res.json({ message: 'Throttled endpoint with progressive delays', rateLimitStrategy: 'Progressive delay throttling', timestamp: new Date().toISOString() });
});

app.get('/api/advanced', rateLimitMiddleware(advancedRateLimiter), (_req: Request, res: Response) => {
  res.json({ message: 'Advanced rate limited endpoint', rateLimitStrategy: 'rate-limiter-flexible with blocking', timestamp: new Date().toISOString() });
});

app.get('/api/sliding', rateLimitMiddleware(slidingWindowLimiter), (_req: Request, res: Response) => {
  res.json({ message: 'Sliding window rate limited endpoint', rateLimitStrategy: 'Sliding window with even distribution', timestamp: new Date().toISOString() });
});

app.get('/api/token-bucket', tokenBucketMiddleware(10, 5, 1000), (_req: Request, res: Response) => {
  res.json({ message: 'Token bucket rate limited endpoint', rateLimitStrategy: 'Token bucket algorithm', timestamp: new Date().toISOString() });
});

app.get('/api/distributed', async (req: Request, res: Response, next: NextFunction) => {
  if (!redisRateLimiter) {
    return res.status(503).json({ error: 'Distributed rate limiter not available', message: 'Redis connection required' });
  }
  return (rateLimitMiddleware(redisRateLimiter) as any)(req, res, next);
}, (_req: Request, res: Response) => {
  res.json({ message: 'Distributed rate limited endpoint', rateLimitStrategy: 'Redis-based distributed limiting', timestamp: new Date().toISOString() });
});

app.post('/api/users', createLimiter, (req: Request, res: Response) => {
  res.json({ message: 'User creation endpoint (demo)', rateLimitStrategy: 'Create operation limiting', data: req.body, timestamp: new Date().toISOString() });
});

app.get('/api/rate-limit/status', (req: Request, res: Response) => {
  const ip = req.ip;
  res.json({
    ip,
    globalLimit: { windowMs: 15 * 60 * 1000, max: 100, strategy: 'sliding-window' },
    endpointLimits: { '/api/auth/login': { max: 5, windowMs: 15 * 60 * 1000 }, '/api/users': { max: 10, windowMs: 60 * 1000 }, '/api/public/data': { max: 60, windowMs: 60 * 1000 } },
    userBasedLimits: { anonymous: { max: 10, windowMs: 60 * 60 * 1000 }, basic: { max: 100, windowMs: 60 * 60 * 1000 }, premium: { max: 1000, windowMs: 60 * 60 * 1000 } },
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/rate-limit/config', (_req: Request, res: Response) => {
  res.json({
    strategies: [
      { name: 'Fixed Window', description: 'Simple counter reset at fixed intervals', endpoints: ['/api/public/data', '/api/auth/login'] },
      { name: 'Sliding Window', description: 'More accurate rate limiting with rolling window', endpoints: ['/api/advanced', '/api/sliding'] },
      { name: 'Token Bucket', description: 'Allows burst traffic up to bucket capacity', endpoints: ['/api/token-bucket'] },
      { name: 'Progressive Delay', description: 'Adds delay instead of blocking requests', endpoints: ['/api/throttled'] },
      { name: 'User-based', description: 'Different limits based on user authentication', endpoints: ['/api/user/profile'] },
    ],
    headers: {
      'X-RateLimit-Limit': 'Number of allowed requests',
      'X-RateLimit-Remaining': 'Number of remaining requests',
      'X-RateLimit-Reset': 'Time when the rate limit resets',
      'Retry-After': 'Seconds to wait before making another request',
    },
  });
});

// Error handlers
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err && (err.statusCode === 429 || err.httpStatus === 429)) {
    return res.status(429).json({ error: 'Rate limit exceeded', message: 'Too many requests, please slow down', timestamp: new Date().toISOString(), endpoint: req.path, ip: req.ip });
  }
  return next(err);
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'Endpoint not found',
    availableEndpoints: [
      'GET /api/public/data',
      'POST /api/auth/login',
      'GET /api/user/profile',
      'GET /api/throttled',
      'GET /api/advanced',
      'GET /api/sliding',
      'GET /api/token-bucket',
      'GET /api/distributed',
      'POST /api/users',
      'GET /api/rate-limit/status',
      'GET /api/rate-limit/config',
    ],
  });
});

const PORT = Number(process.env.PORT || 3000);
initializeRedisRateLimiter().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Rate Limiting Example Server running on port ${PORT}`);
  });
});

export default app;

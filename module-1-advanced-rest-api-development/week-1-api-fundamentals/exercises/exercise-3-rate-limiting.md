# Exercise 3: Advanced Rate Limiting and Throttling

## Objective
Build a comprehensive rate limiting system that can handle various scenarios and protect API endpoints from abuse while providing a good user experience.

## Scenario
You're developing an API for a social media platform that needs to handle millions of requests per day. Different endpoints have different usage patterns and security requirements.

## Requirements

### Endpoint Categories
1. **Public endpoints**: `/api/posts`, `/api/users/{id}/profile` (100 req/min per IP)
2. **Authenticated endpoints**: `/api/posts`, `/api/comments` (300 req/min per user)
3. **Premium endpoints**: `/api/analytics`, `/api/export` (1000 req/min per premium user)
4. **Admin endpoints**: `/api/admin/*` (No limits for admins)
5. **Critical endpoints**: `/api/auth/login` (5 attempts per 15 min per IP)

## Tasks

### Task 1: Basic Rate Limiting
Implement rate limiting using different algorithms:

#### Fixed Window Algorithm
- Track requests per fixed time window
- Reset counter at window boundary
- Simple but can cause traffic spikes

#### Sliding Window Algorithm
- Track requests over rolling time period
- More accurate rate limiting
- Prevents burst allowance gaming

#### Token Bucket Algorithm
- Allow burst traffic up to bucket capacity
- Refill tokens at steady rate
- Good for APIs with variable load

**Implementation Requirements:**
```javascript
// Rate limiter configuration
const rateLimitConfig = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // requests per window
  algorithm: 'sliding_window', // fixed_window, sliding_window, token_bucket
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  keyGenerator: (req) => req.ip + ':' + req.user?.id
};
```

### Task 2: Multi-Tier Rate Limiting
Implement different limits based on user tiers:

```javascript
const tierLimits = {
  free: { requests: 100, windowMs: 3600000 }, // 100/hour
  premium: { requests: 1000, windowMs: 3600000 }, // 1000/hour
  enterprise: { requests: 10000, windowMs: 3600000 }, // 10k/hour
  admin: { requests: -1, windowMs: 0 } // unlimited
};
```

**Features to implement:**
- User tier detection middleware
- Dynamic limit adjustment
- Tier upgrade handling
- Usage analytics per tier

### Task 3: Distributed Rate Limiting
Implement rate limiting across multiple server instances:

**Requirements:**
- Use Redis as shared storage
- Handle Redis connection failures gracefully
- Implement local fallback when Redis is unavailable
- Synchronize counters across instances

```javascript
// Redis-based rate limiter
const distributedLimiter = {
  store: 'redis',
  redisConfig: {
    host: 'localhost',
    port: 6379,
    db: 0
  },
  fallback: 'memory', // fallback when Redis fails
  syncInterval: 1000 // ms
};
```

### Task 4: Intelligent Rate Limiting
Build advanced features:

#### Adaptive Rate Limiting
- Adjust limits based on server load
- Monitor response times and error rates
- Scale limits automatically

#### Progressive Penalties
- Increase penalties for repeated violations
- Temporary account suspension
- Exponential backoff recommendations

#### Whitelist/Blacklist System
- IP-based whitelist for trusted sources
- Automatic blacklist for abusive IPs
- Geographic restrictions

### Task 5: Rate Limit Headers and Responses
Implement proper HTTP headers and responses:

**Headers to include:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
X-RateLimit-Policy: 100;w=3600;comment="Sliding window"
Retry-After: 60
```

**Error Response Format:**
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "limit": 100,
      "remaining": 0,
      "resetTime": "2023-12-31T15:30:00Z",
      "retryAfter": 60
    },
    "suggestions": [
      "Implement exponential backoff",
      "Consider upgrading to premium tier",
      "Distribute requests more evenly"
    ]
  }
}
```

## Advanced Features

### Task 6: Custom Rate Limiting Strategies
Implement specialized rate limiting for specific use cases:

#### API Key-based Limiting
```javascript
const apiKeyLimits = {
  'key_123': { requests: 10000, windowMs: 3600000 },
  'key_456': { requests: 5000, windowMs: 3600000 }
};
```

#### Endpoint-specific Limiting
```javascript
const endpointLimits = {
  'POST /api/posts': { requests: 10, windowMs: 300000 }, // 10 posts per 5 min
  'GET /api/search': { requests: 100, windowMs: 60000 }, // 100 searches per min
  'POST /api/auth/login': { requests: 5, windowMs: 900000 } // 5 login attempts per 15 min
};
```

#### Burst Protection
- Allow small bursts but enforce average rate
- Implement leaky bucket algorithm
- Handle traffic spikes gracefully

### Task 7: Rate Limiting Analytics
Build a monitoring and analytics system:

**Metrics to Track:**
- Requests per second/minute/hour
- Rate limit violations per endpoint
- Top violating IPs/users
- Usage patterns by user tier
- Server performance impact

**Dashboard Features:**
- Real-time rate limiting status
- Historical usage trends
- Abuse detection alerts
- Performance impact metrics

## Implementation Structure

### Middleware Architecture
```
exercise-3/
├── middleware/
│   ├── rateLimiter.js          # Main rate limiting middleware
│   ├── tierDetection.js        # User tier detection
│   ├── adaptiveLimiting.js     # Adaptive rate adjustment
│   └── analytics.js            # Usage tracking
├── algorithms/
│   ├── fixedWindow.js          # Fixed window implementation
│   ├── slidingWindow.js        # Sliding window implementation
│   └── tokenBucket.js          # Token bucket implementation
├── stores/
│   ├── memory.js               # In-memory storage
│   ├── redis.js                # Redis storage
│   └── hybrid.js               # Hybrid memory + Redis
├── config/
│   ├── limits.js               # Rate limit configurations
│   └── tiers.js                # User tier definitions
└── utils/
    ├── headers.js              # Rate limit headers
    ├── responses.js            # Error responses
    └── monitoring.js           # Metrics collection
```

## Validation Criteria
- [ ] All rate limiting algorithms work correctly
- [ ] Multi-tier system functions properly
- [ ] Distributed rate limiting with Redis works
- [ ] Proper HTTP headers and responses
- [ ] Adaptive limiting adjusts based on load
- [ ] Analytics and monitoring work
- [ ] Graceful handling of edge cases
- [ ] Performance impact is minimal

## Testing Scenarios
1. **Load testing**: Send 1000 requests simultaneously
2. **Tier switching**: User upgrades during active session
3. **Redis failure**: Test fallback mechanisms
4. **Geographic restrictions**: Test location-based limiting
5. **Burst traffic**: Test token bucket with sudden spikes
6. **Distributed setup**: Test across multiple server instances

## Bonus Challenges
1. Implement GraphQL query complexity-based rate limiting
2. Add machine learning for abuse detection
3. Build rate limiting for WebSocket connections
4. Implement priority queuing for different user tiers
5. Add geographic load balancing with region-specific limits
6. Create automated DDoS protection
7. Build rate limiting SDK for client applications

## Performance Requirements
- Rate limiting decision: < 1ms average
- Memory usage: < 100MB for 1M users
- Redis operations: < 500μs per request
- Minimal impact on response times

## Files to Submit
```
exercise-3/
├── server.js
├── middleware/ (as described above)
├── algorithms/ (as described above)
├── stores/ (as described above)
├── config/ (as described above)
├── utils/ (as described above)
├── tests/
│   ├── load-test.js
│   ├── integration-test.js
│   └── performance-test.js
├── package.json
└── README.md
```

## Expected Time
4-5 hours

## Resources
- [Rate Limiting Algorithms](https://konghq.com/blog/how-to-design-a-scalable-rate-limiting-algorithm)
- [Redis Rate Limiting Patterns](https://redis.io/docs/reference/patterns/distributed-locks/)
- [HTTP Rate Limiting](https://tools.ietf.org/id/draft-polli-ratelimit-headers-00.html)

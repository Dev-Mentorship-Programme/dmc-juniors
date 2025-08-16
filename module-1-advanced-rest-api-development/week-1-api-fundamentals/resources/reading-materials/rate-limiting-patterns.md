# Rate Limiting Patterns

## 📘 Fundamental Concepts

### Why Rate Limiting is Essential
- **[The Importance of API Rate Limiting](https://blog.cloudflare.com/rate-limiting-api-protection/)**
  - DoS attack prevention
  - Resource protection strategies
  - Fair usage enforcement
  - Business model support

- **[API Rate Limiting Best Practices](https://nordicapis.com/everything-you-need-to-know-about-api-rate-limiting/)**
  - User experience considerations
  - Business impact analysis
  - Implementation strategies

### Core Concepts
- **[Understanding Rate Limiting Algorithms](https://konghq.com/blog/how-to-design-a-scalable-rate-limiting-algorithm)**
  - Traffic shaping principles
  - Burst vs sustained traffic
  - Distributed systems considerations

## 🔢 Rate Limiting Algorithms

### Fixed Window Algorithm
- **[Fixed Window Rate Limiting](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)**
  - Simple counter-based approach
  - Memory efficiency benefits
  - Traffic spike vulnerabilities

#### Implementation Characteristics
```
Window: 1 minute
Limit: 100 requests
Reset: At minute boundary (00:00, 01:00, 02:00...)

Pros: Simple, memory efficient
Cons: Traffic spikes at window boundaries
```

- **[Fixed Window Implementation Patterns](https://redis.io/docs/reference/patterns/rate-limiting/)**
  - Redis-based counters
  - Atomic operations
  - TTL management

### Sliding Window Log
- **[Sliding Window Rate Limiting](https://www.figma.com/blog/an-alternative-approach-to-rate-limiting/)**
  - Timestamp-based tracking
  - Accurate rate limiting
  - Memory overhead considerations

#### Design Patterns
```
Algorithm: Track individual request timestamps
Window: Rolling 1-minute window
Accuracy: Perfect (no burst allowance)
Memory: O(n) where n = requests in window

Pros: Most accurate
Cons: High memory usage for high-traffic APIs
```

- **[Sliding Window Optimizations](https://engineering.classdojo.com/blog/2015/02/06/rolling-rate-limiter/)**
  - Memory optimization techniques
  - Garbage collection strategies
  - Performance considerations

### Token Bucket Algorithm
- **[Token Bucket Rate Limiting](https://en.wikipedia.org/wiki/Token_bucket)**
  - Burst traffic accommodation
  - Steady-state rate control
  - Quality of service applications

#### Implementation Details
```javascript
// Token Bucket Parameters
const bucket = {
  capacity: 100,        // Maximum tokens
  tokens: 100,          // Current tokens
  refillRate: 10,       // Tokens per second
  lastRefill: Date.now()
};

// Allow bursts up to capacity
// Sustain average rate over time
```

- **[Token Bucket vs Leaky Bucket](https://stackoverflow.com/questions/667508/whats-the-difference-between-a-token-bucket-and-a-leaky-bucket-counter)**
  - Algorithm comparison
  - Use case optimization
  - Implementation complexity

### Leaky Bucket Algorithm
- **[Leaky Bucket Implementation](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)**
  - Queue-based traffic shaping
  - Smooth output rate
  - Buffer overflow handling

#### Characteristics
```
Queue Processing: FIFO
Output Rate: Constant
Buffer Size: Fixed capacity
Overflow: Request rejection

Best for: Protecting downstream services
Use case: Traffic smoothing
```

### Sliding Window Counter
- **[Hybrid Sliding Window Approach](https://hechao.li/2018/06/25/Rate-Limiter-Part1/)**
  - Memory efficiency of fixed window
  - Accuracy improvements
  - Implementation simplicity

#### Algorithm Overview
```
Previous Window: 70 requests
Current Window: 30 requests  
Window Progress: 40% through current

Estimated Count: 70 * (1 - 0.4) + 30 = 72 requests
Limit Check: 72 < 100 ✓ Allow
```

## 🏗 Advanced Rate Limiting Patterns

### Hierarchical Rate Limiting
- **[Multi-Level Rate Limiting](https://stripe.com/blog/rate-limiters)**
  - Global limits
  - Per-user limits
  - Per-endpoint limits
  - Per-IP limits

#### Implementation Strategy
```javascript
const hierarchicalLimits = {
  global: { requests: 10000, window: '1m' },
  perUser: { requests: 100, window: '1m' },
  perIP: { requests: 50, window: '1m' },
  perEndpoint: {
    '/api/search': { requests: 20, window: '1m' },
    '/api/upload': { requests: 5, window: '5m' }
  }
};
```

- **[Nested Rate Limiting Patterns](https://blog.cloudflare.com/rate-limiting-with-cloudflare-workers/)**
  - Cascade evaluation
  - Early termination optimization
  - Resource allocation strategies

### Adaptive Rate Limiting
- **[Dynamic Rate Limiting](https://blog.cloudflare.com/smart-rate-limiting/)**
  - Server load-based adjustment
  - User behavior analysis
  - ML-driven limit optimization

#### Implementation Approaches
```javascript
// Server load adaptation
const adaptiveRate = baseRate * (1 - cpuUtilization);

// User behavior analysis
const userRate = baseRate * trustScore * tierMultiplier;

// Time-based adjustment
const timeRate = baseRate * getTimeOfDayMultiplier();
```

- **[Circuit Breaker Pattern Integration](https://martinfowler.com/bliki/CircuitBreaker.html)**
  - Failure state management
  - Recovery strategies
  - Fallback mechanisms

### Distributed Rate Limiting
- **[Distributed Rate Limiting Strategies](https://blog.figma.com/an-alternative-approach-to-rate-limiting-f8a06cf7c94c)**
  - Cross-instance synchronization
  - Eventual consistency handling
  - Performance optimization

#### Architecture Patterns
```
Centralized: Single Redis instance
- Pros: Accurate, simple
- Cons: Single point of failure

Distributed: Multiple Redis shards
- Pros: Scalable, fault tolerant
- Cons: Complex consistency

Local + Sync: Local counters with periodic sync
- Pros: Fast, resilient
- Cons: Less accurate
```

## 🛠 Implementation Technologies

### Redis-Based Solutions
- **[Redis Rate Limiting Patterns](https://redis.io/docs/reference/patterns/rate-limiting/)**
  - Atomic operations with Lua scripts
  - TTL-based cleanup
  - Memory optimization

#### Redis Implementation Examples
```lua
-- Sliding Window Counter in Lua
local current = redis.call('incr', KEYS[1])
if current == 1 then
    redis.call('expire', KEYS[1], ARGV[1])
end
if current > tonumber(ARGV[2]) then
    return {0, ARGV[1]}
end
return {1, ARGV[1]}
```

- **[Redis Cluster Rate Limiting](https://redis.io/docs/reference/cluster-spec/)**
  - Sharding strategies
  - Hash slot distribution
  - Cross-shard operations

### In-Memory Solutions
- **[In-Memory Rate Limiting](https://github.com/animir/node-rate-limiter-flexible)**
  - Local state management
  - Single-instance scenarios
  - Development environments

#### Memory Management
```javascript
// LRU Cache for rate limit data
const LRU = require('lru-cache');
const rateLimitCache = new LRU({
  max: 10000,
  ttl: 1000 * 60 * 60 // 1 hour
});
```

### Database-Backed Solutions
- **[Database Rate Limiting Patterns](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)**
  - Persistent state management
  - Audit trail capabilities
  - Complex query requirements

#### SQL Implementation
```sql
-- Sliding window query
SELECT COUNT(*) FROM requests 
WHERE user_id = ? 
  AND created_at > NOW() - INTERVAL 1 HOUR;

-- Cleanup old records
DELETE FROM requests 
WHERE created_at < NOW() - INTERVAL 24 HOUR;
```

## 🔒 Security-Focused Rate Limiting

### DDoS Protection
- **[DDoS Mitigation with Rate Limiting](https://blog.cloudflare.com/ddos-attack-trends-for-2021-q1/)**
  - Attack pattern recognition
  - Automatic blacklisting
  - Geographic blocking

#### Protection Strategies
```javascript
const ddosProtection = {
  suspiciousThresholds: {
    requests: 1000,      // requests per minute
    distinctPaths: 50,   // unique paths accessed
    userAgentChanges: 10 // UA string variations
  },
  responses: {
    captcha: true,       // CAPTCHA challenge
    temporaryBlock: 300, // 5-minute block
    investigation: true  // Flag for review
  }
};
```

### Authentication Rate Limiting
- **[Brute Force Protection](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)**
  - Login attempt limiting
  - Account lockout policies
  - Progressive delays

#### Authentication Patterns
```javascript
const authRateLimit = {
  '/api/auth/login': {
    requests: 5,
    window: '15m',
    skipSuccessful: true,
    onLimit: 'account_lockout'
  },
  '/api/auth/password-reset': {
    requests: 3,
    window: '1h',
    keyGenerator: (req) => req.body.email
  }
};
```

### Bot Detection Integration
- **[Bot Detection and Rate Limiting](https://blog.cloudflare.com/bot-detection-machine-learning/)**
  - Behavioral analysis
  - Machine learning integration
  - CAPTCHA challenges

## 📊 Performance Considerations

### Latency Impact
- **[Rate Limiting Performance Analysis](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)**
  - Algorithm comparison
  - Memory access patterns
  - Network round-trips

#### Performance Metrics
```
Fixed Window: ~0.1ms (memory lookup)
Sliding Window Log: ~1-5ms (depending on traffic)
Token Bucket: ~0.2ms (simple calculation)
Sliding Window Counter: ~0.3ms (two counters)
Redis-based: +1-3ms (network latency)
```

### Scalability Patterns
- **[Scaling Rate Limiting Systems](https://engineering.grab.com/frequency-capping)**
  - Horizontal scaling strategies
  - Load balancer integration
  - Cache warming techniques

#### Scaling Considerations
```javascript
// Shard-aware key generation
const shardKey = `rate_limit:${userId % numShards}:${endpoint}`;

// Consistent hashing for distribution
const shard = consistentHash(userId, availableShards);

// Local cache with remote fallback
const limit = localCache.get(key) || await redis.get(key);
```

## 🎯 Business Logic Integration

### Tier-Based Rate Limiting
- **[SaaS Rate Limiting Strategies](https://stripe.com/blog/rate-limiters)**
  - Subscription tier mapping
  - Feature-based limits
  - Upgrade incentives

#### Tier Implementation
```javascript
const tierLimits = {
  free: {
    apiCalls: { requests: 1000, window: '1d' },
    uploads: { requests: 10, window: '1h' },
    exports: { requests: 1, window: '1d' }
  },
  premium: {
    apiCalls: { requests: 100000, window: '1d' },
    uploads: { requests: 1000, window: '1h' },
    exports: { requests: 100, window: '1h' }
  },
  enterprise: {
    apiCalls: { requests: -1 }, // unlimited
    uploads: { requests: 10000, window: '1h' },
    exports: { requests: 1000, window: '1h' }
  }
};
```

### Cost-Based Rate Limiting
- **[API Cost Calculation](https://stripe.com/blog/rate-limiters)**
  - Computational complexity scoring
  - Resource usage tracking
  - Dynamic pricing models

#### Cost Scoring Example
```javascript
const endpointCosts = {
  'GET /users': 1,           // Simple read
  'POST /search': 5,         // Database query
  'POST /ai/analyze': 50,    // GPU computation
  'GET /reports/export': 20  // Heavy processing
};

// User cost budget per time window
const userBudget = {
  free: 100 points per hour,
  premium: 10000 points per hour,
  enterprise: unlimited
};
```

### Geographic Rate Limiting
- **[Geo-Based API Restrictions](https://blog.cloudflare.com/geographical-load-balancing-insights/)**
  - Regional compliance
  - Data sovereignty
  - Performance optimization

## 🔍 Monitoring and Analytics

### Rate Limiting Metrics
- **[API Metrics That Matter](https://blog.postman.com/api-metrics-that-matter/)**
  - Request volume trends
  - Limit hit rates
  - User behavior patterns
  - Performance impact analysis

#### Key Metrics
```javascript
const rateLimitMetrics = {
  requests: {
    total: 'Total requests processed',
    allowed: 'Requests within limits',
    blocked: 'Requests blocked by rate limits',
    errorRate: 'blocked / total * 100'
  },
  performance: {
    latency: 'Rate limit check latency',
    throughput: 'Requests per second capacity',
    memoryUsage: 'Rate limit data storage'
  },
  business: {
    tierDistribution: 'Requests by user tier',
    upgradeConversions: 'Upgrades after rate limiting',
    supportTickets: 'Rate limit related issues'
  }
};
```

### Alerting Strategies
- **[Rate Limiting Alert Patterns](https://docs.datadoghq.com/monitors/create/types/apm/)**
  - Threshold-based alerts
  - Anomaly detection
  - Predictive alerting

#### Alert Configuration
```javascript
const alerts = {
  highTraffic: {
    condition: 'requests > 1000 per minute',
    action: 'scale_infrastructure'
  },
  abusiveUser: {
    condition: 'user hit limits > 10 times in hour',
    action: 'investigate_and_potentially_ban'
  },
  systemOverload: {
    condition: 'rate_limit_latency > 10ms',
    action: 'check_redis_performance'
  }
};
```

## 🛡 Error Handling and User Experience

### Rate Limit Response Format
- **[Rate Limiting HTTP Headers](https://tools.ietf.org/id/draft-polli-ratelimit-headers-00.html)**
  - Standard header specification
  - Client implementation guidance
  - Retry strategy communication

#### Response Examples
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200
X-RateLimit-Policy: 100;w=3600;comment="Sliding window"
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "limit": 100,
      "period": "1 hour",
      "resetTime": "2023-12-31T15:30:00Z",
      "retryAfter": 60,
      "policy": "sliding-window"
    }
  }
}
```

### Client-Side Handling
- **[Client Rate Limit Handling](https://docs.github.com/en/rest/guides/best-practices-for-integrators#dealing-with-rate-limits)**
  - Exponential backoff
  - Respect retry headers
  - Request queuing strategies

#### SDK Implementation
```javascript
// Client-side rate limit handling
class APIClient {
  async makeRequest(endpoint, options) {
    try {
      return await this.http.request(endpoint, options);
    } catch (error) {
      if (error.status === 429) {
        const retryAfter = error.headers['retry-after'];
        await this.sleep(retryAfter * 1000);
        return this.makeRequest(endpoint, options);
      }
      throw error;
    }
  }
}
```

## ✅ Implementation Checklist

### Design Phase
- [ ] Identify rate limiting requirements
- [ ] Choose appropriate algorithms
- [ ] Design hierarchical limit structure
- [ ] Plan storage and distribution strategy
- [ ] Define error response format

### Development Phase
- [ ] Implement rate limiting middleware
- [ ] Add proper HTTP headers
- [ ] Create monitoring and logging
- [ ] Build admin override capabilities
- [ ] Add configuration management

### Testing Phase
- [ ] Load test rate limiting accuracy
- [ ] Verify distributed coordination
- [ ] Test failure scenarios
- [ ] Validate client error handling
- [ ] Performance impact assessment

### Production Phase
- [ ] Monitor rate limiting metrics
- [ ] Set up alerting thresholds
- [ ] Document client best practices
- [ ] Plan capacity scaling
- [ ] Regular security review

---

*📚 Continue with [API Security Guidelines](./api-security-guidelines.md) for comprehensive security practices*

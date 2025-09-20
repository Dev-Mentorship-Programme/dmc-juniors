# Resilient API Client Example

A robust HTTP client implementation with retry logic, circuit breaker pattern, rate limiting, and caching capabilities.

## Features

- **Circuit Breaker**: Prevents cascading failures by monitoring request success/failure rates
- **Retry Logic**: Automatic retry with exponential backoff for failed requests
- **Rate Limiting**: Controls request frequency to prevent API rate limit violations
- **Caching**: In-memory response caching for GET requests
- **Timeout Handling**: Configurable request timeouts
- **Health Monitoring**: Built-in health check and metrics collection

## Setup

1. Install dependencies:
```bash
npm install
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Update environment variables as needed

4. Run in development mode:
```bash
npm run dev
```

## Usage Examples

### Basic Client Setup
```typescript
import { ResilientApiClient } from './ResilientApiClient';

const client = new ResilientApiClient({
  baseURL: 'https://api.example.com',
  timeout: 10000,
  retryConfig: {
    retries: 3,
    retryDelay: 1000
  },
  circuitBreakerConfig: {
    failureThreshold: 5,
    successThreshold: 3,
    timeout: 60000
  },
  rateLimitConfig: {
    maxConcurrent: 5,
    minTime: 200
  }
});
```

### Making Requests
```typescript
// GET request with caching
const response = await client.get('/users', { useCache: true });

// POST request
const newUser = await client.post('/users', { name: 'John Doe' });

// Health check
const health = await client.healthCheck();
```

## Configuration Options

- **baseURL**: Base URL for all requests
- **timeout**: Request timeout in milliseconds
- **retryConfig**: Retry behavior configuration
- **circuitBreakerConfig**: Circuit breaker thresholds and timing
- **rateLimitConfig**: Rate limiting parameters

## Architecture Patterns

This example demonstrates several important patterns:

1. **Circuit Breaker Pattern**: Fail fast when external services are down
2. **Retry Pattern**: Handle transient failures gracefully
3. **Rate Limiting**: Respect API quotas and prevent abuse
4. **Caching**: Reduce unnecessary API calls
5. **Monitoring**: Track performance and reliability metrics

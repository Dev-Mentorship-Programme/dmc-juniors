# API Integration Resources

## Third-Party APIs for Practice

### Free APIs (No Authentication Required)
- [JSONPlaceholder](https://jsonplaceholder.typicode.com/) - Fake REST API for testing
- [httpbin](https://httpbin.org/) - HTTP request & response service
- [REST Countries](https://restcountries.com/) - Country data API

### APIs with Free Tiers
- [GitHub API](https://docs.github.com/en/rest) - Repository and user data
- [OpenWeatherMap](https://openweathermap.org/api) - Weather data
- [News API](https://newsapi.org/) - News articles and headlines
- [CoinGecko API](https://www.coingecko.com/en/api) - Cryptocurrency data

## Integration Patterns

### Circuit Breaker Pattern
- **Purpose**: Prevent cascading failures
- **Implementation**: Monitor failure rates and "break" when threshold exceeded
- **Libraries**: `opossum`, custom implementation

### Retry Pattern
- **Types**: Fixed delay, exponential backoff, jitter
- **Considerations**: Idempotency, retry limits, error types
- **Libraries**: `axios-retry`, `p-retry`

### Rate Limiting
- **Client-side**: Respect API quotas and prevent abuse
- **Algorithms**: Token bucket, sliding window
- **Libraries**: `bottleneck`, `p-limit`

## Tools and Libraries

### HTTP Clients
- `axios` - Promise-based HTTP client
- `node-fetch` - Fetch API for Node.js
- `got` - Human-friendly HTTP request library

### Resilience Libraries
- `opossum` - Circuit breaker implementation
- `bottleneck` - Rate limiting and queuing
- `p-retry` - Retry with exponential backoff

### Testing and Mocking
- `nock` - HTTP server mocking
- `msw` - Mock Service Worker
- `wiremock` - Flexible API mocking

## Best Practices

### Error Handling
- Distinguish between retryable and non-retryable errors
- Implement proper fallback mechanisms
- Log errors with sufficient context
- Monitor error rates and patterns

### Performance
- Use connection pooling
- Implement response caching
- Optimize payload sizes
- Monitor response times

### Security
- Validate API responses
- Sanitize input data
- Use HTTPS for all requests
- Rotate API keys regularly

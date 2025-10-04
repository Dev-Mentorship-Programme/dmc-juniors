# Resilient API Client Example

A robust HTTP client implementation with retry logic, circuit breaker pattern, rate limiting, and caching capabilities.

## Features

- **Circuit Breaker**: Prevents cascading failures by monitoring request success/failure rates

  ### What it is
  
  A circuit breaker is a resilience pattern in software systems.
  It's inspired by the electrical circuit breaker in your house that trips when there's a fault — protecting the whole system.
  
  ### How it works (step by step)
  
  **Normal state (Closed)**
  - Requests flow normally from Service A → Service B.
  - Circuit breaker just monitors.
  
  **Failures detected**
  - If Service B starts failing (e.g., errors, timeouts, or too many slow responses), the breaker counts failures.
  
  **Trip (Open state)**
  - When failure rate crosses a threshold (say 50% of requests fail in 1 minute), the breaker opens.
  - Now, instead of letting requests keep failing (and wasting resources), it blocks calls to Service B immediately and can return a fallback response (like "Service unavailable, try again later").
  
  **Recovery (Half-open state)**
  - After a cooldown period, the breaker lets a few trial requests through.
  - If they succeed, the breaker closes again (back to normal).
  - If they fail, it stays open longer.
  
  ### Why it's useful
  
  - **Prevents cascading failures**: If one service is down, it stops other services from being dragged down by endless retries and timeouts.
  - **Improves system stability**: Failures are isolated, so the whole system doesn't collapse.
  - **Provides fallback behavior**: Users get a graceful error or cached response instead of endless spinning.
  
  ### 🔹 Example in plain words:
  
  Imagine you're ordering food from a delivery app.
  
  If the payment service keeps failing, the app might keep retrying and freeze.
  
  A circuit breaker notices payment is failing often, trips, and immediately shows: "Payment service unavailable — try again later."
  
  The app still works for browsing menus, instead of crashing.

- **Retry Logic**: Automatic retry with exponential backoff for failed requests

  ### What it is
  
  **Retry logic means:**
  👉 When a request fails (like a network call, API request, or DB query), the system automatically tries again instead of giving up immediately.
  
  **Exponential backoff means:**
  👉 Instead of retrying immediately or at a fixed interval, the system waits longer and longer between retries.
  
  ### How it works (step by step)
  
  **First attempt** → Send the request.
  - If it succeeds → ✅ done.
  - If it fails → ❌ go to retry.
  
  **Retry with delay**
  - Wait a short time (e.g., 1 second), then retry.
  
  **Next retry**
  - If it fails again, wait longer this time (e.g., 2 seconds).
  
  **Keep doubling delay**
  - 1s → 2s → 4s → 8s → … until either:
    - It succeeds, or
    - The maximum retry limit is reached (to avoid infinite retries).
  
  **Optional jitter**
  - To avoid many clients retrying at the exact same time, systems often add a random "jitter" (e.g., 2.3s instead of exactly 2s).
  
  ### Why it's useful
  
  - **Handles temporary failures**: Many errors are short-lived (like a network glitch or a busy server). A retry often succeeds.
  - **Reduces system overload**: Exponential backoff spreads out retries, preventing a "thundering herd" of requests all slamming the service at once.
  - **Improves reliability**: Users experience fewer errors since transient failures are retried automatically.
  
  ### 🔹 Example in plain words:
  
  You try to book a ride on a mobility app. The request fails because the network is spotty.
  - **Retry 1** → after 1 second
  - **Retry 2** → after 2 seconds
  - **Retry 3** → after 4 seconds
  - **Retry 4** → after 8 seconds
  
  If the network comes back during those retries, your booking goes through without you doing anything.
  
  👉 **In short:**
  - **Retry logic** = keep trying when things fail.
  - **Exponential backoff** = wait longer each time before retrying, so you don't overwhelm the system.
  
  ### 🔹 Retry Logic vs Circuit Breaker
  
  Since retry logic and circuit breaker are often used together in resilient systems, here's how they compare:
  
  **🔹 Retry Logic**
  
  - **What it does**: Keeps trying failed requests again.
  - **How**: Waits longer (exponential backoff) between retries to avoid hammering the service.
  - **Good for**:
    - Temporary failures (e.g., network blip, server busy, packet loss).
    - Situations where retrying has a good chance of success.
  - **Risk if misused**:
    - Can flood a failing service with retries if not limited.
    - Wastes time if the service is completely down.
  - **Example**: A payment API times out once because the server is momentarily overloaded. Retry logic waits 1s, retries, and the request succeeds. ✅
  
  **🔹 Circuit Breaker**
  
  - **What it does**: Stops sending requests to a failing service after repeated failures.
  - **How**: Monitors failure rate → if too high, it "opens" the circuit and blocks requests for a cooldown period.
  - **Good for**:
    - Preventing cascading failures across services.
    - Giving a failing service "room to breathe."
  - **Risk if misused**:
    - Might block requests even after the service has recovered (if thresholds are too strict).
  - **Example**: If the payment API fails repeatedly for 2 minutes, the circuit breaker opens. New requests are blocked immediately and return a fallback ("Payment service unavailable") instead of hanging. ❌
  
  **🔹 How they work together**
  
  - **Retry logic** = "Let's try again in case it was just a glitch."
  - **Circuit breaker** = "Stop trying — the service is clearly down. Protect the system."
  
  👉 **Combined flow:**
  1. A request fails → retry logic kicks in (with exponential backoff).
  2. If failures keep happening → circuit breaker trips to prevent endless retries.
  3. After cooldown → circuit breaker tests the service again (half-open). If success, retries resume.
  
  **⚡ Real-world analogy**
  - **Retry logic** = You call a friend, the line is busy → wait a bit → call again.
  - **Circuit breaker** = After 5 failed calls, you stop trying and just send them a text saying, "Call me when you're available."

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

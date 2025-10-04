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

  ### What it is
  
  **Caching** = storing data temporarily so you don't have to fetch or compute it again.
  
  **In-memory cache** = data is stored in the application's RAM (e.g., using Redis, Memcached, or even Node.js memory).
  
  **For GET requests** = usually applied to read-only operations where the data doesn't change often.
  
  ### How it works (step by step)
  
  **First request (Cache Miss)**
  - A client asks for data (e.g., `/api/products`).
  - The system doesn't have it in cache → fetches from the database or service.
  - The response is saved in memory.
  
  **Subsequent request (Cache Hit)**
  - Another client asks for the same data.
  - Instead of querying the database again, the system serves it directly from memory.
  - Much faster ⚡ and reduces load on backend systems.
  
  **Expiry / Invalidation**
  - Cached data is usually stored only for a set time (TTL = Time-To-Live, e.g., 60 seconds).
  - After expiry, the cache is cleared and refreshed on the next request.
  
  ### Why it's useful
  
  - **Performance boost** → In-memory responses are extremely fast (nanoseconds vs milliseconds).
  - **Reduced load** → Fewer database/API calls, saving resources.
  - **Better scalability** → Handles more traffic with the same infrastructure.
  
  ### 🔹 Example in plain words:
  
  Imagine a shopping site:
  
  Many users keep requesting the same "Top 10 Bestselling Products".
  
  - **Without caching** → each request hits the database, which slows things down.
  - **With caching** → the first request stores the result in memory. Every other request gets the same fast response instantly.
  
  👉 **In short:**
  Caching is like keeping frequently used info on your desk instead of walking to the library every time you need it.

- **Timeout Handling**: Configurable request timeouts

  ### What it is
  
  A **timeout** is the maximum amount of time your system will wait for a request (to an API, database, or service) before giving up.
  
  **Timeout handling** means setting and managing these limits so your app doesn't hang forever.
  
  **Configurable** means you can adjust these values (e.g., 2s, 5s, 30s) depending on the service.
  
  ### How it works (step by step)
  
  **Send a request** → Your service calls another API or database.
  
  **Start a timer** → The system waits for a response.
  
  **If the service responds in time** → ✅ success.
  
  **If the service takes too long** → ❌ request is cancelled and a timeout error is thrown.
  
  **Handle the timeout** → Your app might retry, return a fallback, or log the error.
  
  ### Why it's useful
  
  - **Prevents hanging requests** → Without timeouts, your system could wait forever if the other service never responds.
  - **Improves resilience** → Ensures one slow service doesn't block your whole app.
  - **Protects resources** → Frees up threads/connections instead of locking them until something fails.
  
  ### 🔹 Example in plain words:
  
  You call a restaurant to order food.
  
  If they don't pick up in 30 seconds, you hang up (timeout).
  
  Instead of waiting forever, you either try again (retry) or move to another restaurant (fallback).
  
  👉 **In short:**
  Timeout handling = setting a "maximum wait time" for a request, so your system fails fast instead of getting stuck.
  
  ### 🔹 The Resilience Trio: Timeout + Retry + Circuit Breaker
  
  Timeouts, Retries (with backoff), and Circuit Breakers are often used together as a resilience trio in distributed/microservice systems.
  
  **🔹 1. Timeout Handling → "Don't wait forever"**
  
  - **Purpose**: Fail fast if a service is too slow.
  - **Rule**: "If no response in X seconds, stop waiting."
  - **Benefit**: Frees up resources instead of hanging indefinitely.
  - **Analogy**: You hang up the phone if nobody answers within 30 seconds.
  
  **🔹 2. Retry Logic with Exponential Backoff → "Try again, but smarter"**
  
  - **Purpose**: Handle temporary failures (network glitch, server overload).
  - **Rule**: Retry after 1s → 2s → 4s … up to a limit.
  - **Benefit**: Many issues resolve themselves if you just wait and retry.
  - **Analogy**: If the call doesn't go through, you try again later, waiting a bit longer each time.
  
  **🔹 3. Circuit Breaker → "Stop trying if it's really broken"**
  
  - **Purpose**: Prevent cascading failures when a service is consistently failing.
  - **Rule**: If failure rate crosses threshold, "trip" the breaker and stop sending requests for a cooldown period.
  - **Benefit**: Protects the whole system from being dragged down.
  - **Analogy**: After 5 failed calls, you stop calling and send a text: "Call me when you're back."
  
  **🔄 How They Work Together (Flow)**
  
  1. **Request sent** → Timer starts (timeout handling).
  2. **If response is too slow** → timeout error.
  3. **Timeout/failure happens** → Trigger retry logic.
     - Wait exponentially longer between retries.
  4. **If repeated failures keep happening** → Circuit breaker trips.
     - Blocks new requests and returns a fallback.
     - After cooldown, tests the service again.
  
  **⚡ Real-world analogy: Ordering food online**
  
  - **Timeout**: If the restaurant doesn't confirm your order in 30 seconds, you cancel (fail fast).
  - **Retry**: You try again after 1 minute, then 2 minutes, then 4 minutes (backoff).
  - **Circuit breaker**: After multiple failures, you stop trying that restaurant and switch to another.

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

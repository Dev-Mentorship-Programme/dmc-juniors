# Repository Pattern Example

This example demonstrates the Repository Pattern - an abstraction layer between the business logic and data access layers.

## What is the Repository Pattern?

The Repository Pattern:
- Provides a collection-like interface for accessing domain objects
- Decouples business logic from data persistence concerns
- Makes code more testable by allowing easy mocking
- Centralizes data access logic

## Benefits

1. **Abstraction**: Business logic doesn't know about data storage details
2. **Testability**: Easy to mock repositories for unit testing
3. **Maintainability**: Changes to data access don't affect business logic
4. **Flexibility**: Can swap data sources (SQL → NoSQL) without changing business logic

## Structure

```
src/
├── domain/              # Domain models (entities)
├── interfaces/          # Repository interfaces
├── repositories/        # Repository implementations
├── services/            # Business logic
└── infrastructure/      # Database configuration
```

## Key Concepts

### Repository Interface
Defines the contract for data access operations without implementation details.

### Repository Implementation
Concrete implementation that handles actual data storage and retrieval.

### Dependency Injection
Services depend on repository interfaces, not concrete implementations.

## Running the Example

```bash
npm install
npm run dev
```

## Testing

```bash
npm test
```

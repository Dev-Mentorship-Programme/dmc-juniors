# Week 9 Examples: Architecture & Design Patterns

This folder contains practical TypeScript examples demonstrating key software architecture principles and design patterns.

## Examples Overview

### 1. Layered Architecture Example
**Location:** `layered-architecture-example/`

Demonstrates clean layered architecture with proper separation of concerns:
- **Presentation Layer**: Controllers and routes handling HTTP
- **Business Logic Layer**: Services containing business rules
- **Data Access Layer**: Repositories abstracting data persistence
- **Domain Layer**: Pure business entities

**Key Concepts:**
- Dependency injection
- Layer separation
- Unidirectional dependencies
- Testability

**Run it:**
```bash
cd layered-architecture-example
npm install
npm run dev
```

### 2. Repository Pattern Example
**Location:** `repository-pattern/`

Shows the Repository Pattern for abstracting data access:
- Clean separation between business logic and data access
- Interface-based repository contracts
- Easy to swap implementations (in-memory, SQL, NoSQL)
- Improved testability with mock repositories

**Key Concepts:**
- Repository interfaces
- Implementation abstraction
- Dependency inversion
- Collection-like API

**Run it:**
```bash
cd repository-pattern
npm install
npm run dev
```

### 3. SOLID Principles & Dependency Injection
**Location:** `solid-principles-di/`

Comprehensive example of all SOLID principles with dependency injection:

**S**ingle Responsibility: Each class has one clear purpose
**O**pen/Closed: Open for extension, closed for modification  
**L**iskov Substitution: Implementations can be substituted
**I**nterface Segregation: Small, focused interfaces
**D**ependency Inversion: Depend on abstractions

**Key Concepts:**
- Constructor injection
- Interface-based design
- Dependency injection container
- Loose coupling
- High testability

**Run it:**
```bash
cd solid-principles-di
npm install
npm run dev
```

## Learning Objectives

After studying these examples, you should understand:

1. **Layered Architecture**
   - How to organize code into distinct layers
   - Managing dependencies between layers
   - Benefits of layer separation

2. **Repository Pattern**
   - Abstracting data access logic
   - Creating repository interfaces
   - Implementing repositories for different data sources

3. **SOLID Principles**
   - How each principle improves code quality
   - Practical application of each principle
   - How they work together

4. **Dependency Injection**
   - Constructor injection pattern
   - Benefits for testing and flexibility
   - Building a simple DI container

## Common Patterns Across Examples

All examples use:
- **TypeScript** for type safety
- **Interfaces** for contracts
- **Dependency Injection** for loose coupling
- **Clean separation** of concerns
- **Testable** architecture

## Next Steps

1. Run each example and study the code
2. Try extending them with new features
3. Write tests for the services
4. Experiment with different implementations
5. Apply these patterns to your own projects

## Additional Resources

- [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
- [Repository Pattern](https://martinfowler.com/eaaCatalog/repository.html)
- [Dependency Injection](https://en.wikipedia.org/wiki/Dependency_injection)

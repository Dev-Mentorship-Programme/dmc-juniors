# SOLID Principles & Dependency Injection Example

This example demonstrates the SOLID principles in practice with proper dependency injection.

## SOLID Principles

### 1. **S**ingle Responsibility Principle (SRP)
Each class has one reason to change. Classes are focused on a single responsibility.

### 2. **O**pen/Closed Principle (OCP)
Classes are open for extension but closed for modification.

### 3. **L**iskov Substitution Principle (LSP)
Derived classes can substitute their base classes without breaking functionality.

### 4. **I**nterface Segregation Principle (ISP)
Clients shouldn't be forced to depend on interfaces they don't use.

### 5. **D**ependency Inversion Principle (DIP)
Depend on abstractions, not concretions.

## Dependency Injection

This example demonstrates:
- Constructor injection
- Interface-based dependencies
- Dependency injection container (manual)
- Testability through dependency injection

## Project Structure

```
src/
├── interfaces/          # Contracts/abstractions
├── services/           # Service implementations
├── repositories/       # Data access implementations
├── notifications/      # Notification implementations
├── container/          # DI container
└── index.ts            # Application entry
```

## Benefits

- Loose coupling between components
- Easy to test (mock dependencies)
- Easy to extend (add new implementations)
- Clear contracts (interfaces)
- Flexible architecture

## Running the Example

```bash
npm install
npm run dev
```

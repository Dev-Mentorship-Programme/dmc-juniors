# Week 10 Examples: Project Organization

This folder contains examples of best practices for organizing scalable TypeScript projects.

## Examples Overview

### 1. Modular Project Structure
**Location:** `modular-project-structure/`

Demonstrates a production-ready modular project structure:

**Structure:**
```
src/
├── modules/          # Feature modules (users, auth, products)
│   └── users/
│       ├── dto/      # Data Transfer Objects
│       ├── entities/ # Domain entities
│       ├── services/ # Business logic
│       ├── controllers/ # HTTP handlers
│       └── routes/   # Route definitions
├── shared/           # Shared utilities
│   ├── config/       # Configuration management
│   ├── middleware/   # Shared middleware
│   └── utils/        # Utility functions
├── core/             # Core application
│   ├── database/     # Database connection
│   ├── errors/       # Custom errors
│   └── logger/       # Logging setup
└── app.ts            # Application entry
```

**Key Features:**
- Feature-based organization
- Module encapsulation
- Centralized error handling
- Structured logging with Winston
- Environment configuration
- TypeScript path aliases

**Run it:**
```bash
cd modular-project-structure
npm install
cp .env.example .env
npm run dev
```

**API Endpoints:**
```
POST   /api/users          - Create user
GET    /api/users          - Get all users
GET    /api/users/:id      - Get user by ID
PUT    /api/users/:id      - Update user
DELETE /api/users/:id      - Delete user
GET    /health             - Health check
```

## Key Principles

### 1. Feature-Based Organization
Group code by feature/domain, not by technical role:
```
✓ modules/users/
✗ controllers/, services/, models/
```

**Benefits:**
- Easier to navigate
- Clear feature boundaries
- Easier to extract to microservices
- Team members can work independently

### 2. Module Encapsulation
Each module is self-contained with:
- Its own entities, DTOs, services
- Internal business logic
- Clear public API (index.ts)

### 3. Shared Code Management
Common code goes in dedicated folders:
- `shared/` - Application-wide utilities
- `core/` - Core application infrastructure

### 4. Configuration Management
Centralized configuration:
- Environment variables
- Type-safe config objects
- Default values

### 5. Error Handling
Structured error handling:
- Custom error classes
- HTTP status code mapping
- Centralized error middleware

### 6. Logging
Structured logging:
- Winston logger
- Log levels
- Request/response logging
- Error logging

## Best Practices Demonstrated

### 1. TypeScript Path Aliases
```typescript
import { User } from '@modules/users';
import { config } from '@shared/config';
import { logger } from '@core/logger';
```

### 2. DTOs (Data Transfer Objects)
Separate data structures for:
- Input validation
- API contracts
- Internal domain models

### 3. Middleware Organization
- Shared middleware in `shared/middleware`
- Module-specific middleware in module folder

### 4. Error Handling Pattern
```typescript
try {
  // Business logic
} catch (error) {
  next(error); // Pass to error handler
}
```

### 5. Module Exports
Each module has an `index.ts` that exports public API:
```typescript
export { User } from './entities/User';
export { UserService } from './services/UserService';
```

## Extending the Example

### Adding a New Module

1. Create module folder:
```bash
mkdir -p src/modules/products/{dto,entities,services,controllers,routes}
```

2. Implement the module following the same structure

3. Register routes in `app.ts`:
```typescript
const productRoutes = createProductRoutes(productController);
app.use('/api/products', productRoutes);
```

### Adding Middleware

1. Create middleware file:
```typescript
// src/shared/middleware/auth.ts
export const authenticate = async (req, res, next) => {
  // Auth logic
};
```

2. Apply globally or to specific routes:
```typescript
app.use(authenticate); // Global
router.get('/protected', authenticate, handler); // Route-specific
```

## Testing Strategy

### Unit Tests
Test individual components:
- Services (business logic)
- Validators
- Utilities

### Integration Tests
Test modules together:
- API endpoints
- Database operations
- External services

### Structure
```
src/
└── modules/
    └── users/
        ├── services/
        │   ├── UserService.ts
        │   └── UserService.test.ts
        └── controllers/
            ├── UserController.ts
            └── UserController.test.ts
```

## Common Patterns

### 1. Dependency Injection
```typescript
class UserController {
  constructor(private readonly userService: UserService) {}
}
```

### 2. Async/Await Error Handling
```typescript
async handler(req, res, next) {
  try {
    const result = await this.service.doSomething();
    res.json({ success: true, data: result });
  } catch (error) {
    next(error);
  }
}
```

### 3. Configuration Access
```typescript
import { config } from '@shared/config';
console.log(config.port);
```

## Scalability Considerations

This structure scales well because:
1. **Modules are independent** - Can extract to microservices
2. **Clear boundaries** - Easy to understand ownership
3. **Testable** - Each part can be tested independently
4. **Team-friendly** - Multiple developers can work simultaneously
5. **Maintainable** - Easy to locate and modify code

## Next Steps

1. Study the module structure
2. Add a new module (e.g., products, orders)
3. Add authentication middleware
4. Write tests for services
5. Add database integration
6. Implement API documentation (Swagger)

## Additional Resources

- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)
- [Express.js Guide](https://expressjs.com/en/guide/routing.html)
- [12-Factor App](https://12factor.net/)

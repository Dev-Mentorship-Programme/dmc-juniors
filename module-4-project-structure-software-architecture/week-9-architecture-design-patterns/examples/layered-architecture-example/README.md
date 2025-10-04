# Layered Architecture Example

This example demonstrates a clean layered architecture with proper separation of concerns.

## Architecture Layers

```
┌─────────────────────────────────────┐
│      Presentation Layer (API)      │  ← Controllers, Routes
├─────────────────────────────────────┤
│         Business Logic Layer        │  ← Services, Use Cases
├─────────────────────────────────────┤
│        Data Access Layer            │  ← Repositories, DAL
├─────────────────────────────────────┤
│           Database Layer            │  ← PostgreSQL, MongoDB
└─────────────────────────────────────┘
```

## Project Structure

```
src/
├── controllers/          # Presentation Layer
├── services/            # Business Logic Layer
├── repositories/        # Data Access Layer
├── models/              # Domain Models
├── middleware/          # Cross-cutting concerns
├── utils/               # Utility functions
├── config/              # Configuration
└── app.js               # Application entry point
```

## Key Principles

1. **Separation of Concerns**: Each layer has a specific responsibility
2. **Dependency Rule**: Dependencies point inward (controllers → services → repositories)
3. **Abstraction**: Layers communicate through interfaces/abstractions
4. **Testability**: Each layer can be tested independently

## Running the Example

```bash
npm install
npm run dev
```

## API Endpoints

- `POST /api/users` - Create a new user
- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

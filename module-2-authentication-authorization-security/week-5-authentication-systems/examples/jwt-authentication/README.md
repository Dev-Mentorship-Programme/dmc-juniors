# JWT Authentication System (In-Memory Edition)

A complete JWT-based authentication system with refresh tokens, account security, and comprehensive middleware using **in-memory storage** for educational purposes.

## 🚀 Features

- **User Registration & Login** - Secure user account creation and authentication
- **JWT Token Management** - Access tokens with refresh token rotation
- **Account Security** - Login attempt tracking and account lockout protection
- **Role-Based Authorization** - Flexible permission system with roles
- **Password Security** - Bcrypt hashing with configurable rounds
- **Rate Limiting** - Protection against brute force attacks
- **Session Management** - Multiple device support with token invalidation
- **In-Memory Storage** - No database required for quick setup and learning

## 📋 Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- **No database required!**

## 🏃‍♂️ Quick Start

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Setup**
   ```bash
   cp .env.example .env
   # Update the JWT secrets in .env file
   ```

3. **Run Development Server**
   ```bash
   npm run dev
   ```

4. **Test the API**
   The server will start on `http://localhost:3000` with a pre-created admin user:
   - **Email**: `admin@example.com`
   - **Password**: `Admin123!`

## 🏗️ Storage Architecture

This example demonstrates authentication patterns without requiring database setup:

- **In-Memory User Store** - Users stored in memory using Map data structure
- **Pre-created Admin User** - Default admin account for immediate testing
- **Data Persistence** - Data exists only during server runtime
- **Educational Focus** - Learn authentication patterns without database complexity

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Create new user account
- `POST /api/auth/login` - User login with credentials
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout from current device
- `POST /api/auth/logout-all` - Logout from all devices
- `GET /api/auth/me` - Get current user profile

### User Management
- `GET /api/users` - List all users (admin only)
- `GET /api/users/:userId` - Get user by ID
- `PUT /api/users/:userId` - Update user profile
- `DELETE /api/users/:userId` - Delete user account
- `PUT /api/users/:userId/role` - Update user role (admin only)

## 🔐 Security Features

### Password Requirements
- Minimum 8 characters
- Must contain uppercase, lowercase, number, and special character
- Bcrypt hashing with 12 rounds (configurable)

### Account Protection
- Account lockout after 5 failed login attempts
- 2-hour lockout duration
- Automatic lockout reset on successful login

### Token Security
- Short-lived access tokens (15 minutes default)
- Long-lived refresh tokens (7 days default)
- Token rotation on refresh
- Secure token invalidation

## 📝 Usage Examples

### User Registration
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### User Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "Admin123!"
  }'
```

### Authenticated Request
```bash
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🏛️ Architecture

### Components
- **UserStore** - In-memory user storage with CRUD operations
- **JWT Service** - Token generation and validation
- **Auth Middleware** - Request authentication and authorization
- **Route Handlers** - API endpoint implementations
- **Error Handling** - Centralized error processing

### Security Middleware
- **Authentication** - Verify JWT tokens and user existence
- **Authorization** - Check user roles and permissions
- **Rate Limiting** - Prevent abuse and brute force attacks
- **Input Validation** - Sanitize and validate request data

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## 📚 Learning Objectives

This example demonstrates:
- JWT authentication implementation
- Refresh token patterns
- Role-based authorization
- Account security measures
- API security best practices
- TypeScript in authentication systems

## ⚠️ Important Notes

- **Educational Purpose**: This uses in-memory storage for learning
- **Data Loss**: All data is lost when server restarts
- **Production Use**: Replace with proper database in real applications
- **Default User**: Admin user is created automatically for testing

## 🚀 Next Steps

After understanding this example:
1. Learn about database integration (Module 6)
2. Implement persistent storage
3. Add email verification
4. Implement two-factor authentication
5. Add OAuth integration

## 📖 Related Examples

- **OAuth 2.0 Social Login** - Multi-provider authentication
- **Session-Based Auth** - Traditional session management
- **API Security** - Advanced security middleware

## 🔗 Useful Resources

- [JWT.io](https://jwt.io/) - JWT debugger and information
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

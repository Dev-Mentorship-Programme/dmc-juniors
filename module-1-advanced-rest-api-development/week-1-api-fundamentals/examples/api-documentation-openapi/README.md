# API Documentation with OpenAPI/Swagger

This example demonstrates how to create comprehensive API documentation using OpenAPI 3.0 specification with Express.js and Swagger UI.

## Overview

This project shows best practices for:
- Writing OpenAPI specifications
- Integrating Swagger UI with Express.js
- Using swagger-jsdoc for inline documentation
- Creating comprehensive API documentation

## Features

- **Complete OpenAPI 3.0 Specification**: Detailed API documentation in YAML format
- **Interactive Documentation**: Swagger UI interface for testing endpoints
- **JSDoc Integration**: Inline documentation with swagger-jsdoc
- **Security Definitions**: JWT Bearer token authentication
- **Error Handling**: Standardized error responses
- **Validation**: Input validation with detailed error messages

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Access the API documentation:
   - Swagger UI: http://localhost:3000/api-docs
   - Health Check: http://localhost:3000/api/v1/health

## Project Structure

```
api-documentation-openapi/
├── basic-openapi-spec.yaml      # Complete OpenAPI specification
├── express-swagger-example.js   # Express.js server with Swagger integration
├── package.json                 # Project dependencies
└── README.md                   # This file
```

## Key Concepts Demonstrated

### 1. OpenAPI Specification Structure
- **Info Object**: API metadata, contact information, licensing
- **Servers Array**: Multiple environment configurations
- **Paths Object**: Endpoint definitions with detailed parameters
- **Components**: Reusable schemas, responses, and security schemes
- **Security**: Authentication and authorization specifications

### 2. Express.js Integration
- **swagger-jsdoc**: Generate specs from JSDoc comments
- **swagger-ui-express**: Serve interactive documentation
- **Middleware Integration**: Rate limiting, CORS, security headers

### 3. Documentation Best Practices
- **Detailed Descriptions**: Clear, comprehensive endpoint descriptions
- **Examples**: Realistic request/response examples
- **Error Handling**: Standardized error response formats
- **Validation Rules**: Input validation with detailed constraints

## API Endpoints

### User Management
- `GET /api/v1/users` - List users with pagination and search
- `POST /api/v1/users` - Create a new user
- `GET /api/v1/users/{userId}` - Get user by ID
- `PUT /api/v1/users/{userId}` - Update user (not implemented in example)
- `DELETE /api/v1/users/{userId}` - Delete user (not implemented in example)

### Authentication
- `POST /api/v1/auth/login` - User login (defined in spec, not implemented)

### System
- `GET /api/v1/health` - Health check endpoint

## Authentication

This example uses JWT Bearer token authentication. For testing:
- Use `demo-token` as the Bearer token
- Header format: `Authorization: Bearer demo-token`

## Testing the API

### Using Swagger UI
1. Open http://localhost:3000/api-docs
2. Click on "Authorize" button
3. Enter `demo-token` as the Bearer token
4. Test the endpoints interactively

### Using curl
```bash
# Get all users
curl -H "Authorization: Bearer demo-token" \
  http://localhost:3000/api/v1/users

# Create a new user
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-token" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "password123",
    "firstName": "Test",
    "lastName": "User"
  }' \
  http://localhost:3000/api/v1/users

# Health check (no auth required)
curl http://localhost:3000/api/v1/health
```

## OpenAPI Features Demonstrated

### Schema Definitions
- **User Schema**: Complete user object with validation rules
- **Request Schemas**: Input validation for create/update operations
- **Error Schema**: Standardized error response format

### Response Documentation
- **Success Responses**: Detailed success response structures
- **Error Responses**: Comprehensive error handling with HTTP status codes
- **Examples**: Realistic response examples for each endpoint

### Security Integration
- **Bearer Authentication**: JWT token-based security
- **Security Requirements**: Endpoint-level security specifications
- **Error Responses**: Authentication and authorization error handling

### Advanced Features
- **Parameter Validation**: Query parameters with constraints
- **Content Types**: Multiple content type support
- **Server Configurations**: Multiple environment setup

## Learning Objectives

After studying this example, you should understand:

1. **OpenAPI Specification Structure**: How to structure a complete API specification
2. **Documentation Best Practices**: Writing clear, comprehensive API documentation
3. **Express.js Integration**: Integrating OpenAPI with Node.js applications
4. **Interactive Documentation**: Creating user-friendly API documentation
5. **Security Documentation**: Documenting authentication and authorization
6. **Error Handling**: Standardizing error responses across your API

## Next Steps

1. **Expand the Specification**: Add more endpoints and complex schemas
2. **Add Validation**: Implement proper input validation middleware
3. **Authentication**: Implement real JWT authentication
4. **Database Integration**: Connect to a real database
5. **Testing**: Add automated tests based on the OpenAPI specification

## References

- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [Swagger UI](https://swagger.io/tools/swagger-ui/)
- [swagger-jsdoc Documentation](https://github.com/Surnet/swagger-jsdoc)
- [Express.js Documentation](https://expressjs.com/)

## Common Issues and Solutions

### Swagger UI Not Loading
- Check that the OpenAPI specification is valid
- Verify the paths in swagger-jsdoc configuration
- Check browser console for JavaScript errors

### Authentication Not Working
- Ensure the Authorization header format is correct
- Check that the token is being parsed properly in middleware
- Verify the security scheme in the OpenAPI specification

### Validation Errors
- Check that request body matches the schema
- Verify parameter types and constraints
- Review validation middleware implementation

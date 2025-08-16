# Exercise 1: API Documentation with OpenAPI

## Objective
Create a complete OpenAPI 3.0 specification for a Book Library API and implement it with Express.js and Swagger UI.

## Requirements

### API Endpoints to Document
1. `GET /api/books` - Get all books (with pagination)
2. `GET /api/books/{id}` - Get a specific book
3. `POST /api/books` - Add a new book
4. `PUT /api/books/{id}` - Update a book
5. `DELETE /api/books/{id}` - Delete a book
6. `GET /api/authors` - Get all authors
7. `POST /api/authors` - Add a new author

### Data Models
```json
{
  "Book": {
    "id": "string (UUID)",
    "title": "string (required)",
    "author_id": "string (UUID, required)",
    "isbn": "string (required)",
    "publication_year": "number",
    "genre": "string",
    "price": "number",
    "created_at": "string (ISO 8601)",
    "updated_at": "string (ISO 8601)"
  },
  "Author": {
    "id": "string (UUID)",
    "name": "string (required)",
    "biography": "string",
    "birth_year": "number",
    "nationality": "string",
    "created_at": "string (ISO 8601)"
  }
}
```

## Tasks

### Task 1: OpenAPI Specification
Create an `openapi.yaml` file with:
- Complete API information and contact details
- Server configuration for development and production
- All endpoint definitions with proper HTTP methods
- Request/response schemas for all operations
- Error response schemas (400, 404, 500)
- Proper parameter definitions (path, query)
- Authentication scheme (Bearer token)

### Task 2: Express.js Implementation
Create a `server.js` file that:
- Sets up Express server with Swagger UI
- Implements all documented endpoints
- Uses proper HTTP status codes
- Includes request validation middleware
- Returns responses matching the OpenAPI schema

### Task 3: Interactive Documentation
- Configure Swagger UI to serve at `/api-docs`
- Add custom CSS styling for better presentation
- Include API usage examples
- Add authentication testing capability

## Validation Criteria
- [ ] OpenAPI spec passes validation (use swagger-editor)
- [ ] All endpoints return responses matching the schema
- [ ] Swagger UI displays properly formatted documentation
- [ ] Examples and descriptions are clear and helpful
- [ ] Authentication flow is properly documented

## Bonus Challenges
1. Add request/response examples for each endpoint
2. Implement OpenAPI spec validation middleware
3. Generate client SDKs from the specification
4. Add API versioning to the specification
5. Include rate limiting information in the documentation

## Files to Submit
```
exercise-1/
├── openapi.yaml
├── server.js
├── package.json
└── README.md
```

## Expected Time
2-3 hours

## Resources
- [OpenAPI Specification](https://swagger.io/specification/)
- [Swagger UI Express](https://github.com/scottie1984/swagger-ui-express)
- [OpenAPI Generator](https://openapi-generator.tech/)

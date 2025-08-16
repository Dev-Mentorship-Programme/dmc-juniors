# Exercise 2: API Versioning Implementation

## Objective
Implement a multi-versioned API system that supports different versioning strategies and maintains backward compatibility.

## Scenario
You're working on an e-commerce API that needs to support multiple client applications. Some clients are using older versions while new clients need access to latest features.

## Requirements

### API Versions to Support
- **v1.0**: Basic product information
- **v1.1**: Added product reviews
- **v2.0**: Complete product redesign with categories
- **v2.1**: Added inventory management

### Core Endpoints
1. `GET /products` - List products
2. `GET /products/{id}` - Get product details
3. `POST /products` - Create product
4. `PUT /products/{id}` - Update product

## Tasks

### Task 1: URL Path Versioning
Implement versioning using URL paths:
```
GET /api/v1/products
GET /api/v2/products
```

**Requirements:**
- Separate route handlers for each version
- Different response schemas per version
- Proper error handling for unsupported versions

### Task 2: Header Versioning
Implement versioning using custom headers:
```
GET /api/products
Headers: API-Version: 2.1
```

**Requirements:**
- Parse version from request headers
- Default to latest version if header missing
- Support version ranges (e.g., "2.x", ">=1.1")

### Task 3: Query Parameter Versioning
Implement versioning using query parameters:
```
GET /api/products?version=2.0
```

**Requirements:**
- Extract version from query parameters
- Validate version format
- Handle invalid version requests gracefully

### Task 4: Content Negotiation
Implement versioning using Accept header:
```
GET /api/products
Accept: application/vnd.api+json;version=2
```

**Requirements:**
- Parse custom media types
- Support multiple format negotiations
- Fallback to default version

### Task 5: Version Migration
Create a version migration system that:
- Transforms v1 responses to v2 format
- Handles breaking changes gracefully
- Maintains data consistency across versions

## Data Schemas

### Version 1.0
```json
{
  "id": "string",
  "name": "string",
  "price": "number",
  "description": "string"
}
```

### Version 1.1 (Added reviews)
```json
{
  "id": "string",
  "name": "string",
  "price": "number",
  "description": "string",
  "reviews": [
    {
      "rating": "number",
      "comment": "string",
      "author": "string"
    }
  ]
}
```

### Version 2.0 (Breaking changes)
```json
{
  "product_id": "string",
  "product_name": "string",
  "pricing": {
    "amount": "number",
    "currency": "string"
  },
  "details": {
    "description": "string",
    "category": "string",
    "tags": ["string"]
  },
  "reviews_summary": {
    "average_rating": "number",
    "total_reviews": "number"
  }
}
```

## Implementation Requirements

### Middleware Structure
Create middleware for:
- Version detection and parsing
- Version validation
- Response transformation
- Deprecation warnings

### Error Handling
- Unsupported version responses
- Version format validation errors
- Deprecation notices
- Migration failure handling

### Documentation
- Version changelog
- Migration guides
- Deprecation timeline
- API compatibility matrix

## Validation Criteria
- [ ] All versioning strategies work correctly
- [ ] Backward compatibility maintained
- [ ] Proper error responses for invalid versions
- [ ] Version detection middleware functions properly
- [ ] Response transformation works for all versions
- [ ] Deprecation warnings are implemented
- [ ] Documentation is comprehensive

## Bonus Challenges
1. Implement automatic version sunset with warnings
2. Add version usage analytics
3. Create version-specific rate limiting
4. Build automated compatibility testing
5. Implement version-aware caching
6. Add client SDK auto-generation per version

## Files to Submit
```
exercise-2/
├── server.js
├── middleware/
│   ├── versionDetection.js
│   ├── versionValidation.js
│   └── responseTransformer.js
├── routes/
│   ├── v1/
│   ├── v2/
│   └── latest/
├── schemas/
│   ├── v1.json
│   ├── v2.json
│   └── transformations.js
├── package.json
└── README.md
```

## Expected Time
3-4 hours

## Testing Scenarios
1. Client requests with URL path versions
2. Client requests with header versions
3. Client requests with invalid versions
4. Mixed versioning strategy requests
5. Version migration scenarios
6. Deprecation warning scenarios

## Resources
- [API Versioning Best Practices](https://blog.postman.com/api-versioning/)
- [Semantic Versioning](https://semver.org/)
- [HTTP Content Negotiation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Content_negotiation)

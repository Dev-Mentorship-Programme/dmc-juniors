/**
 * Express.js API Documentation with Swagger/OpenAPI (TypeScript)
 * Module 1 - Week 1: API Documentation and OpenAPI Specification
 * 
 * This example demonstrates how to integrate OpenAPI documentation
 * with an Express.js application using swagger-jsdoc and swagger-ui-express.
 */

import express, { Request, Response, NextFunction, Application } from 'express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { 
  User, 
  Product, 
  CreateUserRequest, 
  UpdateUserRequest,
  PaginationQuery,
  PaginatedResponse,
  ErrorResponse
} from './types';

const app: Application = express();

// Middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting - Basic implementation
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: {
      message: 'Too many requests from this IP, please try again later',
      code: 'RATE_LIMIT_EXCEEDED'
    }
  }
});

app.use('/api/', limiter);

// Swagger configuration
const swaggerOptions: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'User Management API',
      version: '1.0.0',
      description: 'A comprehensive API for managing users with authentication and authorization',
      contact: {
        name: 'DMC Juniors Team',
        email: 'support@dmcjuniors.com'
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000/api/v1',
        description: 'Development server'
      },
      {
        url: 'https://api.dmcjuniors.com/v1',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        User: {
          type: 'object',
          required: ['id', 'email', 'username', 'firstName', 'lastName'],
          properties: {
            id: {
              type: 'string',
              description: 'Unique user identifier',
              example: '64a7b8c9d1e2f3g4h5i6j7k8'
            },
            email: {
              type: 'string',
              format: 'email',
              description: 'User email address',
              example: 'john.doe@example.com'
            },
            username: {
              type: 'string',
              description: 'Unique username',
              example: 'johndoe123'
            },
            firstName: {
              type: 'string',
              description: 'User first name',
              example: 'John'
            },
            lastName: {
              type: 'string',
              description: 'User last name',
              example: 'Doe'
            },
            role: {
              type: 'string',
              enum: ['admin', 'user', 'moderator'],
              description: 'User role',
              example: 'user'
            },
            isActive: {
              type: 'boolean',
              description: 'User account status',
              example: true
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              example: '2023-08-15T10:30:00Z'
            },
            updatedAt: {
              type: 'string',
              format: 'date-time',
              example: '2023-08-15T14:20:00Z'
            }
          }
        },
        CreateUserRequest: {
          type: 'object',
          required: ['email', 'username', 'password', 'firstName', 'lastName'],
          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'john.doe@example.com'
            },
            username: {
              type: 'string',
              minLength: 3,
              maxLength: 50,
              pattern: '^[a-zA-Z0-9_]+$',
              example: 'johndoe123'
            },
            password: {
              type: 'string',
              minLength: 8,
              example: 'SecurePassword123!'
            },
            firstName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
              example: 'John'
            },
            lastName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
              example: 'Doe'
            },
            role: {
              type: 'string',
              enum: ['admin', 'user', 'moderator'],
              default: 'user',
              example: 'user'
            }
          }
        },
        UpdateUserRequest: {
          type: 'object',
          properties: {
            email: {
              type: 'string',
              format: 'email',
              example: 'john.updated@example.com'
            },
            username: {
              type: 'string',
              minLength: 3,
              maxLength: 50,
              pattern: '^[a-zA-Z0-9_]+$',
              example: 'johndoe_updated'
            },
            firstName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
              example: 'John'
            },
            lastName: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
              example: 'Smith'
            },
            role: {
              type: 'string',
              enum: ['admin', 'user', 'moderator'],
              example: 'moderator'
            },
            isActive: {
              type: 'boolean',
              example: false
            }
          }
        },
        Product: {
          type: 'object',
          required: ['id', 'name', 'price', 'category'],
          properties: {
            id: {
              type: 'string',
              description: 'Unique product identifier',
              example: '64a7b8c9d1e2f3g4h5i6j7k9'
            },
            name: {
              type: 'string',
              description: 'Product name',
              example: 'Premium Headphones'
            },
            description: {
              type: 'string',
              description: 'Product description',
              example: 'High-quality wireless headphones with noise cancellation'
            },
            price: {
              type: 'number',
              format: 'float',
              minimum: 0,
              description: 'Product price in USD',
              example: 299.99
            },
            category: {
              type: 'string',
              description: 'Product category',
              example: 'Electronics'
            },
            inStock: {
              type: 'boolean',
              description: 'Stock availability',
              example: true
            },
            createdAt: {
              type: 'string',
              format: 'date-time',
              example: '2023-08-15T10:30:00Z'
            },
            updatedAt: {
              type: 'string',
              format: 'date-time',
              example: '2023-08-15T14:20:00Z'
            }
          }
        },
        PaginatedResponse: {
          type: 'object',
          properties: {
            data: {
              type: 'array',
              items: {
                oneOf: [
                  { $ref: '#/components/schemas/User' },
                  { $ref: '#/components/schemas/Product' }
                ]
              }
            },
            pagination: {
              type: 'object',
              properties: {
                page: { type: 'integer', example: 1 },
                limit: { type: 'integer', example: 10 },
                totalPages: { type: 'integer', example: 5 },
                totalItems: { type: 'integer', example: 50 },
                hasNext: { type: 'boolean', example: true },
                hasPrev: { type: 'boolean', example: false }
              }
            }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: false
            },
            error: {
              type: 'object',
              properties: {
                code: {
                  type: 'string',
                  example: 'VALIDATION_ERROR'
                },
                message: {
                  type: 'string',
                  example: 'The provided data is invalid'
                },
                details: {
                  type: 'object',
                  additionalProperties: true
                },
                timestamp: {
                  type: 'string',
                  format: 'date-time',
                  example: '2023-08-15T10:30:00Z'
                }
              }
            }
          }
        }
      },
      responses: {
        NotFound: {
          description: 'Resource not found',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        },
        ValidationError: {
          description: 'Validation error',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        },
        Unauthorized: {
          description: 'Unauthorized access',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        },
        ServerError: {
          description: 'Internal server error',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        }
      }
    },
    security: [
      {
        bearerAuth: []
      }
    ]
  },
  apis: ['./src/*.ts'] // Path to files containing OpenAPI definitions
};

const specs = swaggerJsdoc(swaggerOptions);

// Swagger UI setup
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info { margin: 20px 0 }
    .swagger-ui .scheme-container { margin: 20px 0 }
  `,
  customSiteTitle: "User Management API Documentation",
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    showCommonExtensions: true
  }
}));

// Mock data storage (in production, use a proper database)
interface MockDatabase {
  users: User[];
  products: Product[];
}

const mockDatabase: MockDatabase = {
  users: [
    {
      id: '1',
      name: 'John Doe',
      email: 'john.doe@example.com',
      role: 'user',
      createdAt: '2023-08-15T10:30:00Z',
      updatedAt: '2023-08-15T10:30:00Z'
    },
    {
      id: '2',
      name: 'Jane Smith',
      email: 'jane.smith@example.com',
      role: 'admin',
      createdAt: '2023-08-15T11:00:00Z',
      updatedAt: '2023-08-15T11:00:00Z'
    }
  ],
  products: [
    {
      id: '1',
      name: 'Premium Headphones',
      description: 'High-quality wireless headphones',
      price: 299.99,
      category: 'Electronics',
      inStock: true,
      createdAt: '2023-08-15T10:30:00Z',
      updatedAt: '2023-08-15T10:30:00Z'
    }
  ]
};

// Utility functions
const generateId = (): string => Math.random().toString(36).substr(2, 9);

const createErrorResponse = (code: string, message: string, details?: any): ErrorResponse => ({
  error: {
    code,
    message,
    details,
    timestamp: new Date().toISOString()
  }
});

const paginate = <T>(array: T[], page: number, limit: number): PaginatedResponse<T> => {
  const offset = (page - 1) * limit;
  const paginatedData = array.slice(offset, offset + limit);
  const totalItems = array.length;
  const totalPages = Math.ceil(totalItems / limit);

  return {
    data: paginatedData,
    pagination: {
      page,
      limit,
      totalPages,
      totalItems,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  };
};

// Routes

/**
 * @openapi
 * /api/v1/health:
 *   get:
 *     tags: [Health Check]
 *     summary: Health check endpoint
 *     description: Returns the health status of the API
 *     responses:
 *       200:
 *         description: API is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "healthy"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: "2023-08-15T10:30:00Z"
 *                 version:
 *                   type: string
 *                   example: "1.0.0"
 *                 environment:
 *                   type: string
 *                   example: "development"
 */
app.get('/api/v1/health', (req: Request, res: Response): void => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * @openapi
 * /api/v1/users:
 *   get:
 *     tags: [Users]
 *     summary: Get all users
 *     description: Retrieve a paginated list of users
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 10
 *         description: Number of users per page
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *           enum: [admin, user, moderator]
 *         description: Filter by user role
 *     responses:
 *       200:
 *         description: Successfully retrieved users
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/PaginatedResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/User'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.get('/api/v1/users', (req: Request<{}, any, any, PaginationQuery>, res: Response): void => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '10', 10);
    const role = req.query.role;

    if (page < 1 || limit < 1 || limit > 100) {
      res.status(400).json(createErrorResponse(
        'VALIDATION_ERROR',
        'Invalid pagination parameters'
      ));
      return;
    }

    let filteredUsers = mockDatabase.users;
    if (role) {
      filteredUsers = mockDatabase.users.filter(user => user.role === role);
    }

    const result = paginate(filteredUsers, page, limit);
    res.json(result);
  } catch (error) {
    res.status(500).json(createErrorResponse(
      'INTERNAL_SERVER_ERROR',
      'Failed to retrieve users',
      { error: (error as Error).message }
    ));
  }
});

/**
 * @openapi
 * /api/v1/users/{id}:
 *   get:
 *     tags: [Users]
 *     summary: Get user by ID
 *     description: Retrieve a specific user by their ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: Successfully retrieved user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         $ref: '#/components/responses/NotFound'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.get('/api/v1/users/:id', (req: Request<{ id: string }>, res: Response): void => {
  try {
    const { id } = req.params;
    const user = mockDatabase.users.find(u => u.id === id);

    if (!user) {
      res.status(404).json(createErrorResponse(
        'USER_NOT_FOUND',
        `User with ID ${id} not found`
      ));
      return;
    }

    res.json(user);
  } catch (error) {
    res.status(500).json(createErrorResponse(
      'INTERNAL_SERVER_ERROR',
      'Failed to retrieve user',
      { error: (error as Error).message }
    ));
  }
});

/**
 * @openapi
 * /api/v1/users:
 *   post:
 *     tags: [Users]
 *     summary: Create a new user
 *     description: Create a new user with the provided information
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateUserRequest'
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       409:
 *         description: User already exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.post('/api/v1/users', (req: Request<{}, any, CreateUserRequest>, res: Response): void => {
  try {
    const { name, email, role = 'user' } = req.body;

    // Basic validation
    if (!name || !email) {
      res.status(400).json(createErrorResponse(
        'VALIDATION_ERROR',
        'Name and email are required'
      ));
      return;
    }

    // Check if user already exists
    const existingUser = mockDatabase.users.find(u => u.email === email);
    if (existingUser) {
      res.status(409).json(createErrorResponse(
        'USER_ALREADY_EXISTS',
        'A user with this email already exists'
      ));
      return;
    }

    const newUser: User = {
      id: generateId(),
      name,
      email,
      role,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    mockDatabase.users.push(newUser);
    res.status(201).json(newUser);
  } catch (error) {
    res.status(500).json(createErrorResponse(
      'INTERNAL_SERVER_ERROR',
      'Failed to create user',
      { error: (error as Error).message }
    ));
  }
});

/**
 * @openapi
 * /api/v1/users/{id}:
 *   put:
 *     tags: [Users]
 *     summary: Update user
 *     description: Update an existing user's information
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUserRequest'
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         $ref: '#/components/responses/NotFound'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.put('/api/v1/users/:id', (req: Request<{ id: string }, any, UpdateUserRequest>, res: Response): void => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const userIndex = mockDatabase.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      res.status(404).json(createErrorResponse(
        'USER_NOT_FOUND',
        `User with ID ${id} not found`
      ));
      return;
    }

    // Update user
    const updatedUser: User = {
      ...mockDatabase.users[userIndex]!,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    mockDatabase.users[userIndex] = updatedUser;
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json(createErrorResponse(
      'INTERNAL_SERVER_ERROR',
      'Failed to update user',
      { error: (error as Error).message }
    ));
  }
});

/**
 * @openapi
 * /api/v1/users/{id}:
 *   delete:
 *     tags: [Users]
 *     summary: Delete user
 *     description: Delete a user by their ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       204:
 *         description: User deleted successfully
 *       404:
 *         $ref: '#/components/responses/NotFound'
 *       500:
 *         $ref: '#/components/responses/ServerError'
 */
app.delete('/api/v1/users/:id', (req: Request<{ id: string }>, res: Response): void => {
  try {
    const { id } = req.params;

    const userIndex = mockDatabase.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      res.status(404).json(createErrorResponse(
        'USER_NOT_FOUND',
        `User with ID ${id} not found`
      ));
      return;
    }

    mockDatabase.users.splice(userIndex, 1);
    res.status(204).send();
  } catch (error) {
    res.status(500).json(createErrorResponse(
      'INTERNAL_SERVER_ERROR',
      'Failed to delete user',
      { error: (error as Error).message }
    ));
  }
});

// Global error handler
app.use((error: Error, req: Request, res: Response, next: NextFunction): void => {
  console.error('Unhandled error:', error);
  res.status(500).json(createErrorResponse(
    'INTERNAL_SERVER_ERROR',
    'An unexpected error occurred',
    { error: error.message }
  ));
});

// 404 handler
app.use((req: Request, res: Response): void => {
  res.status(404).json(createErrorResponse(
    'ENDPOINT_NOT_FOUND',
    `Endpoint ${req.method} ${req.path} not found`
  ));
});

const PORT: number = parseInt(process.env.PORT || '3000', 10);

app.listen(PORT, (): void => {
  console.log(`
🚀 Server running on port ${PORT}
📚 API Documentation available at: http://localhost:${PORT}/api-docs
🌐 Health Check: http://localhost:${PORT}/api/v1/health

Available endpoints:
- GET    /api/v1/health
- GET    /api/v1/users
- GET    /api/v1/users/:id
- POST   /api/v1/users
- PUT    /api/v1/users/:id
- DELETE /api/v1/users/:id
`);
});

export default app;

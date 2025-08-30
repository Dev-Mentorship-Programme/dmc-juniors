/**
 * Express.js API Documentation with Swagger/OpenAPI
 * Module 1 - Week 1: API Documentation and OpenAPI Specification
 * 
 * This example demonstrates how to integrate OpenAPI documentation
 * with an Express.js application using swagger-jsdoc and swagger-ui-express.
 */

const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

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

const openApiSpec = yaml.load(
  fs.readFileSync(path.join(__dirname, 'express-swagger.yaml'), 'utf8')
);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiSpec));

// Swagger configuration


// Generate swagger specification
const specs = swaggerJsdoc(swaggerOptions);

// Mock data store (in production, use a proper database)
let users = [
  {
    id: '64a7b8c9d1e2f3g4h5i6j7k8',
    email: 'admin@example.com',
    username: 'admin',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    isActive: true,
    createdAt: '2023-08-15T10:30:00Z',
    updatedAt: '2023-08-15T10:30:00Z'
  }
];


app.get('/api/v1/users', authenticateToken, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search;

    let filteredUsers = users;

    // Apply search filter if provided
    if (search) {
      filteredUsers = users.filter(user =>
        user.firstName.toLowerCase().includes(search.toLowerCase()) ||
        user.lastName.toLowerCase().includes(search.toLowerCase()) ||
        user.email.toLowerCase().includes(search.toLowerCase()) ||
        user.username.toLowerCase().includes(search.toLowerCase())
      );
    }

    // Apply pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

    // Calculate pagination info
    const totalItems = filteredUsers.length;
    const totalPages = Math.ceil(totalItems / limit);

    res.json({
      success: true,
      data: paginatedUsers,
      pagination: {
        currentPage: page,
        totalPages,
        totalItems,
        itemsPerPage: limit,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error',
        code: 'INTERNAL_ERROR'
      }
    });
  }
});


app.post('/api/v1/users', validateUserInput, (req, res) => {
  try {
    const { email, username, password, firstName, lastName, role = 'user' } = req.body;

    // Check if user already exists
    const existingUser = users.find(u => u.email === email || u.username === username);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: {
          message: 'User with this email or username already exists',
          code: 'USER_EXISTS'
        }
      });
    }

    // Create new user
    const newUser = {
      id: generateId(),
      email,
      username,
      firstName,
      lastName,
      role,
      isActive: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    users.push(newUser);

    res.status(201).json({
      success: true,
      data: newUser
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error',
        code: 'INTERNAL_ERROR'
      }
    });
  }
});


app.get('/api/v1/users/:userId', authenticateToken, (req, res) => {
  try {
    const { userId } = req.params;
    const user = users.find(u => u.id === userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          message: 'User not found',
          code: 'NOT_FOUND'
        }
      });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error',
        code: 'INTERNAL_ERROR'
      }
    });
  }
});

// Middleware functions
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        message: 'Authentication token required',
        code: 'UNAUTHORIZED'
      }
    });
  }

  // In a real application, verify the JWT token here
  // For this example, we'll just check if token exists
  if (token !== 'demo-token') {
    return res.status(401).json({
      success: false,
      error: {
        message: 'Invalid token',
        code: 'UNAUTHORIZED'
      }
    });
  }

  next();
}

function validateUserInput(req, res, next) {
  const { email, username, password, firstName, lastName } = req.body;
  const errors = [];

  if (!email) errors.push('Email is required');
  if (!username) errors.push('Username is required');
  if (!password) errors.push('Password is required');
  if (!firstName) errors.push('First name is required');
  if (!lastName) errors.push('Last name is required');

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push('Invalid email format');
  }

  if (username && (username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username))) {
    errors.push('Username must be at least 3 characters and contain only letters, numbers, and underscores');
  }

  if (password && password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation error',
        code: 'VALIDATION_ERROR',
        details: errors
      }
    });
  }

  next();
}

function generateId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Health check endpoint
app.get('/api/v1/health', (req, res) => {
  res.json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    error: {
      message: 'Internal server error',
      code: 'INTERNAL_ERROR'
    }
  });
});

// Handle 404 errors
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      message: 'Endpoint not found',
      code: 'NOT_FOUND'
    }
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📚 API Documentation available at http://localhost:${PORT}/api-docs`);
  console.log(`🏥 Health check available at http://localhost:${PORT}/api/v1/health`);
});

module.exports = app;

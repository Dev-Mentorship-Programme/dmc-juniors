import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { ResilientApiClient, ResilientClientConfig } from './ResilientApiClient';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Create API client instances for demonstration
const jsonPlaceholderConfig: ResilientClientConfig = {
  baseURL: 'https://jsonplaceholder.typicode.com',
  timeout: 5000,
  rateLimitConfig: {
    minTime: 100, // 100ms between requests
    maxConcurrent: 5
  },
  circuitBreakerConfig: {
    failureThreshold: 3,
    successThreshold: 2,
    timeout: 10000,
    resetTimeout: 10000
  },
  retryConfig: {
    retries: 3,
    retryDelay: 1000
  }
};

const httpBinConfig: ResilientClientConfig = {
  baseURL: 'https://httpbin.org',
  timeout: 10000,
  rateLimitConfig: {
    minTime: 200,
    maxConcurrent: 3
  },
  circuitBreakerConfig: {
    failureThreshold: 2,
    successThreshold: 1,
    timeout: 5000,
    resetTimeout: 5000
  }
};

const jsonPlaceholderClient = new ResilientApiClient(jsonPlaceholderConfig);
const httpBinClient = new ResilientApiClient(httpBinConfig);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// API routes for demonstration

/**
 * @route   GET /api/posts
 * @desc    Fetch posts from JSONPlaceholder
 * @access  Public
 */
app.get('/api/posts', async (req, res) => {
  try {
    const response = await jsonPlaceholderClient.get('/posts');
    
    res.json({
      success: true,
      data: response.data.slice(0, 10), // Return first 10 posts
      metadata: {
        duration: response.duration,
        status: response.status,
        circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.message,
      circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
    });
  }
});

/**
 * @route   GET /api/posts/:id
 * @desc    Fetch a specific post
 * @access  Public
 */
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const response = await jsonPlaceholderClient.get(`/posts/${id}`);
    
    res.json({
      success: true,
      data: response.data,
      metadata: {
        duration: response.duration,
        status: response.status,
        circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.message,
      circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
    });
  }
});

/**
 * @route   POST /api/test-post
 * @desc    Create a test post
 * @access  Public
 */
app.post('/api/test-post', async (req, res) => {
  try {
    const postData = {
      title: req.body.title || 'Test Post',
      body: req.body.body || 'This is a test post created via resilient API client',
      userId: req.body.userId || 1
    };

    const response = await jsonPlaceholderClient.post('/posts', postData);
    
    res.json({
      success: true,
      data: response.data,
      metadata: {
        duration: response.duration,
        status: response.status,
        circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.message,
      circuitBreakerState: jsonPlaceholderClient.getCircuitBreakerState()
    });
  }
});

/**
 * @route   GET /api/test-delay/:seconds
 * @desc    Test delayed response handling
 * @access  Public
 */
app.get('/api/test-delay/:seconds', async (req, res) => {
  try {
    const { seconds } = req.params;
    const delaySeconds = Math.min(parseInt(seconds) || 1, 10); // Max 10 seconds
    
    const response = await httpBinClient.get(`/delay/${delaySeconds}`);
    
    res.json({
      success: true,
      data: response.data,
      metadata: {
        duration: response.duration,
        status: response.status,
        delayRequested: delaySeconds,
        circuitBreakerState: httpBinClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.message,
      circuitBreakerState: httpBinClient.getCircuitBreakerState()
    });
  }
});

/**
 * @route   GET /api/test-failure/:statusCode
 * @desc    Test failure handling with specific status codes
 * @access  Public
 */
app.get('/api/test-failure/:statusCode', async (req, res) => {
  try {
    const { statusCode } = req.params;
    const code = parseInt(statusCode) || 500;
    
    const response = await httpBinClient.get(`/status/${code}`);
    
    res.json({
      success: true,
      data: response.data,
      metadata: {
        duration: response.duration,
        status: response.status,
        circuitBreakerState: httpBinClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.message,
      circuitBreakerState: httpBinClient.getCircuitBreakerState()
    });
  }
});

/**
 * @route   GET /api/circuit-breaker-status
 * @desc    Get circuit breaker status for all clients
 * @access  Public
 */
app.get('/api/circuit-breaker-status', (req, res) => {
  res.json({
    success: true,
    data: {
      jsonPlaceholder: {
        state: jsonPlaceholderClient.getCircuitBreakerState(),
        config: jsonPlaceholderConfig.circuitBreakerConfig
      },
      httpBin: {
        state: httpBinClient.getCircuitBreakerState(),
        config: httpBinConfig.circuitBreakerConfig
      }
    }
  });
});

/**
 * @route   POST /api/circuit-breaker/reset
 * @desc    Reset circuit breakers
 * @access  Public
 */
app.post('/api/circuit-breaker/reset', (req, res) => {
  try {
    jsonPlaceholderClient.resetCircuitBreaker();
    httpBinClient.resetCircuitBreaker();
    
    res.json({
      success: true,
      message: 'Circuit breakers reset successfully',
      data: {
        jsonPlaceholder: jsonPlaceholderClient.getCircuitBreakerState(),
        httpBin: httpBinClient.getCircuitBreakerState()
      }
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// Global error handler
app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', error);
  
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Resilient API Client Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`   GET  /api/posts                     - Fetch posts from JSONPlaceholder`);
  console.log(`   GET  /api/posts/:id                 - Fetch specific post`);
  console.log(`   POST /api/test-post                 - Create test post`);
  console.log(`   GET  /api/test-delay/:seconds       - Test delayed responses`);
  console.log(`   GET  /api/test-failure/:statusCode  - Test failure handling`);
  console.log(`   GET  /api/circuit-breaker-status    - Get circuit breaker status`);
  console.log(`   POST /api/circuit-breaker/reset     - Reset circuit breakers`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

export default app;

/**
 * API Versioning Strategies Example
 * Module 1 - Week 1: API Versioning Strategies
 * 
 * This example demonstrates different API versioning strategies:
 * 1. URL Path Versioning
 * 2. Query Parameter Versioning
 * 3. Header Versioning
 * 4. Content Negotiation Versioning
 */

const express = require('express');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mock data - different versions of user objects
const usersV1 = [
  {
    id: 1,
    name: 'John Doe',
    email: 'john@example.com'
  },
  {
    id: 2,
    name: 'Jane Smith',
    email: 'jane@example.com'
  }
];

const usersV2 = [
  {
    id: 1,
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    createdAt: '2023-01-15T10:30:00Z'
  },
  {
    id: 2,
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane@example.com',
    createdAt: '2023-02-20T14:20:00Z'
  }
];

const usersV3 = [
  {
    id: 1,
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    profile: {
      avatar: 'https://example.com/avatars/john.jpg',
      bio: 'Software developer'
    },
    createdAt: '2023-01-15T10:30:00Z',
    updatedAt: '2023-01-15T10:30:00Z'
  },
  {
    id: 2,
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane@example.com',
    profile: {
      avatar: 'https://example.com/avatars/jane.jpg',
      bio: 'Product manager'
    },
    createdAt: '2023-02-20T14:20:00Z',
    updatedAt: '2023-02-20T14:20:00Z'
  }
];

// =================================================================
// STRATEGY 1: URL PATH VERSIONING
// =================================================================
// Most common and explicit approach
// Pros: Clear, easy to understand, RESTful
// Cons: URL proliferation, potential duplication

app.get('/api/v1/users', (req, res) => {
  res.json({
    version: '1.0',
    data: usersV1,
    message: 'URL Path Versioning - Version 1'
  });
});

app.get('/api/v2/users', (req, res) => {
  res.json({
    version: '2.0',
    data: usersV2,
    message: 'URL Path Versioning - Version 2 (firstName/lastName split)'
  });
});

app.get('/api/v3/users', (req, res) => {
  res.json({
    version: '3.0',
    data: usersV3,
    message: 'URL Path Versioning - Version 3 (added profile object)'
  });
});

// =================================================================
// STRATEGY 2: QUERY PARAMETER VERSIONING
// =================================================================
// Version specified as a query parameter
// Pros: Single URL, optional parameter
// Cons: Can be overlooked, not RESTful

app.get('/api/users', (req, res) => {
  const version = req.query.version || req.query.v || '1';

  switch (version) {
    case '1':
    case '1.0':
      res.json({
        version: '1.0',
        data: usersV1,
        message: 'Query Parameter Versioning - Version 1 (default)'
      });
      break;

    case '2':
    case '2.0':
      res.json({
        version: '2.0',
        data: usersV2,
        message: 'Query Parameter Versioning - Version 2'
      });
      break;

    case '3':
    case '3.0':
      res.json({
        version: '3.0',
        data: usersV3,
        message: 'Query Parameter Versioning - Version 3'
      });
      break;

    default:
      res.status(400).json({
        error: 'Unsupported API version',
        supportedVersions: ['1', '2', '3'],
        requestedVersion: version
      });
  }
});

// =================================================================
// STRATEGY 3: HEADER VERSIONING
// =================================================================
// Version specified in HTTP headers
// Pros: Clean URLs, flexible
// Cons: Less discoverable, requires header management

// Custom header versioning middleware
const headerVersioning = (req, res, next) => {
  // Check multiple possible header names
  const version = 
    req.headers['api-version'] || 
    req.headers['x-api-version'] || 
    req.headers['version'] || 
    '1';

  req.apiVersion = version;
  next();
};

app.get('/users', headerVersioning, (req, res) => {
  const version = req.apiVersion;

  // Set version info in response headers
  res.set('X-API-Version', version);
  res.set('X-Supported-Versions', '1, 2, 3');

  switch (version) {
    case '1':
    case '1.0':
      res.json({
        version: '1.0',
        data: usersV1,
        message: 'Header Versioning - Version 1'
      });
      break;

    case '2':
    case '2.0':
      res.json({
        version: '2.0',
        data: usersV2,
        message: 'Header Versioning - Version 2'
      });
      break;

    case '3':
    case '3.0':
      res.json({
        version: '3.0',
        data: usersV3,
        message: 'Header Versioning - Version 3'
      });
      break;

    default:
      res.status(400).json({
        error: 'Unsupported API version',
        supportedVersions: ['1', '2', '3'],
        requestedVersion: version
      });
  }
});

// =================================================================
// STRATEGY 4: CONTENT NEGOTIATION VERSIONING
// =================================================================
// Version specified in Accept header (Media Type Versioning)
// Pros: HTTP standard compliant, flexible
// Cons: Complex, requires proper Accept header handling

const contentNegotiationVersioning = (req, res, next) => {
  const acceptHeader = req.headers.accept || 'application/json';
  
  // Parse version from Accept header
  // Examples:
  // - application/vnd.dmcjuniors.v1+json
  // - application/vnd.dmcjuniors.v2+json
  // - application/json (defaults to v1)
  
  let version = '1';
  const versionMatch = acceptHeader.match(/vnd\.dmcjuniors\.v(\d+)/);
  
  if (versionMatch) {
    version = versionMatch[1];
  }
  
  req.apiVersion = version;
  next();
};

app.get('/content-negotiation/users', contentNegotiationVersioning, (req, res) => {
  const version = req.apiVersion;
  
  // Set appropriate content type in response
  const contentType = `application/vnd.dmcjuniors.v${version}+json`;
  res.set('Content-Type', contentType);
  res.set('X-API-Version', version);

  switch (version) {
    case '1':
      res.json({
        version: '1.0',
        data: usersV1,
        message: 'Content Negotiation Versioning - Version 1'
      });
      break;

    case '2':
      res.json({
        version: '2.0',
        data: usersV2,
        message: 'Content Negotiation Versioning - Version 2'
      });
      break;

    case '3':
      res.json({
        version: '3.0',
        data: usersV3,
        message: 'Content Negotiation Versioning - Version 3'
      });
      break;

    default:
      res.status(406).json({
        error: 'Not Acceptable - Unsupported API version',
        supportedVersions: ['1', '2', '3'],
        acceptedFormats: [
          'application/vnd.dmcjuniors.v1+json',
          'application/vnd.dmcjuniors.v2+json',
          'application/vnd.dmcjuniors.v3+json'
        ],
        requestedVersion: version
      });
  }
});

// =================================================================
// STRATEGY 5: HYBRID APPROACH
// =================================================================
// Combines multiple strategies with priority order

const hybridVersioning = (req, res, next) => {
  // Priority order: URL path > Header > Query Parameter > Default
  let version = '1';

  // Check URL path first (if it exists)
  if (req.path.includes('/v')) {
    const pathMatch = req.path.match(/\/v(\d+)\//);
    if (pathMatch) {
      version = pathMatch[1];
    }
  } 
  // Check headers
  else if (req.headers['api-version'] || req.headers['x-api-version']) {
    version = req.headers['api-version'] || req.headers['x-api-version'];
  }
  // Check query parameters
  else if (req.query.version || req.query.v) {
    version = req.query.version || req.query.v;
  }

  req.apiVersion = version;
  next();
};

app.get('/hybrid/users', hybridVersioning, (req, res) => {
  const version = req.apiVersion;
  
  res.set('X-API-Version', version);
  res.set('X-Version-Strategy', 'hybrid');

  switch (version) {
    case '1':
      res.json({
        version: '1.0',
        data: usersV1,
        message: 'Hybrid Versioning - Version 1',
        strategy: 'Multiple versioning strategies supported'
      });
      break;

    case '2':
      res.json({
        version: '2.0',
        data: usersV2,
        message: 'Hybrid Versioning - Version 2',
        strategy: 'Multiple versioning strategies supported'
      });
      break;

    case '3':
      res.json({
        version: '3.0',
        data: usersV3,
        message: 'Hybrid Versioning - Version 3',
        strategy: 'Multiple versioning strategies supported'
      });
      break;

    default:
      res.status(400).json({
        error: 'Unsupported API version',
        supportedVersions: ['1', '2', '3'],
        requestedVersion: version,
        strategy: 'hybrid'
      });
  }
});

// =================================================================
// VERSION DEPRECATION AND SUNSET
// =================================================================

// Deprecation warnings
app.use('/api/v1/*', (req, res, next) => {
  res.set('Deprecation', 'true');
  res.set('Sunset', 'Sat, 31 Dec 2024 23:59:59 GMT');
  res.set('Link', '</api/v3/users>; rel="successor-version"');
  next();
});

// =================================================================
// VERSION DISCOVERY ENDPOINTS
// =================================================================

// API versions discovery endpoint
app.get('/api/versions', (req, res) => {
  res.json({
    currentVersion: '3.0',
    supportedVersions: [
      {
        version: '1.0',
        status: 'deprecated',
        sunsetDate: '2024-12-31',
        description: 'Legacy version with basic user info'
      },
      {
        version: '2.0',
        status: 'supported',
        description: 'Enhanced version with firstName/lastName split'
      },
      {
        version: '3.0',
        status: 'current',
        description: 'Latest version with profile information'
      }
    ],
    strategies: [
      'URL Path (/api/v1/users)',
      'Query Parameter (?version=1)',
      'Header (API-Version: 1)',
      'Content Negotiation (Accept: application/vnd.dmcjuniors.v1+json)',
      'Hybrid (combination of above)'
    ]
  });
});

// =================================================================
// UTILITY FUNCTIONS AND MIDDLEWARE
// =================================================================

// Version validation middleware
const validateVersion = (supportedVersions) => {
  return (req, res, next) => {
    const version = req.apiVersion || req.query.version || req.headers['api-version'] || '1';
    
    if (!supportedVersions.includes(version)) {
      return res.status(400).json({
        error: 'Unsupported API version',
        requestedVersion: version,
        supportedVersions: supportedVersions
      });
    }
    
    next();
  };
};

// Version transformation middleware
const transformResponse = (req, res, next) => {
  const originalJson = res.json;
  
  res.json = function(data) {
    // Add version metadata to all responses
    const enhancedData = {
      ...data,
      _metadata: {
        version: req.apiVersion || '1',
        timestamp: new Date().toISOString(),
        strategy: req.versionStrategy || 'unknown'
      }
    };
    
    originalJson.call(this, enhancedData);
  };
  
  next();
};

// =================================================================
// ERROR HANDLING
// =================================================================

// Global error handler for versioning issues
app.use((err, req, res, next) => {
  if (err.type === 'version-error') {
    return res.status(400).json({
      error: 'Version Error',
      message: err.message,
      supportedVersions: ['1', '2', '3']
    });
  }
  
  next(err);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'Endpoint not found',
    availableEndpoints: [
      'GET /api/v1/users',
      'GET /api/v2/users',
      'GET /api/v3/users',
      'GET /api/users?version=1',
      'GET /users (with API-Version header)',
      'GET /content-negotiation/users (with Accept header)',
      'GET /hybrid/users',
      'GET /api/versions'
    ]
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 API Versioning Example Server running on port ${PORT}`);
  console.log('\n📚 Available endpoints:');
  console.log('  URL Path Versioning:');
  console.log(`    GET http://localhost:${PORT}/api/v1/users`);
  console.log(`    GET http://localhost:${PORT}/api/v2/users`);
  console.log(`    GET http://localhost:${PORT}/api/v3/users`);
  console.log('\n  Query Parameter Versioning:');
  console.log(`    GET http://localhost:${PORT}/api/users?version=1`);
  console.log(`    GET http://localhost:${PORT}/api/users?version=2`);
  console.log(`    GET http://localhost:${PORT}/api/users?version=3`);
  console.log('\n  Header Versioning:');
  console.log(`    GET http://localhost:${PORT}/users`);
  console.log('    (with header: API-Version: 1, 2, or 3)');
  console.log('\n  Content Negotiation:');
  console.log(`    GET http://localhost:${PORT}/content-negotiation/users`);
  console.log('    (with Accept: application/vnd.dmcjuniors.v1+json)');
  console.log('\n  Hybrid Approach:');
  console.log(`    GET http://localhost:${PORT}/hybrid/users`);
  console.log('\n  Version Discovery:');
  console.log(`    GET http://localhost:${PORT}/api/versions`);
});

module.exports = app;

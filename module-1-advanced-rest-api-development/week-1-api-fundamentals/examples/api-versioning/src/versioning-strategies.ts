import express, { Request, Response, NextFunction } from 'express';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

type VersionedRequest = Request & { apiVersion?: string; versionStrategy?: string };

const usersV1 = [
  { id: 1, name: 'John Doe', email: 'john@example.com' },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
];

const usersV2 = [
  { id: 1, firstName: 'John', lastName: 'Doe', email: 'john@example.com', createdAt: '2023-01-15T10:30:00Z' },
  { id: 2, firstName: 'Jane', lastName: 'Smith', email: 'jane@example.com', createdAt: '2023-02-20T14:20:00Z' },
];

const usersV3 = [
  {
    id: 1,
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    profile: { avatar: 'https://example.com/avatars/john.jpg', bio: 'Software developer' },
    createdAt: '2023-01-15T10:30:00Z',
    updatedAt: '2023-01-15T10:30:00Z',
  },
  {
    id: 2,
    firstName: 'Jane',
    lastName: 'Smith',
    email: 'jane@example.com',
    profile: { avatar: 'https://example.com/avatars/jane.jpg', bio: 'Product manager' },
    createdAt: '2023-02-20T14:20:00Z',
    updatedAt: '2023-02-20T14:20:00Z',
  },
];

// URL Path Versioning
app.get('/api/v1/users', (_req: Request, res: Response) => {
  res.json({ version: '1.0', data: usersV1, message: 'URL Path Versioning - Version 1' });
});

app.get('/api/v2/users', (_req: Request, res: Response) => {
  res.json({ version: '2.0', data: usersV2, message: 'URL Path Versioning - Version 2 (firstName/lastName split)' });
});

app.get('/api/v3/users', (_req: Request, res: Response) => {
  res.json({ version: '3.0', data: usersV3, message: 'URL Path Versioning - Version 3 (added profile object)' });
});

// Query Parameter Versioning
app.get('/api/users', (req: Request, res: Response) => {
  const version = (req.query.version || req.query.v || '1') as string;

  switch (version) {
    case '1':
    case '1.0':
      res.json({ version: '1.0', data: usersV1, message: 'Query Parameter Versioning - Version 1 (default)' });
      break;
    case '2':
    case '2.0':
      res.json({ version: '2.0', data: usersV2, message: 'Query Parameter Versioning - Version 2' });
      break;
    case '3':
    case '3.0':
      res.json({ version: '3.0', data: usersV3, message: 'Query Parameter Versioning - Version 3' });
      break;
    default:
      res.status(400).json({ error: 'Unsupported API version', supportedVersions: ['1', '2', '3'], requestedVersion: version });
  }
});

// Header Versioning
const headerVersioning = (req: VersionedRequest, _res: Response, next: NextFunction) => {
  const version = (req.headers['api-version'] || req.headers['x-api-version'] || req.headers['version'] || '1') as string;
  req.apiVersion = version;
  next();
};

app.get('/users', headerVersioning, (req: VersionedRequest, res: Response) => {
  const version = req.apiVersion || '1';
  res.set('X-API-Version', version);
  res.set('X-Supported-Versions', '1, 2, 3');

  switch (version) {
    case '1':
    case '1.0':
      res.json({ version: '1.0', data: usersV1, message: 'Header Versioning - Version 1' });
      break;
    case '2':
    case '2.0':
      res.json({ version: '2.0', data: usersV2, message: 'Header Versioning - Version 2' });
      break;
    case '3':
    case '3.0':
      res.json({ version: '3.0', data: usersV3, message: 'Header Versioning - Version 3' });
      break;
    default:
      res.status(400).json({ error: 'Unsupported API version', supportedVersions: ['1', '2', '3'], requestedVersion: version });
  }
});

// Content Negotiation Versioning
const contentNegotiationVersioning = (req: VersionedRequest, _res: Response, next: NextFunction) => {
  const acceptHeader = (req.headers.accept || 'application/json') as string;
  let version = '1';
  const versionMatch = acceptHeader.match(/vnd\.dmcjuniors\.v(\d+)/);
  if (versionMatch && versionMatch[1]) version = versionMatch[1];
  req.apiVersion = version;
  next();
};

app.get('/content-negotiation/users', contentNegotiationVersioning, (req: VersionedRequest, res: Response) => {
  const version = req.apiVersion || '1';
  const contentType = `application/vnd.dmcjuniors.v${version}+json`;
  res.set('Content-Type', contentType);
  res.set('X-API-Version', version);

  switch (version) {
    case '1':
      res.json({ version: '1.0', data: usersV1, message: 'Content Negotiation Versioning - Version 1' });
      break;
    case '2':
      res.json({ version: '2.0', data: usersV2, message: 'Content Negotiation Versioning - Version 2' });
      break;
    case '3':
      res.json({ version: '3.0', data: usersV3, message: 'Content Negotiation Versioning - Version 3' });
      break;
    default:
      res.status(406).json({
        error: 'Not Acceptable - Unsupported API version',
        supportedVersions: ['1', '2', '3'],
        acceptedFormats: [
          'application/vnd.dmcjuniors.v1+json',
          'application/vnd.dmcjuniors.v2+json',
          'application/vnd.dmcjuniors.v3+json',
        ],
        requestedVersion: version,
      });
  }
});

// Hybrid Approach
const hybridVersioning = (req: VersionedRequest, _res: Response, next: NextFunction) => {
  let version = '1';
  if (req.path.includes('/v')) {
    const pathMatch = req.path.match(/\/v(\d+)\//);
  // Guard against optional capture group possibly being undefined
  version = pathMatch?.[1] ?? version;
  } else if (req.headers['api-version'] || req.headers['x-api-version']) {
    version = (req.headers['api-version'] || req.headers['x-api-version']) as string;
  } else if (req.query.version || req.query.v) {
    version = String(req.query.version || req.query.v);
  }
  req.apiVersion = version;
  next();
};

app.get('/hybrid/users', hybridVersioning, (req: VersionedRequest, res: Response) => {
  const version = req.apiVersion || '1';
  res.set('X-API-Version', version);
  res.set('X-Version-Strategy', 'hybrid');

  switch (version) {
    case '1':
      res.json({ version: '1.0', data: usersV1, message: 'Hybrid Versioning - Version 1', strategy: 'Multiple versioning strategies supported' });
      break;
    case '2':
      res.json({ version: '2.0', data: usersV2, message: 'Hybrid Versioning - Version 2', strategy: 'Multiple versioning strategies supported' });
      break;
    case '3':
      res.json({ version: '3.0', data: usersV3, message: 'Hybrid Versioning - Version 3', strategy: 'Multiple versioning strategies supported' });
      break;
    default:
      res.status(400).json({ error: 'Unsupported API version', supportedVersions: ['1', '2', '3'], requestedVersion: version, strategy: 'hybrid' });
  }
});

// Deprecation warnings
app.use('/api/v1/*', (_req: Request, res: Response, next: NextFunction) => {
  res.set('Deprecation', 'true');
  res.set('Sunset', 'Sat, 31 Dec 2024 23:59:59 GMT');
  res.set('Link', '</api/v3/users>; rel="successor-version"');
  next();
});

// API versions discovery endpoint
app.get('/api/versions', (_req: Request, res: Response) => {
  res.json({
    currentVersion: '3.0',
    supportedVersions: [
      { version: '1.0', status: 'deprecated', sunsetDate: '2024-12-31', description: 'Legacy version with basic user info' },
      { version: '2.0', status: 'supported', description: 'Enhanced version with firstName/lastName split' },
      { version: '3.0', status: 'current', description: 'Latest version with profile information' },
    ],
    strategies: [
      'URL Path (/api/v1/users)',
      'Query Parameter (?version=1)',
      'Header (API-Version: 1)',
      'Content Negotiation (Accept: application/vnd.dmcjuniors.v1+json)',
      'Hybrid (combination of above)',
    ],
  });
});

// Error handling
app.use((err: any, _req: Request, res: Response, next: NextFunction): void => {
  if (err && err.type === 'version-error') {
    res.status(400).json({ error: 'Version Error', message: err.message, supportedVersions: ['1', '2', '3'] });
    return;
  }
  next(err);
});

// 404 handler
app.use((_req: Request, res: Response) => {
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
      'GET /api/versions',
    ],
  });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🚀 API Versioning Example Server running on port ${PORT}`);
});

export default app;

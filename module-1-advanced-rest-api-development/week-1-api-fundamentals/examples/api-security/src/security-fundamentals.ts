import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import validator from 'validator';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss';

const app = express();

// JWT Secret (use env in prod)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY ? Buffer.from(process.env.ENCRYPTION_KEY) : crypto.randomBytes(32);
const IV_LENGTH = 16;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

const corsOptions: cors.CorsOptions = {
  origin(origin, callback) {
    const allowedOrigins = ['http://localhost:3000', 'http://localhost:3001', 'https://yourdomain.com'];
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
};
app.use(cors(corsOptions));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests from this IP', retryAfter: '15 minutes' } });
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());
app.use(mongoSanitize({ replaceWith: '_' }));

const enforceHTTPS = (req: Request, res: Response, next: NextFunction) => {
  if (process.env.NODE_ENV === 'production' && req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
};
app.use(enforceHTTPS);

// Validation & sanitization
type Rule = {
  required?: boolean;
  type?: 'email' | 'string' | 'number';
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  sanitize?: Array<'trim' | 'escape' | 'xss' | 'toLowerCase'>;
  min?: number;
  max?: number;
  validate?: (value: any) => string | null;
};

type Schema = Record<string, Rule>;

const sanitizeInput = (input: string, sanitizeRules: Rule['sanitize']) => {
  let sanitized = input;
  if (!sanitizeRules) return sanitized;
  if (sanitizeRules.includes('trim')) sanitized = sanitized.trim();
  if (sanitizeRules.includes('escape')) sanitized = validator.escape(sanitized);
  if (sanitizeRules.includes('xss')) sanitized = xss(sanitized);
  if (sanitizeRules.includes('toLowerCase')) sanitized = sanitized.toLowerCase();
  return sanitized;
};

const validateInput = (schema: Schema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const errors: string[] = [];
    for (const [field, rules] of Object.entries(schema)) {
      const rawValue = (req.body as any)[field];
      const value = typeof rawValue === 'string' ? rawValue : String(rawValue ?? '');

      if (rules.required && (!value || value.trim() === '')) {
        errors.push(`${field} is required`);
        continue;
      }
      if (!value && !rules.required) continue;

      if (rules.type === 'email' && !validator.isEmail(value)) errors.push(`${field} must be a valid email`);

      if (rules.type === 'string') {
        if (rules.minLength && value.length < rules.minLength) errors.push(`${field} must be at least ${rules.minLength} characters`);
        if (rules.maxLength && value.length > rules.maxLength) errors.push(`${field} must be no more than ${rules.maxLength} characters`);
        if (rules.pattern && !rules.pattern.test(value)) errors.push(`${field} format is invalid`);
      }

      if (rules.type === 'number') {
        const numValue = Number(value);
        if (Number.isNaN(numValue)) errors.push(`${field} must be a number`);
        else {
          if (rules.min !== undefined && numValue < rules.min) errors.push(`${field} must be at least ${rules.min}`);
          if (rules.max !== undefined && numValue > rules.max) errors.push(`${field} must be no more than ${rules.max}`);
        }
      }

      if (rules.validate) {
        const customError = rules.validate(value);
        if (customError) errors.push(customError);
      }
    }

    if (errors.length > 0) {
      res.status(400).json({ success: false, error: 'Validation failed', details: errors });
      return;
    }

    for (const [field, rules] of Object.entries(schema)) {
      if ((req.body as any)[field] && rules.sanitize) {
        (req.body as any)[field] = sanitizeInput((req.body as any)[field], rules.sanitize);
      }
    }

    next();
  };
};

// Mock users
type User = { id: number; email: string; password: string; role: 'admin' | 'user'; apiKey: string; isActive: boolean; firstName?: string; lastName?: string; createdAt?: string };
const users: User[] = [
  { id: 1, email: 'admin@example.com', password: '$2b$10$6Z0xHpGUzqKfXhHFb5KzzeE.nSZ.zS1FrQZ5KzKfXhHFb5KzzeE.nS', role: 'admin', apiKey: 'ak_admin_12345', isActive: true },
  { id: 2, email: 'user@example.com', password: '$2b$10$7A1yIqHVzrLgYiIGc6Laa.fTa.aT2GsRa6Laa.7A1yIqHVzrLgYiIG', role: 'user', apiKey: 'ak_user_67890', isActive: true },
];

// Auth
type JwtPayload = { id: number; email: string; role: 'admin' | 'user' };

const authenticateToken = (req: Request & { user?: JwtPayload }, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && (authHeader as string).split(' ')[1];
  if (!token) {
    res.status(401).json({ success: false, error: 'Authentication required', message: 'Please provide a valid JWT token' });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || !user) {
      res.status(403).json({ success: false, error: 'Invalid token', message: 'Token is expired or invalid' });
      return;
    }
    (req as any).user = user as JwtPayload;
    next();
  });
};

const authenticateApiKey = (req: Request & { user?: User }, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'] as string | undefined;
  if (!apiKey) {
    res.status(401).json({ success: false, error: 'API key required', message: 'Please provide a valid API key in X-API-Key header' });
    return;
  }

  const user = users.find((u) => u.apiKey === apiKey && u.isActive);
  if (!user) {
    res.status(401).json({ success: false, error: 'Invalid API key', message: 'API key is invalid or inactive' });
    return;
  }

  (req as any).user = user;
  next();
};

const authorize = (...roles: Array<User['role']>) => {
  return (req: Request & { user?: JwtPayload }, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ success: false, error: 'Authentication required' });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ success: false, error: 'Insufficient permissions', message: `Requires one of: ${roles.join(', ')}` });
      return;
    }
    next();
  };
};

// Encrypt/Decrypt
const encrypt = (text: string) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedData: string) => {
  try {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts.shift() as string, 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    throw new Error('Failed to decrypt data');
  }
};

// Routes
app.post(
  '/api/auth/login',
  rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { error: 'Too many login attempts' } }),
  validateInput({
    email: { required: true, type: 'email', sanitize: ['trim', 'toLowerCase'] },
    password: { required: true, type: 'string', minLength: 6, sanitize: ['trim'] },
  }),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password } = req.body as any;
      const user = users.find((u) => u.email === email && u.isActive);
  if (!user) { res.status(401).json({ success: false, error: 'Invalid credentials' }); return; }
      const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) { res.status(401).json({ success: false, error: 'Invalid credentials' }); return; }
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ success: true, data: { token, user: { id: user.id, email: user.email, role: user.role } } });
    } catch {
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  }
);

app.post(
  '/api/auth/register',
  validateInput({
    email: { required: true, type: 'email', sanitize: ['trim', 'toLowerCase'] },
    password: {
      required: true,
      type: 'string',
      minLength: 8,
      validate: (value) => (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value) ? 'Password must contain at least one lowercase letter, one uppercase letter, and one number' : null),
    },
    firstName: { required: true, type: 'string', maxLength: 50, sanitize: ['trim', 'xss'] },
    lastName: { required: true, type: 'string', maxLength: 50, sanitize: ['trim', 'xss'] },
  }),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, password, firstName, lastName } = req.body as any;
  const existingUser = users.find((u) => u.email === email);
  if (existingUser) { res.status(409).json({ success: false, error: 'User already exists' }); return; }
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const apiKey = `ak_${crypto.randomBytes(16).toString('hex')}`;
      const newUser: User = {
        id: users.length + 1,
        email,
        password: hashedPassword,
        firstName: encrypt(firstName),
        lastName: encrypt(lastName),
        role: 'user',
        apiKey,
        isActive: true,
        createdAt: new Date().toISOString(),
      };
      users.push(newUser);
      res.status(201).json({ success: true, data: { id: newUser.id, email: newUser.email, apiKey: newUser.apiKey, role: newUser.role }, message: 'User registered successfully' });
    } catch {
      res.status(500).json({ success: false, error: 'Registration failed' });
    }
  }
);

app.get('/api/profile', authenticateToken as any, (req: Request & { user?: JwtPayload }, res: Response): void => {
  const user = users.find((u) => u.id === (req.user as JwtPayload).id);
  if (!user) { res.status(404).json({ success: false, error: 'User not found' }); return; }
  res.json({ success: true, data: { id: user.id, email: user.email, firstName: user.firstName ? decrypt(user.firstName) : null, lastName: user.lastName ? decrypt(user.lastName) : null, role: user.role } });
});

app.get('/api/admin/users', authenticateToken as any, authorize('admin') as any, (_req: Request, res: Response) => {
  const publicUserData = users.map((user) => ({ id: user.id, email: user.email, role: user.role, isActive: user.isActive, createdAt: user.createdAt }));
  res.json({ success: true, data: publicUserData });
});

app.get('/api/data', authenticateApiKey as any, (req: Request & { user?: User }, res: Response) => {
  res.json({ success: true, data: { message: 'Sensitive data accessible via API key', user: { id: (req.user as User).id, role: (req.user as User).role }, timestamp: new Date().toISOString() } });
});

app.post(
  '/api/comments',
  authenticateToken as any,
  validateInput({
    content: { required: true, type: 'string', maxLength: 1000, sanitize: ['trim', 'xss'] },
    title: { required: false, type: 'string', maxLength: 200, sanitize: ['trim', 'xss'] },
  }),
  (req: Request & { user?: JwtPayload }, res: Response) => {
    const { content, title } = req.body as any;
    const sanitizedContent = xss(content, { whiteList: { p: [], br: [], strong: [], em: [], u: [] } });
    res.json({ success: true, data: { id: Date.now(), title: title || null, content: sanitizedContent, author: (req.user as JwtPayload).id, createdAt: new Date().toISOString() }, message: 'Comment created successfully (content sanitized)' });
  }
);

app.get('/api/security/info', (req: Request, res: Response) => {
  res.json({
    security: {
      https: req.secure || req.headers['x-forwarded-proto'] === 'https',
      headers: { helmet: 'enabled', cors: 'configured', csp: 'enabled', hsts: 'enabled' },
      authentication: { jwt: 'supported', apiKey: 'supported', rateLimiting: 'enabled' },
      validation: { inputSanitization: 'enabled', xssProtection: 'enabled', nosqlInjectionPrevention: 'enabled' },
      encryption: { piiEncryption: 'enabled', passwordHashing: 'bcrypt', algorithm: 'AES-256-CBC' },
    },
    recommendations: ['Use HTTPS in production', 'Implement proper logging and monitoring', 'Regular security audits', 'Keep dependencies updated', 'Use environment variables for secrets'],
  });
});

app.get('/api/security/headers', (req: Request, res: Response) => {
  const securityHeaders = {
    'content-security-policy': res.get('Content-Security-Policy') ? 'present' : 'missing',
    'strict-transport-security': res.get('Strict-Transport-Security') ? 'present' : 'missing',
    'x-content-type-options': res.get('X-Content-Type-Options') ? 'present' : 'missing',
    'x-frame-options': res.get('X-Frame-Options') ? 'present' : 'missing',
    'x-xss-protection': res.get('X-XSS-Protection') ? 'present' : 'missing',
  } as const;
  res.json({ success: true, securityHeaders, requestHeaders: { userAgent: req.get('User-Agent'), origin: req.get('Origin'), referer: req.get('Referer') } });
});

// Errors
app.use((err: any, _req: Request, res: Response, next: NextFunction): void => {
  console.error('Error:', err?.message);
  if (process.env.NODE_ENV === 'production') { res.status(500).json({ success: false, error: 'Internal server error' }); return; }
  res.status(500).json({ success: false, error: err?.message, stack: err?.stack });
});

app.use((err: any, _req: Request, res: Response, next: NextFunction): void => {
  if (err?.message === 'Not allowed by CORS') {
    res.status(403).json({ success: false, error: 'CORS policy violation', message: 'Origin not allowed' });
    return;
  }
  next(err);
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: 'Endpoint not found',
    availableEndpoints: [
      'POST /api/auth/login',
      'POST /api/auth/register',
      'GET /api/profile (requires JWT)',
      'GET /api/admin/users (requires admin role)',
      'GET /api/data (requires API key)',
      'POST /api/comments (requires JWT)',
      'GET /api/security/info',
      'GET /api/security/headers',
    ],
  });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🔐 API Security Example Server running on port ${PORT}`);
});

export default app;

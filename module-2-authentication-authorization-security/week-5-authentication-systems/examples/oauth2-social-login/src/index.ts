import express from 'express';
import session from 'express-session';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import passport from './config/passport';
import authRoutes from './routes/auth';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  }
}));

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

app.use('/auth/', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: parseInt(process.env.SESSION_MAX_AGE || '86400000') // 24 hours
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// View engine setup (for demo pages)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// Make user available in all templates
app.use((req, res, next) => {
  res.locals.user = req.user;
  res.locals.isAuthenticated = req.isAuthenticated();
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    authentication: {
      google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      github: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET)
    }
  });
});

// Authentication routes
app.use('/auth', authRoutes);

// Demo pages (remove these in production)
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }
  res.render('index', { 
    title: 'OAuth2 Social Login Demo',
    error: req.query.error 
  });
});

app.get('/login', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }
  res.render('login', { 
    title: 'Login',
    error: req.query.error 
  });
});

app.get('/register', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }
  res.render('register', { 
    title: 'Register' 
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  res.render('dashboard', { 
    title: 'Dashboard',
    user: req.user 
  });
});

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  res.render('profile', { 
    title: 'Profile',
    user: req.user 
  });
});

// API Routes for testing
app.get('/api/protected', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required'
    });
  }

  res.json({
    success: true,
    message: 'This is a protected route',
    user: {
      id: (req.user as any).id,
      email: (req.user as any).email,
      name: `${(req.user as any).firstName} ${(req.user as any).lastName}`
    }
  });
});

app.get('/api/admin', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required'
    });
  }

  const user = req.user as any;
  if (user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }

  res.json({
    success: true,
    message: 'Admin route accessed successfully',
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      message: `Route ${req.originalUrl} not found`
    });
  }
  
  res.status(404).render('404', { 
    title: 'Page Not Found',
    url: req.originalUrl 
  });
});

// Global error handler
app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', error);
  
  if (req.path.startsWith('/api/')) {
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
  
  res.status(500).render('error', { 
    title: 'Server Error',
    error: process.env.NODE_ENV === 'development' ? error : null
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 OAuth2 Social Login Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n🔐 Authentication providers:`);
  
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    console.log(`   ✅ Google OAuth configured`);
  } else {
    console.log(`   ❌ Google OAuth not configured`);
  }
  
  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    console.log(`   ✅ GitHub OAuth configured`);
  } else {
    console.log(`   ❌ GitHub OAuth not configured`);
  }
  
  console.log(`\n📋 Demo pages:`);
  console.log(`   GET  /                    - Landing page`);
  console.log(`   GET  /login              - Login page`);
  console.log(`   GET  /register           - Registration page`);
  console.log(`   GET  /dashboard          - User dashboard`);
  console.log(`   GET  /profile            - User profile`);
  
  console.log(`\n📋 API endpoints:`);
  console.log(`   POST /auth/register      - Register with email/password`);
  console.log(`   POST /auth/login         - Login with email/password`);
  console.log(`   GET  /auth/google        - Initiate Google OAuth`);
  console.log(`   GET  /auth/github        - Initiate GitHub OAuth`);
  console.log(`   POST /auth/logout        - Logout`);
  console.log(`   GET  /auth/me            - Get current user`);
  console.log(`   PUT  /auth/profile       - Update profile`);
  console.log(`   GET  /api/protected      - Protected API route`);
  console.log(`   GET  /api/admin          - Admin-only API route`);
  
  console.log(`\n🔗 Default admin account:`);
  console.log(`   Email: admin@example.com`);
  console.log(`   Password: Admin123!`);
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

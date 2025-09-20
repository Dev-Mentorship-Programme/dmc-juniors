import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { body, validationResult } from 'express-validator';
import { userStore } from '../models/UserStore';

const router = express.Router();

// Middleware to ensure user is authenticated
export const ensureAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    return next();
  }
  
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required'
    });
  }
  
  res.redirect('/login');
};

// Middleware to ensure user is not authenticated (for login/register pages)
export const ensureGuest = (req: Request, res: Response, next: NextFunction) => {
  if (!req.isAuthenticated()) {
    return next();
  }
  
  if (req.path.startsWith('/api/')) {
    return res.status(400).json({
      success: false,
      message: 'Already authenticated'
    });
  }
  
  res.redirect('/dashboard');
};

/**
 * @route   POST /auth/register
 * @desc    Register a new user with email/password
 * @access  Public
 */
router.post('/register', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain uppercase, lowercase, number and special character'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters')
], async (req: Request, res: Response) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, firstName, lastName } = req.body;

    // Create user
    const user = await userStore.createLocalUser({
      email,
      password,
      firstName,
      lastName
    });

    // Log the user in automatically
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Registration successful but login failed'
        });
      }

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        user: userStore.sanitizeUser(user)
      });
    });

  } catch (error: any) {
    if (error.message === 'User with this email already exists') {
      return res.status(409).json({
        success: false,
        message: error.message
      });
    }

    res.status(500).json({
      success: false,
      message: 'Registration failed'
    });
  }
});

/**
 * @route   POST /auth/login
 * @desc    Login with email/password
 * @access  Public
 */
router.post('/login', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password required')
], (req: Request, res: Response, next: NextFunction) => {
  // Check validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  passport.authenticate('local', (err: any, user: any, info: any) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Authentication error'
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: info?.message || 'Invalid credentials'
      });
    }

    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Login failed'
        });
      }

      res.json({
        success: true,
        message: 'Login successful',
        user: userStore.sanitizeUser(user)
      });
    });
  })(req, res, next);
});

/**
 * @route   GET /auth/google
 * @desc    Initiate Google OAuth
 * @access  Public
 */
router.get('/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}));

/**
 * @route   GET /auth/google/callback
 * @desc    Google OAuth callback
 * @access  Public
 */
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?error=google_auth_failed' }),
  (req: Request, res: Response) => {
    // Successful authentication
    if (req.path.includes('/api/')) {
      return res.json({
        success: true,
        message: 'Google authentication successful',
        user: userStore.sanitizeUser(req.user as any)
      });
    }
    
    res.redirect('/dashboard');
  }
);

/**
 * @route   GET /auth/github
 * @desc    Initiate GitHub OAuth
 * @access  Public
 */
router.get('/github', passport.authenticate('github', {
  scope: ['user:email']
}));

/**
 * @route   GET /auth/github/callback
 * @desc    GitHub OAuth callback
 * @access  Public
 */
router.get('/github/callback',
  passport.authenticate('github', { failureRedirect: '/login?error=github_auth_failed' }),
  (req: Request, res: Response) => {
    // Successful authentication
    if (req.path.includes('/api/')) {
      return res.json({
        success: true,
        message: 'GitHub authentication successful',
        user: userStore.sanitizeUser(req.user as any)
      });
    }
    
    res.redirect('/dashboard');
  }
);

/**
 * @route   POST /auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', (req: Request, res: Response) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }

    res.json({
      success: true,
      message: 'Logout successful'
    });
  });
});

/**
 * @route   GET /auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', ensureAuthenticated, (req: Request, res: Response) => {
  res.json({
    success: true,
    user: userStore.sanitizeUser(req.user as any)
  });
});

/**
 * @route   PUT /auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', [
  ensureAuthenticated,
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be less than 50 characters'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be less than 50 characters')
], async (req: Request, res: Response) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const user = req.user as any;
    const { firstName, lastName } = req.body;

    const updatedUser = await userStore.updateUser(user.id, {
      firstName: firstName || user.firstName,
      lastName: lastName || user.lastName
    });

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: userStore.sanitizeUser(updatedUser)
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Profile update failed'
    });
  }
});

/**
 * @route   POST /auth/link/google
 * @desc    Link Google account to existing user
 * @access  Private
 */
router.get('/link/google', ensureAuthenticated, passport.authenticate('google', {
  scope: ['profile', 'email']
}));

/**
 * @route   POST /auth/link/github
 * @desc    Link GitHub account to existing user
 * @access  Private
 */
router.get('/link/github', ensureAuthenticated, passport.authenticate('github', {
  scope: ['user:email']
}));

/**
 * @route   POST /auth/unlink/:provider
 * @desc    Unlink social account
 * @access  Private
 */
router.post('/unlink/:provider', ensureAuthenticated, async (req: Request, res: Response) => {
  try {
    const { provider } = req.params;
    const user = req.user as any;

    if (!['google', 'github'].includes(provider)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid provider'
      });
    }

    // Check if user has at least one authentication method remaining
    const hasLocal = !!user.providers.local;
    const hasGoogle = !!user.providers.google;
    const hasGitHub = !!user.providers.github;
    
    const authMethods = [hasLocal, hasGoogle, hasGitHub].filter(Boolean).length;
    
    if (authMethods <= 1) {
      return res.status(400).json({
        success: false,
        message: 'Cannot unlink the only authentication method'
      });
    }

    // Remove the provider
    const updatedProviders = { ...user.providers };
    delete updatedProviders[provider as keyof typeof updatedProviders];

    const updatedUser = await userStore.updateUser(user.id, {
      providers: updatedProviders
    });

    res.json({
      success: true,
      message: `${provider} account unlinked successfully`,
      user: userStore.sanitizeUser(updatedUser!)
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to unlink account'
    });
  }
});

export default router;

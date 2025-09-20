import express, { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';
import { userStore } from '../models/UserStore';
import { JWTService } from '../utils/jwt';
import { authenticate } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters and contain uppercase, lowercase, number and special character'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters')
], async (req: Request, res: Response, next: NextFunction) => {
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

    // Check if user already exists
    const existingUser = await userStore.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Create new user
    const user = await userStore.createUser({
      email,
      password,
      firstName,
      lastName
    });

    // Generate tokens
    const { accessToken, refreshToken } = JWTService.generateTokenPair({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    // Add refresh token to user's refresh tokens array
    await userStore.addRefreshToken(user.id, refreshToken);

    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: userStore.sanitizeUser(user),
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || '15m'
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], async (req: Request, res: Response, next: NextFunction) => {
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

    const { email, password } = req.body;

    // Find user
    const user = await userStore.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if account is locked
    if (userStore.isLocked(user)) {
      return res.status(423).json({
        success: false,
        message: 'Account temporarily locked due to too many failed login attempts'
      });
    }

    // Verify password
    const isValidPassword = await userStore.comparePassword(user, password);
    if (!isValidPassword) {
      // Increment login attempts
      await userStore.incrementLoginAttempts(user.id);
      
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await userStore.resetLoginAttempts(user.id);
    }

    // Update last login
    await userStore.updateUser(user.id, { lastLogin: new Date() });

    // Generate tokens
    const { accessToken, refreshToken } = JWTService.generateTokenPair({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    // Add refresh token to user's refresh tokens array
    await userStore.addRefreshToken(user.id, refreshToken);

    logger.info(`User logged in: ${email}`);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          lastLogin: user.lastLogin
        },
        tokens: {
          accessToken,
          refreshToken,
          expiresIn: process.env.JWT_EXPIRES_IN || '15m'
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh', [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
], async (req: Request, res: Response, next: NextFunction) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { refreshToken } = req.body;

    // Verify refresh token
    const decoded = JWTService.verifyRefreshToken(refreshToken);

    // Find user and check if refresh token exists
    const user = await userStore.findById(decoded.userId);
    if (!user || !user.refreshTokens.includes(refreshToken)) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new access token
    const newAccessToken = JWTService.generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: newAccessToken,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m'
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (invalidate refresh token)
 * @access  Private
 */
router.post('/logout', authenticate, [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
], async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    const user = req.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not authenticated'
      });
    }

    // Remove refresh token from user's tokens array
    await userStore.removeRefreshToken(user.id, refreshToken);

    logger.info(`User logged out: ${user.email}`);

    res.json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   POST /api/auth/logout-all
 * @desc    Logout from all devices (invalidate all refresh tokens)
 * @access  Private
 */
router.post('/logout-all', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not authenticated'
      });
    }

    // Clear all refresh tokens
    await userStore.clearAllRefreshTokens(user.id);

    logger.info(`User logged out from all devices: ${user.email}`);

    res.json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not authenticated'
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

export default router;

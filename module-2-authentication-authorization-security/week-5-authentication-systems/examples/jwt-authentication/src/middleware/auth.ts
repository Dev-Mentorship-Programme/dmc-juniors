import { Request, Response, NextFunction } from 'express';
import { JWTService, TokenPayload } from '../utils/jwt';
import { userStore, IUser } from '../models/UserStore';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: IUser;
      token?: TokenPayload;
    }
  }
}

/**
 * Middleware to authenticate JWT tokens
 */
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = JWTService.extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    // Verify token
    const decoded = JWTService.verifyAccessToken(token);

    // Check if user still exists
    const user = await userStore.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists'
      });
    }

    // Check if user account is locked
    if (userStore.isLocked(user)) {
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked due to failed login attempts'
      });
    }

    // Attach user and token info to request
    req.user = user;
    req.token = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

/**
 * Middleware to authorize based on user roles
 */
export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

/**
 * Middleware to check if user owns the resource or is admin
 */
export const authorizeOwnerOrAdmin = (userIdParam: string = 'userId') => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const resourceUserId = req.params[userIdParam];
    const currentUserId = req.user.id;
    const isAdmin = req.user.role === 'admin';

    if (currentUserId === resourceUserId || isAdmin) {
      next();
    } else {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only access your own resources.'
      });
    }
  };
};

/**
 * Optional authentication middleware - doesn't fail if no token
 */
export const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    const token = JWTService.extractTokenFromHeader(authHeader);

    if (token) {
      const decoded = JWTService.verifyAccessToken(token);
      const user = await userStore.findById(decoded.userId);
      
      if (user && !userStore.isLocked(user)) {
        req.user = user;
        req.token = decoded;
      }
    }

    next();
  } catch (error) {
    // Ignore authentication errors in optional auth
    next();
  }
};

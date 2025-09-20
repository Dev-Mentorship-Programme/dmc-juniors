import express, { Request, Response, NextFunction } from 'express';
import { authenticate, authorize, authorizeOwnerOrAdmin } from '../middleware/auth';
import { userStore } from '../models/UserStore';

const router = express.Router();

/**
 * @route   GET /api/users
 * @desc    Get all users (admin only)
 * @access  Private/Admin
 */
router.get('/', authenticate, authorize('admin'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;

    const { users, total } = await userStore.getAllUsers(skip, limit);

    // Sanitize users data
    const sanitizedUsers = users.map(user => userStore.sanitizeUser(user));

    res.json({
      success: true,
      data: {
        users: sanitizedUsers,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   GET /api/users/:userId
 * @desc    Get user by ID
 * @access  Private (own profile or admin)
 */
router.get('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params;

    const user = await userStore.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: { user: userStore.sanitizeUser(user) }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   PUT /api/users/:userId
 * @desc    Update user profile
 * @access  Private (own profile or admin)
 */
router.put('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params;
    const { firstName, lastName } = req.body;

    // Only allow updating specific fields
    const updateData: any = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;

    const user = await userStore.updateUser(userId, updateData);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: userStore.sanitizeUser(user) }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   DELETE /api/users/:userId
 * @desc    Delete user account
 * @access  Private (own account or admin)
 */
router.delete('/:userId', authenticate, authorizeOwnerOrAdmin('userId'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params;

    const deleted = await userStore.deleteUser(userId);
    if (!deleted) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   PUT /api/users/:userId/role
 * @desc    Update user role (admin only)
 * @access  Private/Admin
 */
router.put('/:userId/role', authenticate, authorize('admin'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    if (!['user', 'admin', 'moderator'].includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role. Must be user, admin, or moderator'
      });
    }

    const user = await userStore.updateUser(userId, { role });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User role updated successfully',
      data: { user: userStore.sanitizeUser(user) }
    });

  } catch (error) {
    next(error);
  }
});

export default router;

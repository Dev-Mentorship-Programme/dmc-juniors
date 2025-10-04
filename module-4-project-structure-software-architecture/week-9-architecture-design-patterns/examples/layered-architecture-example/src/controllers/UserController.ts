// Presentation Layer - Handles HTTP requests and responses
import { Request, Response } from 'express';
import { IUserService } from '../services/UserService';
import { User } from '../models/User';

// Extend Express Request type to include user
export interface AuthenticatedRequest extends Request {
  user: User;
}

export class UserController {
  constructor(private readonly userService: IUserService) {}

  async createUser(req: Request, res: Response): Promise<void> {
    try {
      const userData = {
        name: req.body.name,
        email: req.body.email,
        role: req.body.role,
      };

      const user = await this.userService.createUser(userData);

      res.status(201).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(400).json({
        success: false,
        error: errorMessage,
      });
    }
  }

  async getUser(req: Request, res: Response): Promise<void> {
    try {
      const userId = req.params.id;
      const user = await this.userService.getUserById(userId);

      res.status(200).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(404).json({
        success: false,
        error: errorMessage,
      });
    }
  }

  async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const filters: Record<string, any> = {};
      if (req.query.role) {
        filters.role = req.query.role;
      }

      const users = await this.userService.getAllUsers(filters);

      res.status(200).json({
        success: true,
        data: users.map((user) => user.toJSON()),
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({
        success: false,
        error: errorMessage,
      });
    }
  }

  async updateUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.params.id;
      const updateData = {
        name: req.body.name,
        email: req.body.email,
        role: req.body.role,
      };

      const requestingUser = req.user;
      const user = await this.userService.updateUser(userId, updateData, requestingUser);

      res.status(200).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const statusCode = errorMessage.includes('Unauthorized') ? 403 : 400;
      res.status(statusCode).json({
        success: false,
        error: errorMessage,
      });
    }
  }

  async deleteUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.params.id;
      const requestingUser = req.user;

      await this.userService.deleteUser(userId, requestingUser);

      res.status(200).json({
        success: true,
        message: 'User deleted successfully',
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const statusCode = errorMessage.includes('Unauthorized') ? 403 : 400;
      res.status(statusCode).json({
        success: false,
        error: errorMessage,
      });
    }
  }
}

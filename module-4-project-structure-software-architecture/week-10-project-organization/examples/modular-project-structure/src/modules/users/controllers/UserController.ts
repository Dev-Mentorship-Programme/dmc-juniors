import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/UserService';
import { CreateUserDto, UpdateUserDto } from '../dto/UserDto';

export class UserController {
  constructor(private readonly userService: UserService) {}

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const dto: CreateUserDto = req.body;
      const user = await this.userService.createUser(dto);

      res.status(201).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      next(error);
    }
  }

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const user = await this.userService.getUserById(id);

      res.status(200).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      next(error);
    }
  }

  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const users = await this.userService.getAllUsers();

      res.status(200).json({
        success: true,
        data: users.map((u) => u.toJSON()),
      });
    } catch (error) {
      next(error);
    }
  }

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      const dto: UpdateUserDto = req.body;
      const user = await this.userService.updateUser(id, dto);

      res.status(200).json({
        success: true,
        data: user.toJSON(),
      });
    } catch (error) {
      next(error);
    }
  }

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { id } = req.params;
      await this.userService.deleteUser(id);

      res.status(200).json({
        success: true,
        message: 'User deleted successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}

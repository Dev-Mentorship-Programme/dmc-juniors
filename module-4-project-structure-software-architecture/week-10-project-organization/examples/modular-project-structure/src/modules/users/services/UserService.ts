import { User } from '../entities/User';
import { CreateUserDto, UpdateUserDto } from '../dto/UserDto';
import { NotFoundError, ValidationError } from '../../../core/errors/AppError';

export class UserService {
  private users: Map<string, User> = new Map();

  async createUser(dto: CreateUserDto): Promise<User> {
    // Validation
    if (!this.isValidEmail(dto.email)) {
      throw new ValidationError('Invalid email format');
    }

    if (dto.name.length < 2) {
      throw new ValidationError('Name must be at least 2 characters');
    }

    // Check if user exists
    const existingUser = Array.from(this.users.values()).find(
      (u) => u.email === dto.email
    );
    if (existingUser) {
      throw new ValidationError('Email already in use');
    }

    const user = new User(
      this.generateId(),
      dto.email,
      dto.name,
      dto.role || 'user',
      new Date()
    );

    this.users.set(user.id, user);
    return user;
  }

  async getUserById(id: string): Promise<User> {
    const user = this.users.get(id);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    return user;
  }

  async getAllUsers(): Promise<User[]> {
    return Array.from(this.users.values());
  }

  async updateUser(id: string, dto: UpdateUserDto): Promise<User> {
    const existingUser = await this.getUserById(id);

    const updatedUser = new User(
      existingUser.id,
      existingUser.email,
      dto.name || existingUser.name,
      dto.role || existingUser.role,
      existingUser.createdAt
    );

    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async deleteUser(id: string): Promise<void> {
    const user = await this.getUserById(id);
    this.users.delete(user.id);
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private generateId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

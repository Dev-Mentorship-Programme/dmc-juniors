// Business Logic Layer - Contains business rules and orchestration
import { User } from '../models/User';
import { IUserRepository, CreateUserData } from '../repositories/UserRepository';

export interface IUserService {
  createUser(userData: CreateUserData): Promise<User>;
  getUserById(id: string): Promise<User>;
  getAllUsers(filters?: Record<string, any>): Promise<User[]>;
  updateUser(id: string, updateData: Partial<CreateUserData>, requestingUser: User): Promise<User>;
  deleteUser(id: string, requestingUser: User): Promise<boolean>;
}

export class UserService implements IUserService {
  constructor(private readonly userRepository: IUserRepository) {}

  async createUser(userData: CreateUserData): Promise<User> {
    // Business rule: Check if user already exists
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Business rule: Validate email format
    if (!this.isValidEmail(userData.email)) {
      throw new Error('Invalid email format');
    }

    // Business rule: Validate name length
    if (userData.name.length < 2) {
      throw new Error('Name must be at least 2 characters long');
    }

    return await this.userRepository.create(userData);
  }

  async getUserById(id: string): Promise<User> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  async getAllUsers(filters: Record<string, any> = {}): Promise<User[]> {
    return await this.userRepository.findAll(filters);
  }

  async updateUser(
    id: string,
    updateData: Partial<CreateUserData>,
    requestingUser: User
  ): Promise<User> {
    const user = await this.getUserById(id);

    // Business rule: Authorization check
    if (!requestingUser.canModifyUser(id)) {
      throw new Error('Unauthorized to modify this user');
    }

    // Business rule: Prevent email change if already in use
    if (updateData.email && updateData.email !== user.email) {
      const existingUser = await this.userRepository.findByEmail(updateData.email);
      if (existingUser) {
        throw new Error('Email already in use');
      }
    }

    const updatedUser = await this.userRepository.update(id, updateData);
    if (!updatedUser) {
      throw new Error('Failed to update user');
    }

    return updatedUser;
  }

  async deleteUser(id: string, requestingUser: User): Promise<boolean> {
    // Verify user exists (will throw if not found)
    await this.getUserById(id);

    // Business rule: Authorization check
    if (!requestingUser.canModifyUser(id)) {
      throw new Error('Unauthorized to delete this user');
    }

    return await this.userRepository.delete(id);
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}

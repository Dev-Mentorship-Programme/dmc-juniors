// Data Access Layer - Handles all database operations
import { User, UserRole } from '../models/User';
import { IDatabase } from '../database/InMemoryDatabase';

export interface CreateUserData {
  name: string;
  email: string;
  role?: UserRole;
}

export interface IUserRepository {
  create(userData: CreateUserData): Promise<User>;
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findAll(filters?: Record<string, any>): Promise<User[]>;
  update(id: string, updateData: Partial<CreateUserData>): Promise<User | null>;
  delete(id: string): Promise<boolean>;
}

export class UserRepository implements IUserRepository {
  constructor(private readonly db: IDatabase) {}

  async create(userData: CreateUserData): Promise<User> {
    const user = new User(
      this.generateId(),
      userData.name,
      userData.email,
      userData.role || 'user',
      new Date()
    );

    await this.db.save('users', user.toJSON());
    return user;
  }

  async findById(id: string): Promise<User | null> {
    const userData = await this.db.findOne<any>('users', { id });
    if (!userData) return null;

    return new User(
      userData.id,
      userData.name,
      userData.email,
      userData.role,
      new Date(userData.createdAt)
    );
  }

  async findByEmail(email: string): Promise<User | null> {
    const userData = await this.db.findOne<any>('users', { email });
    if (!userData) return null;

    return new User(
      userData.id,
      userData.name,
      userData.email,
      userData.role,
      new Date(userData.createdAt)
    );
  }

  async findAll(filters: Record<string, any> = {}): Promise<User[]> {
    const usersData = await this.db.find<any>('users', filters);
    return usersData.map(
      (userData) =>
        new User(
          userData.id,
          userData.name,
          userData.email,
          userData.role,
          new Date(userData.createdAt)
        )
    );
  }

  async update(id: string, updateData: Partial<CreateUserData>): Promise<User | null> {
    const user = await this.findById(id);
    if (!user) return null;

    const updatedUser = new User(
      user.id,
      updateData.name || user.name,
      updateData.email || user.email,
      updateData.role || user.role,
      user.createdAt
    );

    await this.db.update('users', { id }, updatedUser.toJSON());
    return updatedUser;
  }

  async delete(id: string): Promise<boolean> {
    return await this.db.delete('users', { id });
  }

  private generateId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

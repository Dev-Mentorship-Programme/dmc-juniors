import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

export interface IUser {
  id: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: 'user' | 'admin' | 'moderator';
  isEmailVerified: boolean;
  emailVerificationToken?: string;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  lastLogin?: Date;
  loginAttempts: number;
  lockUntil?: Date;
  refreshTokens: string[];
  createdAt: Date;
  updatedAt: Date;
}

export class UserStore {
  private users: Map<string, IUser> = new Map();
  private emailIndex: Map<string, string> = new Map(); // email -> userId mapping

  constructor() {
    // Create a default admin user for testing
    this.createUser({
      email: 'admin@example.com',
      password: 'Admin123!',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin'
    });
  }

  async createUser(userData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    role?: 'user' | 'admin' | 'moderator';
  }): Promise<IUser> {
    // Check if user already exists
    if (this.emailIndex.has(userData.email.toLowerCase())) {
      throw new Error('User with this email already exists');
    }

    // Hash password
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS || '12'));
    const hashedPassword = await bcrypt.hash(userData.password, salt);

    const user: IUser = {
      id: uuidv4(),
      email: userData.email.toLowerCase(),
      password: hashedPassword,
      firstName: userData.firstName,
      lastName: userData.lastName,
      role: userData.role || 'user',
      isEmailVerified: false,
      loginAttempts: 0,
      refreshTokens: [],
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.users.set(user.id, user);
    this.emailIndex.set(user.email, user.id);

    return user;
  }

  async findById(id: string): Promise<IUser | null> {
    const user = this.users.get(id);
    return user || null;
  }

  async findByEmail(email: string): Promise<IUser | null> {
    const userId = this.emailIndex.get(email.toLowerCase());
    if (!userId) return null;
    return this.findById(userId);
  }

  async updateUser(id: string, updates: Partial<IUser>): Promise<IUser | null> {
    const user = this.users.get(id);
    if (!user) return null;

    const updatedUser = {
      ...user,
      ...updates,
      id: user.id, // Prevent ID changes
      email: user.email, // Prevent email changes (would need special handling)
      updatedAt: new Date()
    };

    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async deleteUser(id: string): Promise<boolean> {
    const user = this.users.get(id);
    if (!user) return false;

    this.users.delete(id);
    this.emailIndex.delete(user.email);
    return true;
  }

  async comparePassword(user: IUser, candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, user.password);
  }

  async incrementLoginAttempts(id: string): Promise<void> {
    const user = this.users.get(id);
    if (!user) return;

    // If we have a previous lock that has expired, restart at 1
    if (user.lockUntil && user.lockUntil < new Date()) {
      await this.updateUser(id, {
        loginAttempts: 1,
        lockUntil: undefined
      });
      return;
    }

    const newAttempts = user.loginAttempts + 1;
    const updates: Partial<IUser> = { loginAttempts: newAttempts };

    // Lock account after 5 failed attempts for 2 hours
    if (newAttempts >= 5 && !this.isLocked(user)) {
      updates.lockUntil = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours
    }

    await this.updateUser(id, updates);
  }

  async resetLoginAttempts(id: string): Promise<void> {
    await this.updateUser(id, {
      loginAttempts: 0,
      lockUntil: undefined
    });
  }

  isLocked(user: IUser): boolean {
    return !!(user.lockUntil && user.lockUntil > new Date());
  }

  async addRefreshToken(id: string, refreshToken: string): Promise<void> {
    const user = this.users.get(id);
    if (!user) return;

    const updatedTokens = [...user.refreshTokens, refreshToken];
    await this.updateUser(id, { refreshTokens: updatedTokens });
  }

  async removeRefreshToken(id: string, refreshToken: string): Promise<void> {
    const user = this.users.get(id);
    if (!user) return;

    const updatedTokens = user.refreshTokens.filter(token => token !== refreshToken);
    await this.updateUser(id, { refreshTokens: updatedTokens });
  }

  async clearAllRefreshTokens(id: string): Promise<void> {
    await this.updateUser(id, { refreshTokens: [] });
  }

  async getAllUsers(skip = 0, limit = 10): Promise<{ users: IUser[]; total: number }> {
    const allUsers = Array.from(this.users.values());
    const total = allUsers.length;
    const users = allUsers
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(skip, skip + limit);

    return { users, total };
  }

  // Utility method to get sanitized user (without password and sensitive data)
  sanitizeUser(user: IUser): Omit<IUser, 'password' | 'refreshTokens' | 'emailVerificationToken' | 'passwordResetToken' | 'loginAttempts' | 'lockUntil'> {
    const { password, refreshTokens, emailVerificationToken, passwordResetToken, loginAttempts, lockUntil, ...sanitized } = user;
    return sanitized;
  }
}

// Create a singleton instance
export const userStore = new UserStore();

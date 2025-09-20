import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

export interface IUser {
  id: string;
  email: string;
  password?: string; // Optional for OAuth users
  firstName: string;
  lastName: string;
  role: 'user' | 'admin' | 'moderator';
  profilePicture?: string;
  isEmailVerified: boolean;
  
  // OAuth provider data
  providers: {
    local?: {
      password: string;
      emailVerificationToken?: string;
      passwordResetToken?: string;
      passwordResetExpires?: Date;
    };
    google?: {
      id: string;
      accessToken?: string;
      refreshToken?: string;
    };
    github?: {
      id: string;
      username: string;
      accessToken?: string;
    };
  };
  
  lastLogin?: Date;
  loginAttempts: number;
  lockUntil?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export class UserStore {
  private users: Map<string, IUser> = new Map();
  private emailIndex: Map<string, string> = new Map(); // email -> userId mapping
  private googleIdIndex: Map<string, string> = new Map(); // googleId -> userId
  private githubIdIndex: Map<string, string> = new Map(); // githubId -> userId

  constructor() {
    // Create a default admin user for testing
    this.createLocalUser({
      email: 'admin@example.com',
      password: 'Admin123!',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin'
    });
  }

  async createLocalUser(userData: {
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
      firstName: userData.firstName,
      lastName: userData.lastName,
      role: userData.role || 'user',
      isEmailVerified: false,
      providers: {
        local: {
          password: hashedPassword
        }
      },
      loginAttempts: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.users.set(user.id, user);
    this.emailIndex.set(user.email, user.id);

    return user;
  }

  async createOrUpdateGoogleUser(profile: any): Promise<IUser> {
    const googleId = profile.id;
    const email = profile.emails?.[0]?.value?.toLowerCase();
    
    if (!email) {
      throw new Error('Google profile must have an email');
    }

    // Check if user exists by Google ID
    let userId = this.googleIdIndex.get(googleId);
    
    if (userId) {
      // Update existing Google user
      const user = this.users.get(userId)!;
      const updatedUser = {
        ...user,
        firstName: profile.name?.givenName || user.firstName,
        lastName: profile.name?.familyName || user.lastName,
        profilePicture: profile.photos?.[0]?.value || user.profilePicture,
        lastLogin: new Date(),
        updatedAt: new Date(),
        providers: {
          ...user.providers,
          google: {
            id: googleId,
            accessToken: profile.accessToken,
            refreshToken: profile.refreshToken
          }
        }
      };
      
      this.users.set(userId, updatedUser);
      return updatedUser;
    }

    // Check if user exists by email (link accounts)
    userId = this.emailIndex.get(email);
    
    if (userId) {
      // Link Google account to existing user
      const user = this.users.get(userId)!;
      const updatedUser = {
        ...user,
        profilePicture: profile.photos?.[0]?.value || user.profilePicture,
        lastLogin: new Date(),
        updatedAt: new Date(),
        providers: {
          ...user.providers,
          google: {
            id: googleId,
            accessToken: profile.accessToken,
            refreshToken: profile.refreshToken
          }
        }
      };
      
      this.users.set(userId, updatedUser);
      this.googleIdIndex.set(googleId, userId);
      return updatedUser;
    }

    // Create new user
    const newUser: IUser = {
      id: uuidv4(),
      email,
      firstName: profile.name?.givenName || 'Unknown',
      lastName: profile.name?.familyName || 'User',
      role: 'user',
      profilePicture: profile.photos?.[0]?.value,
      isEmailVerified: true, // Google accounts are pre-verified
      providers: {
        google: {
          id: googleId,
          accessToken: profile.accessToken,
          refreshToken: profile.refreshToken
        }
      },
      loginAttempts: 0,
      lastLogin: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.users.set(newUser.id, newUser);
    this.emailIndex.set(newUser.email, newUser.id);
    this.googleIdIndex.set(googleId, newUser.id);

    return newUser;
  }

  async createOrUpdateGitHubUser(profile: any): Promise<IUser> {
    const githubId = profile.id.toString();
    const email = profile.emails?.[0]?.value?.toLowerCase();
    
    if (!email) {
      throw new Error('GitHub profile must have an email');
    }

    // Check if user exists by GitHub ID
    let userId = this.githubIdIndex.get(githubId);
    
    if (userId) {
      // Update existing GitHub user
      const user = this.users.get(userId)!;
      const updatedUser = {
        ...user,
        firstName: profile.displayName?.split(' ')[0] || user.firstName,
        lastName: profile.displayName?.split(' ').slice(1).join(' ') || user.lastName,
        profilePicture: profile.photos?.[0]?.value || user.profilePicture,
        lastLogin: new Date(),
        updatedAt: new Date(),
        providers: {
          ...user.providers,
          github: {
            id: githubId,
            username: profile.username,
            accessToken: profile.accessToken
          }
        }
      };
      
      this.users.set(userId, updatedUser);
      return updatedUser;
    }

    // Check if user exists by email (link accounts)
    userId = this.emailIndex.get(email);
    
    if (userId) {
      // Link GitHub account to existing user
      const user = this.users.get(userId)!;
      const updatedUser = {
        ...user,
        profilePicture: profile.photos?.[0]?.value || user.profilePicture,
        lastLogin: new Date(),
        updatedAt: new Date(),
        providers: {
          ...user.providers,
          github: {
            id: githubId,
            username: profile.username,
            accessToken: profile.accessToken
          }
        }
      };
      
      this.users.set(userId, updatedUser);
      this.githubIdIndex.set(githubId, userId);
      return updatedUser;
    }

    // Create new user
    const displayNameParts = profile.displayName?.split(' ') || [];
    const newUser: IUser = {
      id: uuidv4(),
      email,
      firstName: displayNameParts[0] || profile.username || 'Unknown',
      lastName: displayNameParts.slice(1).join(' ') || 'User',
      role: 'user',
      profilePicture: profile.photos?.[0]?.value,
      isEmailVerified: true, // GitHub accounts are pre-verified
      providers: {
        github: {
          id: githubId,
          username: profile.username,
          accessToken: profile.accessToken
        }
      },
      loginAttempts: 0,
      lastLogin: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.users.set(newUser.id, newUser);
    this.emailIndex.set(newUser.email, newUser.id);
    this.githubIdIndex.set(githubId, newUser.id);

    return newUser;
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

  async findByGoogleId(googleId: string): Promise<IUser | null> {
    const userId = this.googleIdIndex.get(googleId);
    if (!userId) return null;
    return this.findById(userId);
  }

  async findByGitHubId(githubId: string): Promise<IUser | null> {
    const userId = this.githubIdIndex.get(githubId);
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
    
    if (user.providers.google) {
      this.googleIdIndex.delete(user.providers.google.id);
    }
    
    if (user.providers.github) {
      this.githubIdIndex.delete(user.providers.github.id);
    }
    
    return true;
  }

  async comparePassword(user: IUser, candidatePassword: string): Promise<boolean> {
    if (!user.providers.local?.password) {
      return false; // No local password set
    }
    return bcrypt.compare(candidatePassword, user.providers.local.password);
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

  async getAllUsers(skip = 0, limit = 10): Promise<{ users: IUser[]; total: number }> {
    const allUsers = Array.from(this.users.values());
    const total = allUsers.length;
    const users = allUsers
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(skip, skip + limit);

    return { users, total };
  }

  // Utility method to get sanitized user (without sensitive data)
  sanitizeUser(user: IUser): Omit<IUser, 'providers'> & { 
    providers: { 
      local?: boolean; 
      google?: boolean; 
      github?: boolean; 
    } 
  } {
    const { providers, ...sanitized } = user;
    return {
      ...sanitized,
      providers: {
        local: !!providers.local,
        google: !!providers.google,
        github: !!providers.github
      }
    };
  }
}

// Create a singleton instance
export const userStore = new UserStore();

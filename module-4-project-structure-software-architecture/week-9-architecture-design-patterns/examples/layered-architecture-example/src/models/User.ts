// Domain Model - Pure business entity
export type UserRole = 'user' | 'admin' | 'moderator';

export interface UserData {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  createdAt: Date;
}

export class User {
  constructor(
    public readonly id: string,
    public readonly name: string,
    public readonly email: string,
    public readonly role: UserRole,
    public readonly createdAt: Date
  ) {}

  // Business logic methods
  isAdmin(): boolean {
    return this.role === 'admin';
  }

  canModifyUser(targetUserId: string): boolean {
    return this.isAdmin() || this.id === targetUserId;
  }

  toJSON(): UserData {
    return {
      id: this.id,
      name: this.name,
      email: this.email,
      role: this.role,
      createdAt: this.createdAt,
    };
  }
}

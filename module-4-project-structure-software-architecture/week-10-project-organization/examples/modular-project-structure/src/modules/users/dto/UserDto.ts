// Data Transfer Object for creating users
export interface CreateUserDto {
  email: string;
  name: string;
  role?: 'user' | 'admin';
}

export interface UpdateUserDto {
  name?: string;
  role?: 'user' | 'admin';
}

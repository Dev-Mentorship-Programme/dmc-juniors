import express, { Request, Response, NextFunction } from 'express';
import { InMemoryDatabase } from './database/InMemoryDatabase';
import { UserRepository } from './repositories/UserRepository';
import { UserService } from './services/UserService';
import { UserController, AuthenticatedRequest } from './controllers/UserController';
import { createUserRoutes } from './routes/userRoutes';
import { User } from './models/User';

// Initialize application
const app = express();
app.use(express.json());

// Dependency injection - Build the layers from bottom to top
const database = new InMemoryDatabase();
const userRepository = new UserRepository(database);
const userService = new UserService(userRepository);
const userController = new UserController(userService);

// Mock authentication middleware (for demonstration)
app.use((req: Request, _res: Response, next: NextFunction) => {
  // In a real app, this would extract user from JWT token
  const authReq = req as AuthenticatedRequest;
  authReq.user = new User('admin_1', 'Admin User', 'admin@example.com', 'admin', new Date());
  next();
});

// Register routes
const userRoutes = createUserRoutes(userController);
app.use('/api', userRoutes);

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

// Error handling middleware
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`API base URL: http://localhost:${PORT}/api`);
});

export default app;

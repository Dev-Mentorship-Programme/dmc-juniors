import express, { Application } from 'express';
import { config } from './shared/config';
import { logger } from './core/logger';
import { errorHandler } from './shared/middleware/errorHandler';
import { requestLogger } from './shared/middleware/requestLogger';

// Import modules
import { UserService, UserController, createUserRoutes } from './modules/users';

class App {
  public app: Application;

  constructor() {
    this.app = express();
    this.initializeMiddlewares();
    this.initializeModules();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(requestLogger);
  }

  private initializeModules(): void {
    // Users module setup
    const userService = new UserService();
    const userController = new UserController(userService);
    const userRoutes = createUserRoutes(userController);

    // Register module routes
    this.app.use('/api/users', userRoutes);

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date(),
        environment: config.nodeEnv,
      });
    });
  }

  private initializeErrorHandling(): void {
    this.app.use(errorHandler);
  }

  public listen(): void {
    this.app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`);
      logger.info(`Environment: ${config.nodeEnv}`);
      logger.info(`Health check: http://localhost:${config.port}/health`);
    });
  }
}

// Bootstrap the application
const application = new App();
application.listen();

export default application.app;

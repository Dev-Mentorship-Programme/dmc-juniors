import { Router, Request, Response } from 'express';
import { UserController, AuthenticatedRequest } from '../controllers/UserController';

export function createUserRoutes(userController: UserController): Router {
  const router = Router();

  // Bind controller methods to maintain 'this' context
  router.post('/users', (req: Request, res: Response) => userController.createUser(req, res));
  router.get('/users', (req: Request, res: Response) => userController.getAllUsers(req, res));
  router.get('/users/:id', (req: Request, res: Response) => userController.getUser(req, res));
  router.put('/users/:id', (req: Request, res: Response) =>
    userController.updateUser(req as AuthenticatedRequest, res)
  );
  router.delete('/users/:id', (req: Request, res: Response) =>
    userController.deleteUser(req as AuthenticatedRequest, res)
  );

  return router;
}

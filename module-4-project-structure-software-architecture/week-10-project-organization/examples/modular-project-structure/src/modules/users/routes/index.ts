import { Router } from 'express';
import { UserController } from '../controllers/UserController';

export function createUserRoutes(userController: UserController): Router {
  const router = Router();

  router.post('/', (req, res, next) => userController.create(req, res, next));
  router.get('/', (req, res, next) => userController.getAll(req, res, next));
  router.get('/:id', (req, res, next) => userController.getById(req, res, next));
  router.put('/:id', (req, res, next) => userController.update(req, res, next));
  router.delete('/:id', (req, res, next) => userController.delete(req, res, next));

  return router;
}

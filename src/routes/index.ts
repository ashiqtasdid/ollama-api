import { Express } from 'express';
import { getHome } from '../controllers/homeController';
import { generate } from '../controllers/ollamaController';
import { createApiKey, createToken } from '../controllers/authController';

export const setRoutes = (app: Express) => {
  app.get('/', getHome);
  app.post('/generate', generate);
  
  // Authentication routes
  app.post('/keys', createApiKey);
  app.post('/tokens', createToken);
};
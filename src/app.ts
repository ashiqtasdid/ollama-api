import express from 'express';
import { setRoutes } from './routes';

const app = express();

// Add middleware to parse JSON bodies
app.use(express.json());

setRoutes(app);

export default app;
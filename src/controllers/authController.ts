import { Request, Response } from 'express';
import { generateApiKey, generateToken } from '../services/ollamaService';

export const createApiKey = (req: Request, res: Response) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const apiKey = generateApiKey(userId);
    return res.status(201).json({ apiKey });
  } catch (error) {
    console.error('Error creating API key:', error);
    return res.status(500).json({ error: 'Failed to create API key' });
  }
};

export const createToken = (req: Request, res: Response) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const token = generateToken(userId);
    return res.status(201).json({ token });
  } catch (error) {
    console.error('Error creating token:', error);
    return res.status(500).json({ error: 'Failed to create token' });
  }
};
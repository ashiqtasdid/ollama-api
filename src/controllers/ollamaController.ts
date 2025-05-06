import { Request, Response } from 'express';
import { generateCompletion, ApiError, ErrorType } from '../services/ollamaService';

export const generate = async (req: Request, res: Response) => {
  try {
    const { prompt } = req.body;
    
    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }
    
    // Extract authorization header from request
    const authorization = req.headers.authorization;
    
    if (!authorization) {
      return res.status(401).json({ 
        error: 'Authorization header is required',
        type: 'AUTHENTICATION_ERROR'
      });
    }
    
    // Pass both prompt and options to generateCompletion
    const response = await generateCompletion(prompt, {
      authorization,
      safetySettings: req.body.safetySettings
    });
    
    return res.json({ response });
  } catch (error: unknown) {
    console.error('Error generating completion:', error);
    
    // Type guard to check if error is an ApiError
    if (error instanceof ApiError) {
      return res.status(error.statusCode).json({
        error: error.message,
        type: error.type
      });
    }
    
    // For other errors, return a generic error message
    return res.status(500).json({ 
      error: 'Failed to generate completion',
      type: 'SERVICE_ERROR'
    });
  }
};
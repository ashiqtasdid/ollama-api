import axios, { AxiosError } from 'axios';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import 'dotenv/config'
// Configuration
const OLLAMA_API_URL = process.env.OLLAMA_API_URL || 'http://localhost:11434/api/generate';
const API_KEY_SECRET = process.env.API_KEY_SECRET || 'your-secret-key-change-me';
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key-change-me';
const TOKEN_EXPIRY = '24h';
const MAX_PROMPT_LENGTH = 4000; // Maximum allowed prompt length
const MAX_REQUESTS_PER_MINUTE = 20;

// Request tracking for rate limiting
const requestTracker = new Map<string, { count: number, resetTime: number }>();

// Error types
enum ErrorType {
  AUTHENTICATION = 'AUTHENTICATION_ERROR',
  RATE_LIMIT = 'RATE_LIMIT_ERROR',
  VALIDATION = 'VALIDATION_ERROR',
  SERVICE = 'SERVICE_ERROR',
  CONTENT_FILTER = 'CONTENT_FILTER_ERROR',
}

class ApiError extends Error {
  type: ErrorType;
  statusCode: number;

  constructor(type: ErrorType, message: string, statusCode: number) {
    super(message);
    this.type = type;
    this.statusCode = statusCode;
    this.name = 'ApiError';
  }
}

interface OllamaRequest {
  model: string;
  prompt: string;
  stream?: boolean;
  options?: {
    temperature?: number;
    top_p?: number;
    top_k?: number;
    max_tokens?: number;
  };
}

interface OllamaResponse {
  model: string;
  response: string;
  done: boolean;
}

interface RequestOptions {
  apiKey?: string; // Make this optional
  authorization?: string; // Add this for Bearer token
  userId?: string;
  model?: string; // Add model parameter
  safetySettings?: {
    harassmentThreshold?: 'BLOCK_MEDIUM_AND_ABOVE' | 'BLOCK_ONLY_HIGH' | 'BLOCK_NONE';
    hateSpeechThreshold?: 'BLOCK_MEDIUM_AND_ABOVE' | 'BLOCK_ONLY_HIGH' | 'BLOCK_NONE';
    sexuallyExplicitThreshold?: 'BLOCK_MEDIUM_AND_ABOVE' | 'BLOCK_ONLY_HIGH' | 'BLOCK_NONE';
    dangerousContentThreshold?: 'BLOCK_MEDIUM_AND_ABOVE' | 'BLOCK_ONLY_HIGH' | 'BLOCK_NONE';
  };
}

// Clean the response by removing thinking patterns
const cleanResponse = (response: string): string => {
  // Remove the entire thinking section with tags
  let cleaned = response.replace(/<think>[\s\S]*?<\/think>/g, '');

  // Also try alternate format that might be used
  cleaned = cleaned.replace(/<thinking>[\s\S]*?<\/thinking>/g, '');

  // Remove prompt formatting/tags if present
  cleaned = cleaned.replace(/<prompt>|<\/prompt>/g, '');

  // Remove any XML-like tags that might remain
  cleaned = cleaned.replace(/<[^>]*>/g, '');

  // Remove lines that start with common thinking indicators
  cleaned = cleaned.replace(/^(Let me think|I'm thinking|Thinking:|Wait,|Hmm,|Okay, so).*$/gm, '');

  // Remove any potential instruction text that might be self-dialogue
  cleaned = cleaned.replace(/^(I need to|I'll|I will|Let me|I should|First,|Let's|Now,|Also,|Finally,).*$/gm, '');

  // Clean up extra whitespace and normalize line breaks
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n'); // Replace 3+ consecutive newlines with just 2
  cleaned = cleaned.trim();

  return cleaned;
};

// Validate API key
const validateApiKey = (apiKey: string): boolean => {
  // In a real implementation, you would check against stored API keys
  // This is a simplified example using HMAC verification
  const [id, key] = apiKey.split('.');

  if (!id || !key) return false;

  const expectedHmac = crypto
    .createHmac('sha256', API_KEY_SECRET)
    .update(id)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(key),
    Buffer.from(expectedHmac.substring(0, key.length))
  );
};

// Validate bearer token
const validateBearerToken = (token: string): { userId: string } => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
    return decoded;
  } catch (error) {
    throw new ApiError(
      ErrorType.AUTHENTICATION,
      'Invalid or expired token',
      401
    );
  }
};

// Check rate limits
const checkRateLimit = (userId: string): void => {
  const now = Date.now();
  const minuteMs = 60 * 1000;

  if (!requestTracker.has(userId)) {
    requestTracker.set(userId, { count: 1, resetTime: now + minuteMs });
    return;
  }

  const userTracker = requestTracker.get(userId)!;

  if (now > userTracker.resetTime) {
    // Reset counter if the minute has passed
    userTracker.count = 1;
    userTracker.resetTime = now + minuteMs;
    return;
  }

  if (userTracker.count >= MAX_REQUESTS_PER_MINUTE) {
    const resetTimeSeconds = Math.ceil((userTracker.resetTime - now) / 1000);
    throw new ApiError(
      ErrorType.RATE_LIMIT,
      `Rate limit exceeded. Try again in ${resetTimeSeconds} seconds.`,
      429
    );
  }

  userTracker.count++;
};

// Simple content filter check
const checkContentSafety = (text: string, safetySettings?: RequestOptions['safetySettings']): void => {
  if (!safetySettings) return;

  // This is a simplified example - in production you would use a proper content filtering API
  const sensitivePatterns = [
    /\b(hack|exploit|illegal|bomb|weapon|porn|terrorist)\b/i
  ];

  if (safetySettings.dangerousContentThreshold !== 'BLOCK_NONE' &&
    sensitivePatterns.some(pattern => pattern.test(text))) {
    throw new ApiError(
      ErrorType.CONTENT_FILTER,
      'Your request was blocked due to content safety policy violations.',
      400
    );
  }
};

// Generate API key for a user
export const generateApiKey = (userId: string): string => {
  const id = userId;
  const hmac = crypto
    .createHmac('sha256', API_KEY_SECRET)
    .update(id)
    .digest('hex');

  return `${id}.${hmac.substring(0, 16)}`;
};

// Generate a JWT token
export const generateToken = (userId: string): string => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
};

// Main text generation function
export const generateCompletion = async (
  prompt: string,
  options: RequestOptions
): Promise<string> => {
  try {
    let userId = 'anonymous';
    // Default model to use if none specified
    const model = options.model || 'deepseek-r1:7b';

    // Handle authentication - either API key or Bearer token
    if (options.authorization) {
      // Bearer token authentication
      const authParts = options.authorization.split(' ');
      if (authParts.length !== 2 || authParts[0] !== 'Bearer') {
        throw new ApiError(
          ErrorType.AUTHENTICATION,
          'Invalid authorization format. Use: Bearer <token>',
          401
        );
      }

      const userData = validateBearerToken(authParts[1]);
      userId = userData.userId;
    }
    else if (options.apiKey) {
      // API key authentication
      if (!validateApiKey(options.apiKey)) {
        throw new ApiError(
          ErrorType.AUTHENTICATION,
          'Invalid API key. Please provide a valid API key.',
          401
        );
      }
      userId = options.userId || 'anonymous';
    }
    else {
      // No authentication provided
      throw new ApiError(
        ErrorType.AUTHENTICATION,
        'Authentication required. Provide either API key or Bearer token.',
        401
      );
    }

    // Check rate limits
    checkRateLimit(userId);

    // Validate input
    if (!prompt || typeof prompt !== 'string') {
      throw new ApiError(
        ErrorType.VALIDATION,
        'Prompt is required and must be a string.',
        400
      );
    }

    if (prompt.length > MAX_PROMPT_LENGTH) {
      throw new ApiError(
        ErrorType.VALIDATION,
        `Prompt exceeds maximum length of ${MAX_PROMPT_LENGTH} characters.`,
        400
      );
    }

    // Check content safety
    checkContentSafety(prompt, options.safetySettings);

    // Add explicit instruction to not include thinking process
    const enhancedPrompt = `${prompt}\n\nProvide your response directly without showing your thinking process, notes, or planning.`;

    // Log request (in production, use proper logging)
    console.log(`[${new Date().toISOString()}] Request from user ${userId} using model ${model}`);

    const request: OllamaRequest = {
      model: model,
      prompt: enhancedPrompt,
      stream: false,
      options: {
        temperature: 0.7,
        max_tokens: 1000
      }
    };

    const response = await axios.post<OllamaResponse>(OLLAMA_API_URL, request, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Check content safety on response too
    checkContentSafety(response.data.response, options.safetySettings);

    // Clean the response before returning it
    return cleanResponse(response.data.response);
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;

      if (axiosError.code === 'ECONNREFUSED') {
        throw new ApiError(
          ErrorType.SERVICE,
          'Connection to Ollama refused. Make sure Ollama is running.',
          503
        );
      }

      throw new ApiError(
        ErrorType.SERVICE,
        `API request failed: ${axiosError.message}`,
        500
      );
    }

    throw new ApiError(
      ErrorType.SERVICE,
      'An unexpected error occurred',
      500
    );
  }
};
export { ApiError, ErrorType };
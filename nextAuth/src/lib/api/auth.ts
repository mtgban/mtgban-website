// src/lib/api/authApi.ts
import { User } from '../../context/AuthContext';

// Type Definitions
export interface LoginRequest {
  email: string;
  password: string;
  remember?: boolean;
}

export interface SignupRequest {
  email: string;
  password: string;
  confirmPassword: string;
  fullName: string;
}

export interface AuthResponse {
  success: boolean;
  user?: User;
  error?: string;
  emailConfirmationRequired?: boolean;
}

// Default API endpoints - can be configured via environment variables
const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';
const AUTH_API = `${API_BASE}/next-api/auth`;

// Helper function for handling response errors
async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    // For 401/403 errors on auth endpoints, return a clean error
    if ((response.status === 401 || response.status === 403) && 
        response.url.includes('/auth/')) {
      throw new Error("Authentication required");
    }
    
    // Try to parse error message from response
    try {
      const errorData = await response.json();
      throw new Error(errorData.error || response.statusText);
    } catch (e) {
      // If JSON parsing fails, use status text
      throw new Error(`Request failed: ${response.status} ${response.statusText}`);
    }
  }
  
  // Return JSON data or empty object if no content
  if (response.status === 204) {
    return {} as T;
  }
  
  return await response.json() as T;
}

// Authentication API
export const authApi = {
  // Login with email and password
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    try {
      const response = await fetch(`${AUTH_API}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
        credentials: 'same-origin',
      });
      
      return await handleResponse<AuthResponse>(response);
    } catch (error) {
      console.error('Login API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Login failed',
      };
    }
  },
  
  // Sign up new user
  async signup(data: SignupRequest): Promise<AuthResponse> {
    try {
      const userData = {
        email: data.email,
        password: data.password,
        userData: {
          full_name: data.fullName,
          tier: 'free',
        },
      };
      
      const response = await fetch(`${AUTH_API}/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData),
        credentials: 'same-origin',
      });
      
      return await handleResponse<AuthResponse>(response);
    } catch (error) {
      console.error('Signup API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Signup failed',
      };
    }
  },
  
  // Logout current user
  async logout(): Promise<void> {
    try {
      await fetch(`${AUTH_API}/logout`, {
        method: 'POST',
        credentials: 'same-origin',
      });
    } catch (error) {
      console.error('Logout API error:', error);
      throw error;
    }
  },
  
  // Get current user
  async getUser(): Promise<User | null> {
    try {
      const response = await fetch(`${AUTH_API}/me`, {
        credentials: 'same-origin',
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          // Not authenticated - return null without throwing
          return null;
        }
        throw new Error(`Failed to fetch user: ${response.status}`);
      }
      
      const data = await response.json();
      return data.user || null;
    } catch (error) {
      console.error('Get user API error:', error);
      return null;
    }
  },
  
  // Request password reset
  async forgotPassword(email: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${AUTH_API}/forgot-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
      
      return await handleResponse<AuthResponse>(response);
    } catch (error) {
      console.error('Forgot password API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to request password reset',
      };
    }
  },
  
  // Reset password with token
  async resetPassword(password: string, token: string): Promise<AuthResponse> {
    try {
      const response = await fetch(`${AUTH_API}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password, token }),
        credentials: 'same-origin',
      });
      
      return await handleResponse<AuthResponse>(response);
    } catch (error) {
      console.error('Reset password API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to reset password',
      };
    }
  },
  
  // Refresh authentication token
  async refreshToken(): Promise<boolean> {
    try {
      const response = await fetch(`${AUTH_API}/refresh-token`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      
      return response.ok;
    } catch (error) {
      console.error('Token refresh API error:', error);
      return false;
    }
  },
};
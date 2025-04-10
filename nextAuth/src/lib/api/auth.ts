// lib/api/auth.ts
import { UserCredentials, SignupData, User } from './types';

// Define response types
interface AuthResponse {
  success: boolean;
  message?: string;
  error?: string;
  data?: any;
  user?: User;
  session?: {
    expires_at: number;
    csrf_token: string;
  };
  redirectTo?: string;
  emailConfirmationRequired?: boolean;
}

/**
 * Authentication API service
 */
export const authApi = {
  /**
   * Login with email and password
   */
  async login(credentials: UserCredentials): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials),
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error,
        user: data.data?.user,
        session: {
          expires_at: data.data?.expires_at || 0,
          csrf_token: data.data?.csrf_token || ''
        },
        redirectTo: data.data?.redirectTo
      };
    } catch (error) {
      console.error('Login API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Sign up a new user
   */
  async signup(data: SignupData): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: data.email,
          password: data.password,
          userData: {
            full_name: data.fullName,
            tier: 'free'
          }
        }),
        credentials: 'same-origin'
      });
      
      const responseData = await response.json();
      
      return {
        success: responseData.success,
        message: responseData.message,
        error: responseData.error,
        user: responseData.data?.user,
        emailConfirmationRequired: responseData.data?.emailConfirmationRequired,
        session: responseData.data?.session,
        redirectTo: responseData.data?.redirectTo
      };
    } catch (error) {
      console.error('Signup API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Logout user
   */
  async logout(): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error,
        redirectTo: data.data?.redirectTo
      };
    } catch (error) {
      console.error('Logout API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Get current user
   */
  async getUser(): Promise<User | null> {
    try {
      const response = await fetch('/next-api/auth/me', {
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      if (!data.success || !data.data?.user) {
        return null;
      }
      
      return data.data.user;
    } catch (error) {
      console.error('Get user API error:', error);
      return null;
    }
  },

  /**
   * Refresh authentication token
   */
  async refreshToken(): Promise<boolean> {
    try {
      const response = await fetch('/next-api/auth/refresh-token', {
        method: 'POST',
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return data.success === true;
    } catch (error) {
      console.error('Refresh token API error:', error);
      return false;
    }
  },

  /**
   * Request password reset
   */
  async forgotPassword(email: string): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email }),
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Forgot password API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Reset password with token
   */
  async resetPassword(password: string, token: string): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password, token }),
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error,
        redirectTo: data.data?.redirectTo
      };
    } catch (error) {
      console.error('Reset password API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Update user's email
   */
  async updateEmail(newEmail: string): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/update-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ newEmail }),
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Update email API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  },

  /**
   * Update user's name
   */
  async updateName(fullName: string): Promise<AuthResponse> {
    try {
      const response = await fetch('/next-api/auth/update-name', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ fullName }),
        credentials: 'same-origin'
      });
      
      const data = await response.json();
      
      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Update name API error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'An unexpected error occurred'
      };
    }
  }
};
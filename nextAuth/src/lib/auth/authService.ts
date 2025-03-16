import { 
  UserCredentials,
  SignupData,
  User
} from '../api/types';

import { createFetchInterceptor } from './interceptor';

// Get the API base URL from environment variable or default
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || '/next-api';
const AUTH_API_PATH = process.env.NEXT_PUBLIC_AUTH_API_PATH || '/next-api/auth';

/**
 * Core authentication service
 * This version uses environment variables to configure API paths
 * and works in both development and production
 */
export class AuthService {
  private user: User | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshing = false;
  private listeners: ((user: User | null) => void)[] = [];
  private tokenExpiryKey = 'token_expires_at';
  
  /**
   * Initialize auth state
   * @param initialUser - User data if available
   */
  public init(initialUser: User | null): void {
    this.user = initialUser;
    
    if (initialUser) {
      this.setupTokenRefresh();
    }
    
    this.notifyListeners();
  }
  
  /**
   * Get API URL based on current environment
   */
  private getApiUrl(endpoint: string): string {
    // Remove leading slash if present for consistent joining
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint.substring(1) : endpoint;
    return `${AUTH_API_PATH}/${cleanEndpoint}`;
  }
  
  /**
   * Login with email and password
   */
  public async login(credentials: UserCredentials): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      // In development: calls local Next.js API routes
      // In production: calls Go backend API directly
      const response = await fetch(this.getApiUrl('login'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials),
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Login failed');
      }
      
      const data = await response.json();
      
      // Store expiry time
      if (data.session?.expires_at) {
        try {
          localStorage.setItem(this.tokenExpiryKey, String(data.session.expires_at * 1000));
        } catch (e) {
          console.warn('Local storage not available for token expiry');
        }
      }
      
      this.user = data.user;
      this.notifyListeners();
      
      // Setup token refresh
      this.setupTokenRefresh();
      
      return {
        success: true,
        user: data.user
      };
    } catch (error) {
      console.error('Login error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Login failed'
      };
    }
  }

  /**
   * Sign up a new user
   */
  public async signup(data: SignupData): Promise<{ 
    success: boolean; 
    user?: User; 
    error?: string;
    emailConfirmationRequired?: boolean;
  }> {
    try {
      if (data.password !== data.confirmPassword) {
        return {
          success: false,
          error: 'Passwords do not match'
        };
      }

      const userData = {
        full_name: data.fullName,
        tier: 'free'
      };

      const response = await fetch(this.getApiUrl('signup'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: data.email,
          password: data.password,
          userData
        }),
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Signup failed');
      }
      
      const responseData = await response.json();
      
      // If email confirmation is required
      if (responseData.emailConfirmationRequired) {
        return {
          success: true,
          emailConfirmationRequired: true,
          user: responseData.user
        };
      }
      
      // Store expiry time
      if (responseData.session?.expires_at) {
        try {
          localStorage.setItem(this.tokenExpiryKey, String(responseData.session.expires_at * 1000));
        } catch (e) {
          console.warn('Local storage not available for token expiry');
        }
      }
      
      this.user = responseData.user;
      this.notifyListeners();
      
      // Setup token refresh
      this.setupTokenRefresh();
      
      return {
        success: true,
        user: responseData.user
      };
    } catch (error) {
      console.error('Signup error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Signup failed'
      };
    }
  }
  
  /**
   * Logout the current user
   */
  public async logout(): Promise<void> {
    try {
      await fetch(this.getApiUrl('logout'), {
        method: 'POST',
        credentials: 'same-origin'
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
    
    // Clear local state regardless of server response
    this.user = null;
    
    // Clear refresh timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    
    // Clear stored expiry time
    try {
      localStorage.removeItem(this.tokenExpiryKey);
    } catch (e) {
      // Local storage might not be available
    }
    
    this.notifyListeners();
  }
  
  /**
   * Get current user information
   */
  public async fetchUser(): Promise<User | null> {
    try {
      const response = await fetch(this.getApiUrl('me'), {
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error('Failed to fetch user');
      }
      
      const data = await response.json();
      this.user = data.user;
      this.notifyListeners();
      
      return this.user;
    } catch (error) {
      console.error('Error fetching user:', error);
      this.user = null;
      this.notifyListeners();
      return null;
    }
  }
  
  /**
   * Refresh the authentication tokens
   */
  public async refreshSession(): Promise<boolean> {
    if (this.refreshing) return false;
    
    this.refreshing = true;
    
    try {
      const response = await fetch(this.getApiUrl('refresh-token'), {
        method: 'POST',
        credentials: 'same-origin'
      });
      
      if (!response.ok) {
        throw new Error('Failed to refresh token');
      }
      
      const data = await response.json();
      
      // Store new expiry time
      if (data.expires_at) {
        try {
          localStorage.setItem(this.tokenExpiryKey, String(data.expires_at * 1000));
        } catch (e) {
          // Local storage might not be available
        }
      }
      
      // Get updated user data
      await this.fetchUser();
      
      // Setup next refresh
      this.setupTokenRefresh();
      
      this.refreshing = false;
      return true;
    } catch (error) {
      console.error('Session refresh failed:', error);
      
      // If refresh failed, log user out
      this.user = null;
      this.notifyListeners();
      
      this.refreshing = false;
      return false;
    }
  }
  
  /**
   * Request a password reset
   */
  public async forgotPassword(email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const response = await fetch(this.getApiUrl('forgot-password'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });
      
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to process request');
      }
      
      return { success: true };
    } catch (error) {
      console.error('Forgot password error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to request password reset'
      };
    }
  }
  
  /**
   * Get current user
   */
  public getUser(): User | null {
    return this.user;
  }
  
  /**
   * Check if user is authenticated
   */
  public isAuthenticated(): boolean {
    return !!this.user;
  }
  
  /**
   * Subscribe to auth state changes
   */
  public subscribe(listener: (user: User | null) => void): () => void {
    this.listeners.push(listener);
    
    // Return unsubscribe function
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }
  
  /**
   * Set up automatic token refresh
   */
  private setupTokenRefresh(): void {
    // Clear any existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    
    // Refresh token 5 minutes before expiry
    const refreshBuffer = 5 * 60 * 1000; // 5 minutes
    
    // Get token expiry from local storage if available
    let expiresAt = 0;
    try {
      const expiryData = localStorage.getItem(this.tokenExpiryKey);
      if (expiryData) {
        expiresAt = parseInt(expiryData, 10);
      }
    } catch (e) {
      // Local storage might not be available
    }
    
    if (!expiresAt || isNaN(expiresAt)) {
      // If no expiry found, refresh every hour
      this.refreshTimer = setTimeout(() => this.refreshSession(), 60 * 60 * 1000);
      return;
    }
    
    const now = Date.now();
    const timeUntilRefresh = Math.max(0, expiresAt - now - refreshBuffer);
    
    // Set timer to refresh just before expiration
    this.refreshTimer = setTimeout(() => this.refreshSession(), timeUntilRefresh);
  }
  
  /**
   * Notify all listeners of auth state change
   */
  private notifyListeners(): void {
    this.listeners.forEach(listener => listener(this.user));
  }
  
  /**
   * Create fetch interceptor for automatic token refresh
   */
  public createFetchInterceptor(): () => void {
    return createFetchInterceptor();
  }
}

// Create singleton instance
export const authService = new AuthService();

// Install fetch interceptor when in browser
if (typeof window !== 'undefined') {
  authService.createFetchInterceptor();
}
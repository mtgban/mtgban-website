// providers/AuthProvider.tsx
import React, { createContext, useContext, useState, ReactNode, useEffect } from 'react';
import { authApi } from '@/lib/api/auth';
import { User } from '@/lib/api/types';

// Auth context type definition
interface AuthContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  loading: boolean;
  error: string | null;
  csrfToken: string | null;
  login: (email: string, password: string, remember?: boolean) => Promise<boolean>;
  signup: (email: string, password: string, fullName: string) => Promise<boolean>;
  logout: () => Promise<void>;
  forgotPassword: (email: string) => Promise<boolean>;
  resetPassword: (password: string, token: string) => Promise<boolean>;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

// Create context with undefined default
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Helper to consistently check if on an auth page
const isAuthPage = () => {
  if (typeof window === 'undefined') return false;
  
  const path = window.location.pathname;
  return path.includes('/auth/login')
      || path.includes('/auth/signup')
      || path.includes('/auth/reset-password')
      || path.includes('/auth/forgot-password')
      || path.includes('/auth/confirmation')
      || path.includes('/auth/account');
};

// Check for pre-loaded data from the server
const getInitialData = () => {
  if (typeof window !== 'undefined' && window.__INITIAL_DATA__) {
    return {
      user: window.__INITIAL_DATA__.user || null,
      csrfToken: window.__INITIAL_DATA__.csrf_token || null
    };
  }
  return { user: null, csrfToken: null };
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // Get initial data if available
  const initialData = getInitialData();
  
  const [user, setUser] = useState<User | null>(initialData.user);
  const [csrfToken, setCsrfToken] = useState<string | null>(initialData.csrfToken);
  const [loading, setLoading] = useState<boolean>(!initialData.user);
  const [error, setError] = useState<string | null>(null);
  const [initialized, setInitialized] = useState<boolean>(!!initialData.user);

  // Check for existing session on mount
  useEffect(() => {
    if (initialized) return; // Only run once
    
    // Skip auth check on auth pages to prevent redirect loops
    if (isAuthPage()) {
      setLoading(false);
      setInitialized(true);
      return;
    }

    const checkSession = async () => {
      try {
        // Check for auth token cookie
        const hasToken = document.cookie.includes('auth_token=');
        
        if (hasToken) {
          // Try to get user from API
          const apiUser = await authApi.getUser();
          
          if (apiUser) {
            setUser(apiUser);
          } else {
            // Clear any stored user data
            localStorage.removeItem('user');
          }
        } else {
          // Try to refresh token 
          const refreshed = await authApi.refreshToken();
          if (refreshed) {
            // Re-fetch user after refresh
            const apiUser = await authApi.getUser();
            if (apiUser) {
              setUser(apiUser);
            }
          }
        }
      } catch (err) {
        console.error('Session check error:', err);
      } finally {
        setLoading(false);
        setInitialized(true);
      }
    };
    
    checkSession();
  }, [initialized]);

  // Set up scheduled token refresh
  useEffect(() => {
    if (!user) return;

    const refreshInterval = setInterval(async () => {
      try {
        await authApi.refreshToken();
        await refreshUser(); // Update user data after refresh
      } catch (err) {
        console.error('Token refresh error:', err);
      }
    }, 20 * 60 * 1000); // 20 minutes
    
    return () => clearInterval(refreshInterval);
  }, [user]);

  // Clear any error messages
  const clearError = () => {
    setError(null);
  };

  // Refresh user data
  const refreshUser = async () => {
    try {
      setLoading(true);
      const updatedUser = await authApi.getUser();
      if (updatedUser) {
        setUser(updatedUser);
      }
    } catch (err) {
      console.error('User refresh error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Login function
  const login = async (email: string, password: string, remember = false): Promise<boolean> => {
    try {
      setLoading(true);
      clearError();
      
      const response = await authApi.login({ email, password, remember });
      
      if (!response.success) {
        throw new Error(response.error || 'Login failed');
      }
      
      if (response.user) {
        setUser(response.user);
        
        // Store CSRF token if available
        if (response.session?.csrf_token) {
          setCsrfToken(response.session.csrf_token);
        }
        
        // Save to localStorage for persistence
        localStorage.setItem('user', JSON.stringify(response.user));
        
        // Redirect if needed
        if (response.redirectTo) {
          window.location.href = response.redirectTo;
        }
      }
      
      return true;
    } catch (err) {
      console.error('Login error:', err);
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Signup function
  const signup = async (email: string, password: string, fullName: string): Promise<boolean> => {
    try {
      setLoading(true);
      clearError();
      
      const response = await authApi.signup({
        email,
        password,
        confirmPassword: password,
        fullName
      });
      
      if (!response.success) {
        throw new Error(response.error || 'Signup failed');
      }
      
      if (response.emailConfirmationRequired) {
        // If email confirmation is required, return success but don't set user
        return true;
      }

      if (response.user) {
        setUser(response.user);
        
        // Store CSRF token if available
        if (response.session?.csrf_token) {
          setCsrfToken(response.session.csrf_token);
        }
        
        localStorage.setItem('user', JSON.stringify(response.user));
        
        // Redirect if needed
        if (response.redirectTo) {
          window.location.href = response.redirectTo;
        }
      }
      
      return true;
    } catch (err) {
      console.error('Signup error:', err);
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Logout function
  const logout = async (): Promise<void> => {
    try {
      setLoading(true);
      
      const response = await authApi.logout();
      
      // Clear user from state and local storage
      setUser(null);
      setCsrfToken(null);
      localStorage.removeItem('user');
      
      // Redirect if needed
      if (response.redirectTo) {
        window.location.href = response.redirectTo;
      }
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Forgot password function
  const forgotPassword = async (email: string): Promise<boolean> => {
    try {
      setLoading(true);
      clearError();
      
      const response = await authApi.forgotPassword(email);
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to request password reset');
      }
      
      return true;
    } catch (err) {
      console.error('Forgot password error:', err);
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Reset password function
  const resetPassword = async (password: string, token: string): Promise<boolean> => {
    try {
      setLoading(true);
      clearError();
      
      const response = await authApi.resetPassword(password, token);
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to reset password');
      }
      
      // Redirect if needed
      if (response.redirectTo) {
        window.location.href = response.redirectTo;
      }
      
      return true;
    } catch (err) {
      console.error('Reset password error:', err);
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const contextValue: AuthContextType = {
    user,
    setUser,
    loading,
    error,
    csrfToken,
    login,
    signup,
    logout,
    forgotPassword,
    resetPassword,
    refreshUser,
    clearError
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
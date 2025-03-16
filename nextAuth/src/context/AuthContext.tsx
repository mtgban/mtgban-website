import React, { createContext, useContext, useState, ReactNode, useEffect, FC } from 'react';
import { authApi } from '@/lib/api/auth';

export interface User {
  id: string;
  email: string;
  tier?: string;
  user_metadata?: Record<string, any>;
}

interface AuthContextType {
  user: User | null;
  setUser: (user: User) => void;
  loading: boolean;
  error: string | null;
  login: (email: string, password: string, remember?: boolean) => Promise<boolean>;
  signup: (email: string, password: string, fullName: string) => Promise<boolean>;
  logout: () => Promise<void>;
  forgotPassword: (email: string) => Promise<boolean>;
  resetPassword: (password: string, token: string) => Promise<boolean>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);


export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Check for existing session on mount
  useEffect(() => {
    const isAuthPage = window.location.pathname.includes('/auth/login') || 
    window.location.pathname.includes('/auth/signup');

    if (isAuthPage) {
      setLoading(false);
      return; // Don't check auth status on auth pages unless you want infinite loop lol
    }

    const checkSession = async () => {
      try {
        // Only try to get user if we have a stored token
        const hasToken = document.cookie.includes('auth_token=') || localStorage.getItem('user');
        
        if (hasToken) {
          // Try to get user from API
          const apiUser = await authApi.getUser();
          if (apiUser) {
            setUser(apiUser);
          } else {
            // Fallback to localStorage if API fails or returns null
            const storedUser = localStorage.getItem('user');
            if (storedUser) {
              try {
                const parsedUser = JSON.parse(storedUser);
                setUser(parsedUser);
                
                // Validate stored user with API
                authApi.refreshToken().catch(() => {
                  // Clear invalid session silently
                  setUser(null);
                  localStorage.removeItem('user');
                });
              } catch (parseError) {
                // Clear invalid data
                localStorage.removeItem('user');
              }
            }
          }
        }
      } catch (err) {
        console.error('Session check error:', err);
      } finally {
        setLoading(false);
      }
    };    
    checkSession();
  }, []);

  // Clear any error messages
  const clearError = () => {
    setError(null);
  };

  // Login function
  const login = async (email: string, password: string, remember: boolean = false): Promise<boolean> => {
    try {
      setLoading(true);
      clearError();
      
      const response = await authApi.login({ email, password, remember });
      
      if (!response.success || !response.user) {
        throw new Error(response.error || 'Login failed');
      }
      
      setUser(response.user);
      
      if (remember) {
        localStorage.setItem('user', JSON.stringify(response.user));
      }
      
      return true;
    } catch (err) {
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
        // Handle email confirmation if needed
        return true;
      }
      
      if (response.user) {
        setUser(response.user);
        localStorage.setItem('user', JSON.stringify(response.user));
      }
      
      return true;
    } catch (err) {
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
      
      // Call logout API
      await authApi.logout();
      
      // Clear user from state and storage
      setUser(null);
      localStorage.removeItem('user');
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
      
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const value: AuthContextType = {
    user,
    setUser,
    loading,
    error,
    login,
    signup,
    logout,
    forgotPassword,
    resetPassword,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
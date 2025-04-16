  import React, { createContext, useContext, useState, ReactNode, useEffect } from 'react';
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

  // Helper to consistently check if on an auth page
  const isAuthPage = () => {
    if (typeof window === 'undefined') return false;
    
    const path = window.location.pathname;
    return path.includes('/auth/login')
        || path.includes('/auth/signup')
        || path.includes('/auth/reset-password')
        || path.includes('/auth/forgot-password')
        || path.includes('/auth/confirmation')
        || path.includes('/auth/account')
  }

  export const AuthProvider = ({ children }: AuthProviderProps) => {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const [initialized, setInitialized] = useState<boolean>(false);

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
            console.log('Auth token found, fetching user data');
            // Try to get user from API
            const apiUser = await authApi.getUser();
            
            if (apiUser) {
              console.log('User data retrieved successfully');
              setUser(apiUser);
            } else {
              console.log('No user data or invalid session');
              // Clear any stored user data
              localStorage.removeItem('user');
            }
          } else {
            console.log('No auth token found');
            // Check for stored user data
            const storedUser = localStorage.getItem('user');
            if (storedUser) {
              try {
                // Try to load user from localStorage
                const parsedUser = JSON.parse(storedUser);
                
                // Validate session with API
                const refreshed = await authApi.refreshToken();
                if (refreshed) {
                  // Re-fetch user after refresh
                  const apiUser = await authApi.getUser();
                  if (apiUser) {
                    setUser(apiUser);
                  } else {
                    // Clear invalid data
                    localStorage.removeItem('user');
                  }
                } else {
                  // Clear invalid data
                  localStorage.removeItem('user');
                }
              } catch (parseError) {
                console.error('Error parsing stored user data', parseError);
                localStorage.removeItem('user');
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

    // Clear any error messages
    const clearError = () => {
      setError(null);
    };

    // Login function
    const login = async (email: string, password: string, rememberMe: boolean = false): Promise<boolean> => {
      try {
        setLoading(true);
        clearError();
        
        console.log('Logging in user:', email);
        const response = await authApi.login({ email, password, rememberMe: rememberMe });
        
        const user = response.user || (response.data && response.data.user);

        if (!response.success || !user) {
          throw new Error(response.error || 'Login failed');
        }
        
        console.log('Login successful for:', email);
        setUser(user);
        
        localStorage.setItem('user', JSON.stringify(user));
        
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
        
        console.log('Creating account for:', email);
        const response = await authApi.signup({
          email,
          password,
          confirmPassword: password,
          fullName
        });
        
        if (!response.success) {
          throw new Error(response.error || 'Signup failed');
        }
        

        if (response.user) {
          console.log('Signup successful for:', email);
          setUser(response.user);
          localStorage.setItem('user', JSON.stringify(response.user));
        } else {
          // If for some reason we didn't get a user object back
          console.log('Signup successful but no user object returned');
          // Attempt automatic login after signup
          await login(email, password, true);
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
        
        console.log('Logging out user');
        // Call logout API - this will clear cookies server-side
        await authApi.logout();
        
        // Clear user from state and local storage only
        setUser(null);
        localStorage.removeItem('user');
        
        console.log('Logout successful');
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
        
        console.log('Requesting password reset for:', email);
        const response = await authApi.forgotPassword(email);
        
        if (!response.success) {
          throw new Error(response.error || 'Failed to request password reset');
        }
        
        console.log('Password reset request sent for:', email);
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
        
        console.log('Resetting password with token');
        const response = await authApi.resetPassword(password, token);
        
        if (!response.success) {
          throw new Error(response.error || 'Failed to reset password');
        }
        
        console.log('Password reset successful');
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
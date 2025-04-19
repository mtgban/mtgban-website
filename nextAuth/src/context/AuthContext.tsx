import { createContext, useContext } from 'react';
import type { AuthContextType } from '@/types/auth';

export const AuthContext = createContext<AuthContextType | null>(null);

// Custom hook for easy consumption of the context
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
'use client'

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { extractGoTemplateVars, getGoValue } from '@/utils/GoNextBridge';
import type { GoPageData } from '@/types/go/pageVars';

// Define the shape of your Go data
interface GoData {
  // Authentication data
  user: {
    email: string;
    tier: string;
    isLoggedIn: boolean;
  };
  
  // Feature flags from Go template
  features: Record<string, boolean>;
  
  // Page-specific data from Go template
  pageData: {
    title?: string;
    searchQuery?: string;
    isSealed?: boolean;
    hash?: string;
    // Add other common page props here
    [key: string]: any;
  };
  
  // Raw template vars for advanced use cases
  rawTemplateVars: Record<string, any>;
  
  // Method to refresh data
  refresh: () => void;
}

// Define context interface
interface GoDataContextType {
  pageData: GoPageData;
  features: Record<string, boolean>;
  user: {
    email: string;
    tier: string;
    isLoggedIn: boolean;
  };
  isGoBackend: boolean;
}

// Create context with default values
const GoDataContext = createContext<GoDataContextType>({
  pageData: {},
  features: {},
  user: {
    email: '',
    tier: '',
    isLoggedIn: false,
  },
  isGoBackend: false,
});

interface GoDataProviderProps {
  children: ReactNode;
}

/**
 * Provider component that extracts and provides Go template data to all child components
 */
export function GoDataProvider({ children }: GoDataProviderProps) {
  // Initialize state from window.__GO_DATA__ if available
  const [contextValue, setContextValue] = useState<GoDataContextType>({
    pageData: {},
    features: {},
    user: {
      email: '',
      tier: '',
      isLoggedIn: false,
    },
    isGoBackend: false,
  });

  useEffect(() => {
    // Get data from Go backend if available
    const email = getGoValue<string>('__USER_EMAIL__', '');
    const tier = getGoValue<string>('__USER_TIER__', '');
    const isLoggedIn = getGoValue<boolean>('__IS_LOGGED_IN__', false);
    const featureFlags = getGoValue<Record<string, boolean>>('__FEATURE_FLAGS__', {});
    
    // Check if we're running in a Go backend
    const isGoBackend = typeof window !== 'undefined' && (
      window.__USER_EMAIL__ !== undefined || 
      window.__USER_TIER__ !== undefined || 
      window.__IS_LOGGED_IN__ !== undefined
    );
    
    // Update context with values from Go backend
    setContextValue({
      pageData: window.__GO_DATA__ || {},
      features: featureFlags,
      user: {
        email,
        tier,
        isLoggedIn,
      },
      isGoBackend,
    });
  }, []);

  return (
    <GoDataContext.Provider value={contextValue}>
      {children}
    </GoDataContext.Provider>
  );
}

/**
 * Hook to access Go data in functional components
 */
export function useGoData() {
  return useContext(GoDataContext);
}

/**
 * Higher-Order Component to inject Go data into a component
 * @param WrappedComponent Component to wrap
 * @returns Wrapped component with goData prop
 */
export function withGoData<P extends object>(
  WrappedComponent: React.ComponentType<P & { goData: GoDataContextType }>
) {
  return function WithGoData(props: P) {
    const goData = useGoData();
    return <WrappedComponent {...props} goData={goData} />;
  };
}

// Add to Window interface
declare global {
  interface Window {
    __GO_DATA__?: GoPageData;
  }
}

export default GoDataContext;
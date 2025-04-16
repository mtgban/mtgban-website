// utils/legalUtils.ts
import { useRouter } from 'next/router';

/**
 * Enum of available legal page routes
 */
export enum LegalPage {
  TERMS = 'terms-and-conditions',
  CASUAL_TERMS = 'casual-terms',
  PRIVACY = 'privacy-policy',
  CASUAL_PRIVACY = 'casual-privacy',
}

/**
 * Navigate to a legal page
 * @param page The legal page to navigate to
 * @param router Next.js router instance (optional, will use window.location if not provided)
 * @param options Additional navigation options
 */
export const navigateToLegalPage = (
  page: LegalPage,
  router?: ReturnType<typeof useRouter>,
  options?: {
    newTab?: boolean;
    query?: Record<string, string>;
  }
) => {
  const { newTab = false, query = {} } = options || {};
  
  const path = `/legal/${page}`;
  const queryString = Object.keys(query).length 
    ? `?${new URLSearchParams(query).toString()}` 
    : '';
  
  const fullPath = `${path}${queryString}`;
  
  if (newTab) {
    // Open in a new tab
    window.open(fullPath, '_blank');
  } else if (router) {
    // Use Next.js router if provided
    router.push({
      pathname: path,
      query,
    });
  } else {
    // Fallback to window.location
    window.location.href = fullPath;
  }
};

/**
 * Hook to get functions for navigating to legal pages
 */
export const useLegalNavigation = () => {
  const router = useRouter();
  
  return {
    goToTerms: (options?: { newTab?: boolean; query?: Record<string, string> }) => 
      navigateToLegalPage(LegalPage.TERMS, router, options),

    goToPrivacy: (options?: { newTab?: boolean; query?: Record<string, string> }) => 
      navigateToLegalPage(LegalPage.PRIVACY, router, options),
    
    goToCasualTerms: (options?: { newTab?: boolean; query?: Record<string, string> }) => 
      navigateToLegalPage(LegalPage.CASUAL_TERMS, router, options),
    
    goToCasualPrivacy: (options?: { newTab?: boolean; query?: Record<string, string> }) => 
      navigateToLegalPage(LegalPage.CASUAL_PRIVACY, router, options),
  };
};

/**
 * Props for the LegalLinks component
 */
export interface LegalLinksProps {
  casual?: boolean;
  className?: string;
  linkClassName?: string;
  separator?: React.ReactNode;
  newTab?: boolean;
}

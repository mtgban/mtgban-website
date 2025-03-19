import { Request as UndiciRequest } from 'undici';
import { authService } from './authService';

/**
 * TypeScript declaration to ensure compatibility with undici
 */
declare global {
  interface Request extends Omit<UndiciRequest, 'duplex'> {
    duplex?: string; // Make duplex optional to accommodate different Request implementations
  }
}

/**
 * Create a fetch interceptor that handles authentication errors and session refreshes.
 */
export function createFetchInterceptor() {
  if (typeof window === 'undefined') {
    return () => {}; // No-op for server-side
  }
  
  // Save original fetch function
  const originalFetch = window.fetch;

  // Check if original fetch is available
  if (!originalFetch) {
    console.warn('Original fetch function is not available');
    return () => {};
  }

  // helper function
  const isOnAuthPage = () => {
    const path = window.location.pathname;
    return path.includes('/auth/login') || 
           path.includes('/auth/signup') || 
           path.includes('/auth/reset-password') ||
           path.includes('/auth/forgot-password') ||
           path.includes('/auth/confirmation');
  };

  // Replace global fetch with intercepted version
  const fetchWithAuth = async function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    try {
      // Make the request
      const response = await originalFetch(input, init);
      
      // Don't try to refresh tokens on auth API endpoints or when on auth pages
      const url = input instanceof Request ? input.url : input.toString();
      const isAuthApiCall = url.includes('/next-api/auth/');
      
      // Handle auth errors (status 401/403)
      if (response.status === 401 || response.status === 403) {
        // Skip token refresh for auth endpoints and when on auth pages
        if (!isAuthApiCall && !isOnAuthPage()) {
          console.log('Auth error detected, attempting token refresh');
          
          try {
            // Try to refresh the token
            const refreshed = await authService.refreshSession();
            
            // If refresh succeeded, retry the original request
            if (refreshed) {
              console.log('Token refreshed successfully, retrying request');
              
              // For Request objects, clone before retrying
              if (input instanceof Request) {
                try {
                  const clonedRequest = input.clone();
                  return originalFetch(clonedRequest, init);
                } catch (cloneError) {
                  console.warn('Error cloning request:', cloneError);
                  // Fallback to original URL
                  return originalFetch(input.url, {
                    ...init,
                    method: input.method,
                    headers: input.headers,
                    body: init?.body || input.body
                  });
                }
              }
              
              // For strings/URLs, retry with original parameters
              return originalFetch(input, init);
            } else {
              console.warn('Token refresh failed');
            }
          } catch (refreshError) {
            console.warn('Error during token refresh:', refreshError);
          }
          
          // If we reach here, token refresh failed or the refreshed request failed
          if (!isAuthApiCall && !url.includes('/api/')) {
            console.log('Session expired, redirecting to login');
            // Use history API instead of location.href to avoid reload
            const returnPath = encodeURIComponent(window.location.pathname);
            window.history.pushState({}, '', `/auth/login?return_to=${returnPath}`);
            window.location.reload();
          }
        }
      }
      
      return response;
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  };

  // Preserve all function properties and type signatures
  window.fetch = fetchWithAuth as typeof window.fetch;
  
  // Return function to restore original fetch
  return () => {
    window.fetch = originalFetch;
  };
}
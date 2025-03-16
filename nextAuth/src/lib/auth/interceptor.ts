import { Request as UndiciRequest } from 'undici';
import { authService } from './authService';

/**
 * TypeScript declaration for the fetch function to ensure compatibility with undici
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

  // Replace global fetch with intercepted version that preserves the function's structure
  const fetchWithAuth = async function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    try {
      // Make the request
      const response = await originalFetch(input, init);
      
      // For signup and login pages, don't try to refresh tokens on 401 errors
      const currentPath = window.location.pathname;
      const isAuthPage = currentPath.includes('/auth/login') || 
            currentPath.includes('/auth/signup') || 
            currentPath.includes('/auth/forgot-password');  
      
      // Check for auth errors (but only refresh if not on auth pages)
      if ((response.status === 401 || response.status === 403) && !isAuthPage) {
        // If not already on auth page
        if (!window.location.pathname.includes('/auth/login')) {
          // Try refreshing the token
          try {
            const refreshed = await authService.refreshSession();
            
            // If refresh succeeded, retry the request
            if (refreshed) {
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
            }
          } catch (refreshError) {
            // Only redirect if not on an auth page already
            if (!isAuthPage) {
              console.warn('Session expired, handling gracefully');
              // Don't redirect automatically on API requests
              if (!input.toString().includes('/api/')) {
                const currentPath = encodeURIComponent(window.location.pathname);
                window.location.href = `/auth/login?redirectTo=${currentPath}`;
              }
            }
          }
        }
      }
      
      return response;
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  };

  //preserve all function properties and type signatures
  window.fetch = fetchWithAuth as typeof window.fetch;
  
  // Return function to restore original fetch
  return () => {
    window.fetch = originalFetch;
  };
}
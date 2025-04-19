// auth/interceptor.ts

import { Request as UndiciRequest } from 'undici';
import { authService } from './authService';

declare global {
    interface Request extends Omit<UndiciRequest, 'duplex'> {
        duplex?: string;
    }
}

// --- Constants ---
const AUTH_API_PREFIX = process.env.NEXT_PUBLIC_AUTH_API_PATH || '/next-api/auth';
// Prefix for frontend auth pages (used to avoid refresh/redirect loops)
const AUTH_PAGE_PREFIX = '/auth/';

/**
 * Checks if the current browser path starts with the auth page prefix.
 */
function isCurrentlyOnAuthPage(): boolean {
    if (typeof window === 'undefined') {
        return false; // Cannot determine on server-side
    }
    return window.location.pathname.startsWith(AUTH_PAGE_PREFIX);
}


/**
 * Create a fetch interceptor that handles authentication errors (401/403)
 * by attempting to refresh the session and retry the request.
 * Also handles redirection to login on unrecoverable auth failures for non-API calls.
 */
export function createFetchInterceptor() {
    // Interceptor only runs in the browser
    if (typeof window === 'undefined' || typeof window.fetch === 'undefined') {
        console.log('Fetch interceptor disabled (SSR or fetch not available).');
        return () => {}; // No-op function
    }

    const originalFetch = window.fetch;
    let isInterceptorActive = true; // Flag to control the interceptor

    console.log('Activating fetch interceptor.');

    window.fetch = async (
        input: RequestInfo | URL,
        init?: RequestInit
    ): Promise<Response> => {
        // Add CSRF token to the initial request if available and applicable
        const requestUrl = input instanceof Request ? input.url : input.toString();
        const isAuthApiCall = requestUrl.includes(AUTH_API_PREFIX);

        let requestInit = init;
        // Only add CSRF for non-GET requests to non-auth API endpoints
        const method = init?.method?.toUpperCase() || (input instanceof Request ? input.method.toUpperCase() : 'GET');
        if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
             requestInit = {
                ...init,
                headers: authService.addCsrfToken(init?.headers), // Use service helper
                credentials: init?.credentials ?? 'same-origin', // Ensure credentials are sent
            };
        } else {
            // Ensure credentials are set for GET requests too if needed for cookies
             requestInit = {
                ...init,
                credentials: init?.credentials ?? 'same-origin',
            };
        }


        const response = await originalFetch(input, requestInit);

        // Handle Auth Errors (401/403)
        if ((response.status === 401 || response.status === 403) && isInterceptorActive) {
            console.debug(`Interceptor: Detected ${response.status} for ${requestUrl}`);

            // Conditions to skip refresh attempt:
            // - If the failed request was to one of our auth API endpoints.
            // - If the user is currently on one of the frontend auth pages.
            const skipRefresh = isAuthApiCall || isCurrentlyOnAuthPage();

            if (!skipRefresh) {
                console.log('Auth error on non-auth path/page, attempting token refresh...');
                isInterceptorActive = false; // Temporarily disable interceptor during refresh
                let refreshSuccess = false;
                try {
                     // Attempt refresh using the service
                     refreshSuccess = await authService.refreshSession();
                } catch (refreshError) {
                     console.warn('Error thrown during token refresh:', refreshError);
                     // authService.refreshSession should handle logout on failure
                } finally {
                     isInterceptorActive = true; // Re-enable interceptor
                }


                if (refreshSuccess) {
                    console.log('Token refreshed successfully, retrying original request...');

                    // Retry Request with New Token
                    // Prepare new headers with potentially updated CSRF token
                    const retryHeaders = new Headers(requestInit?.headers);
                    const newCsrf = authService.getCsrfToken();
                    if (newCsrf) {
                        retryHeaders.set('X-CSRF-Token', newCsrf);
                    } else {
                        retryHeaders.delete('X-CSRF-Token');
                    }

                    // Prepare new init object for retry
                    const retryInit: RequestInit = {
                        ...requestInit, // Copy original method, body, credentials etc.
                        headers: retryHeaders,
                    };

                    // Retry the original request (input could be URL string or Request object)
                    console.debug('Retrying fetch for:', requestUrl);
                    return originalFetch(input instanceof Request ? input : requestUrl, retryInit); // Re-use original input if Request, else url

                } else {
                    // Handle Failed Refresh
                    console.warn('Token refresh failed or was skipped. Original response returned for potential handling.');
                    // Redirect to login only if:
                    // Refresh failed (handled above)
                    // It wasn't an auth API call itself (already checked by skipRefresh)
                    // It wasn't a general API call (e.g., /api/data)
                    // User is not already on an auth page (already checked by skipRefresh)
                    const isGeneralApiCall = requestUrl.includes('/api/') && !isAuthApiCall; // Exclude our auth API
                    if (!isGeneralApiCall) { // Only redirect for page loads/non-API requests
                        console.log(`Session invalid/expired after failed refresh on page ${window.location.pathname}, redirecting to login.`);
                        // authService.logout() should have already cleared state.
                        // Redirect with return path
                        const returnPath = encodeURIComponent(window.location.pathname + window.location.search);
                        // Use replace to avoid polluting history with failed pages
                        window.location.replace(`${AUTH_PAGE_PREFIX}login?return_to=${returnPath}`);
                        return new Promise(() => {});
                    }
                    // For failed API calls after failed refresh, return original 401/403
                    // Let the specific API call handler manage the error display.
                    return response;
                }
            } else {
                 console.debug(`Skipping token refresh: isAuthApiCall=${isAuthApiCall}, isCurrentlyOnAuthPage=${isCurrentlyOnAuthPage()}`);
            }
        }

        // --- 5. Return Original Response (Success or Unhandled Error) ---
        return response;
    };

    // Return function to restore original fetch
    return () => {
        if (window.fetch === originalFetch) {
            console.log('Fetch interceptor already restored or was not active.');
        } else {
            window.fetch = originalFetch;
            console.log('Fetch interceptor restored.');
        }
        isInterceptorActive = false;
    };
}

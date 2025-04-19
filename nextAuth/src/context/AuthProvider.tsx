// context/AuthContext/AuthProvider.tsx
import React, {
    useState,
    useEffect,
    useMemo,
    useCallback,
    PropsWithChildren,
} from 'react';
import { AuthContext } from './AuthContext';

// Import the refined types
import type {
    AuthContextType,
    AuthContextUser, // This is AppUser | null
    AuthContextError,
    AppUser, // Specific type for the user object
    UserCredentials,
    SignupFormData, // Use the corrected name
} from '@/types/auth'; // Adjust path as needed

// Import the singleton authService
import { authService } from '@/lib/auth/authService'; // Adjust path as needed

export const AuthProvider: React.FC<PropsWithChildren<{}>> = ({ children }) => {
    // State using the refined types
    const [user, setUser] = useState<AuthContextUser>(null); // AppUser | null
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(true); // Start loading initially
    const [error, setError] = useState<AuthContextError | null>(null);

    // Derived state
    const isAuthenticated = useMemo(() => !!user, [user]);

    // Helper to clear error state
    const clearError = useCallback(() => {
        setError(null);
    }, []);

    // --- Authentication Actions ---
    // These now primarily call authService and then sync the provider's state
    // with the service's state.

    const login = useCallback(
        async (credentials: UserCredentials): Promise<boolean> => {
            setIsLoading(true);
            clearError();
            try {
                // authService.login handles API call, state update within service, returns success/user/error
                const result = await authService.login(credentials);

                if (result.success) {
                    // Sync provider state with service state
                    setUser(authService.getUser()); // Get the AppUser | null from service
                    setCsrfToken(authService.getCsrfToken());
                    setError(null);
                    setIsLoading(false);
                    return true;
                } else {
                    throw new Error(result.error || 'Login failed');
                }
            } catch (err: any) {
                console.error('AuthProvider Login Error:', err);
                setError({ message: err.message || 'Login failed' });
                // Ensure provider state is cleared if service failed internally
                setUser(null);
                setCsrfToken(null);
                setIsLoading(false);
                return false;
            }
        },
        [clearError] // Dependency injection for clearError
    );

    const signup = useCallback(
        async (signupData: SignupFormData): Promise<{ success: boolean; emailConfirmationRequired?: boolean }> => {
            setIsLoading(true);
            clearError();
            try {
                // Use the corrected input type: SignupFormData
                const result = await authService.signup(signupData);

                if (result.success) {
                    if (result.emailConfirmationRequired) {
                        setError({ message: 'Please check your email to confirm your account.' });
                        // Keep user null as they haven't auto-logged in
                        setUser(null);
                        setCsrfToken(null); // No CSRF token yet
                    } else if (result.user) {
                        // Auto-login successful, sync state
                        setUser(authService.getUser());
                        setCsrfToken(authService.getCsrfToken());
                        setError(null);
                    }
                    // If success but no user/confirmation, state remains logged out
                    setIsLoading(false);
                    return { success: true, emailConfirmationRequired: result.emailConfirmationRequired };
                } else {
                    throw new Error(result.error || 'Signup failed');
                }
            } catch (err: any) {
                console.error('AuthProvider Signup Error:', err);
                setError({ message: err.message || 'Signup failed' });
                setUser(null);
                setCsrfToken(null);
                setIsLoading(false);
                return { success: false };
            }
        },
        [clearError]
    );

    const logout = useCallback(async (): Promise<void> => {
        // Don't necessarily need isLoading here, logout should feel instant locally
        // setIsLoading(true);
        clearError();
        try {
            await authService.logout(); // Service clears its state immediately & calls backend
        } catch (err: any) {
            // Log service error, but local state clearing should proceed
            console.error('AuthProvider Logout Error (from service):', err);
            // setError({ message: 'Logout failed, clearing local state.' }); // Optional: Inform user
        } finally {
            // Sync provider state AFTER service has cleared its state
            setUser(authService.getUser()); // Should be null
            setCsrfToken(authService.getCsrfToken()); // Should be null
            // setIsLoading(false);
        }
    }, [clearError]);

    const fetchUser = useCallback(async (): Promise<AuthContextUser> => {
        // Only set loading if not already loading (prevents flicker on rapid calls)
        // Although usually called only on init or manually
        if (!isLoading) setIsLoading(true);
        clearError();
        try {
            // Service fetchUser handles API call and updates its internal state
            const fetchedUser = await authService.fetchUser();
            // Sync provider state with the result from the service
            setUser(fetchedUser);
            setCsrfToken(authService.getCsrfToken());
            setError(null); // Clear error on successful fetch
            setIsLoading(false);
            return fetchedUser; // Return AppUser | null
        } catch (err: any) {
            // This catch might not be strictly needed if authService handles its errors,
            // but good for safety / logging provider-level fetch issues.
            console.error('AuthProvider Fetch User Error:', err);
            // Sync state even on error (authService might have cleared user on 401)
            setUser(authService.getUser());
            setCsrfToken(authService.getCsrfToken());
            setError({ message: err.message || 'Failed to check session' });
            setIsLoading(false);
            return null;
        }
    }, [clearError, isLoading]); // Add isLoading to dependencies

    const refreshSession = useCallback(async (): Promise<boolean> => {
        setIsLoading(true);
        clearError();
        try {
            const success = await authService.refreshSession(); // Service handles API, state update, logout on fail
            // Sync provider state with service state after the attempt
            setUser(authService.getUser());
            setCsrfToken(authService.getCsrfToken());
            if (!success) {
                setError({ message: 'Session expired or refresh failed.' });
            } else {
                setError(null); // Clear error on successful refresh
            }
            setIsLoading(false);
            return success;
        } catch (err: any) {
            // Should be caught by authService which triggers logout, but sync state just in case
            console.error('AuthProvider Refresh Session Error:', err);
            setUser(null);
            setCsrfToken(null);
            setError({ message: 'Session refresh failed unexpectedly.' });
            setIsLoading(false);
            return false;
        }
    }, [clearError]);

    // --- Initial Load Effect ---
    useEffect(() => {
        let isMounted = true; // Prevent state updates if component unmounts during fetch
        console.log('AuthProvider mounted. Initializing auth state...');
        setIsLoading(true);

        authService.fetchUser().then(initialUser => {
            if (isMounted) {
                setUser(initialUser);
                setCsrfToken(authService.getCsrfToken());
                console.log('AuthProvider initialization complete. User:', initialUser ? initialUser.email : 'None');
            }
        }).catch(err => {
            if (isMounted) {
                console.log('Initial fetchUser failed (likely no session):', err.message);
                setUser(null);
                setCsrfToken(null);
            }
        }).finally(() => {
            if (isMounted) {
                setIsLoading(false);
            }
        });

        // Cleanup function to prevent setting state on unmounted component
        return () => {
            isMounted = false;
        };
    }, []); // Run only on mount

    // Memoize the context value
    const contextValue = useMemo<AuthContextType>(
        () => ({
            user,
            isAuthenticated,
            isLoading,
            error,
            csrfToken,
            login,
            logout,
            signup,
            fetchUser,
            refreshSession,
            clearError,
            forgotPassword: () => Promise.resolve(false),
            resetPassword: () => Promise.resolve(false),
        }),
        [
            user,
            isAuthenticated,
            isLoading,
            error,
            csrfToken,
            login,
            logout,
            signup,
            fetchUser,
            refreshSession,
            clearError,
        ]
    );

    return (
        <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
    );
};

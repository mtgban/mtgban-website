// context/AuthContext/AuthProvider.tsx
import React, {
    useState,
    useEffect,
    useMemo,
    useCallback,
    PropsWithChildren,
} from 'react';
import { AuthContext } from './AuthContext';

import type {
    AuthContextType,
    AuthContextUser,
    AuthContextError,
    AppUser,
    UserCredentials,
    SignupFormData,
} from '@/types/auth';

import { authService } from '@/lib/auth/authService';

export const AuthProvider: React.FC<PropsWithChildren<{}>> = ({ children }) => {
    const [user, setUser] = useState<AuthContextUser>(null);
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [error, setError] = useState<AuthContextError | null>(null);

    const isAuthenticated = useMemo(() => !!user, [user]);

    const clearError = useCallback(() => {
        setError(null);
    }, []);

    const login = useCallback(
        async (credentials: UserCredentials): Promise<boolean> => {
            setIsLoading(true);
            clearError();
            try {
                const result = await authService.login(credentials);

                if (result.success) {
                    setUser(authService.getUser());
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
        [clearError]
    );

    const signup = useCallback(
        async (signupData: SignupFormData): Promise<{ success: boolean; emailConfirmationRequired?: boolean }> => {
            setIsLoading(true);
            clearError();
            try {
                const result = await authService.signup(signupData);

                if (result.success) {
                    if (result.emailConfirmationRequired) {
                        setError({ message: 'Please check your email to confirm your account.' });
                        setUser(null);
                        setCsrfToken(null);
                    } else if (result.user) {
                        setUser(authService.getUser());
                        setCsrfToken(authService.getCsrfToken());
                        setError(null);
                    }
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
        clearError();
        try {
            await authService.logout();
        } catch (err: any) {
            console.error('AuthProvider Logout Error (from service):', err);
        } finally {
            setUser(authService.getUser());
            setCsrfToken(authService.getCsrfToken());
        }
    }, [clearError]);

    const fetchUser = useCallback(async (): Promise<AuthContextUser> => {
        if (!isLoading) setIsLoading(true);
        clearError();
        try {
            const fetchedUser = await authService.fetchUser();
            setUser(fetchedUser);
            setCsrfToken(authService.getCsrfToken());
            setError(null);
            setIsLoading(false);
            return fetchedUser;
        } catch (err: any) {
            console.error('AuthProvider Fetch User Error:', err);
            setUser(authService.getUser());
            setCsrfToken(authService.getCsrfToken());
            setError({ message: err.message || 'Failed to check session' });
            setIsLoading(false);
            return null;
        }
    }, [clearError, isLoading]);

    const refreshSession = useCallback(async (): Promise<boolean> => {
        setIsLoading(true);
        clearError();
        try {
            const success = await authService.refreshSession();
            setUser(authService.getUser());
            setCsrfToken(authService.getCsrfToken());
            if (!success) {
                setError({ message: 'Session expired or refresh failed.' });
            } else {
                setError(null);
            }
            setIsLoading(false);
            return success;
        } catch (err: any) {
            console.error('AuthProvider Refresh Session Error:', err);
            setUser(null);
            setCsrfToken(null);
            setError({ message: 'Session refresh failed unexpectedly.' });
            setIsLoading(false);
            return false;
        }
    }, [clearError]);

    useEffect(() => {
        let isMounted = true;
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

        return () => {
            isMounted = false;
        };
    }, []);

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

    return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
};

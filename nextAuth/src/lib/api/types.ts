/**
 * Authentication related type definitions and factory functions
 */

/**
 * User credentials for login
 */
export interface UserCredentials {
    /** User's email address */
    email: string;
    /** User's password */
    password: string;
    /** Whether to remember the user for a longer period */
    remember?: boolean;
}

/**
 * Create default UserCredentials with optional overrides
 */
const createCredentials = (
    partial?: Partial<UserCredentials>
): UserCredentials => ({
    email: "",
    password: "",
    remember: false,
    ...partial,
});

/**
 * Data required for creating a new user account
 */
export interface SignupData {
    /** User's email address */
    email: string;
    /** User's chosen password */
    password: string;
    /** Confirmation of the password (for validation) */
    confirmPassword: string;
    /** User's full name */
    fullName: string;
}

/**
 * Create default SignupData with optional overrides
 */
const createSignupData = (partial?: Partial<SignupData>): SignupData => ({
    email: "",
    password: "",
    confirmPassword: "",
    fullName: "",
    ...partial,
});

/**
 * Additional metadata stored with a user account
 */
export interface UserMetadata {
    /** User's full name */
    full_name?: string;
    /** User's subscription tier */
    tier?: string;
    /** User's role */
    role?: string;
    /** Any additional custom fields */
    [key: string]: any;
}

/**
 * Create default UserMetadata
 */
const createDefaultMetadata = (): UserMetadata => ({
    tier: "free",
    full_name: "",
});

/**
 * User object representing an authenticated user
 */
export interface User {
    /** Unique identifier for the user */
    id: string;
    /** User's email address */
    email: string;
    /** User's subscription tier */
    tier?: string;
    /** Whether the user's email has been confirmed */
    emailConfirmed?: boolean;
    /** Additional user metadata */
    user_metadata?: UserMetadata;
    /** Any other user properties */
    [key: string]: any;
}

/**
 * Create a default User object
 */
const createDefaultUser = (): User => ({
    id: "",
    email: "",
    emailConfirmed: false,
    user_metadata: {
        tier: "free",
        full_name: "",
    },
});

/**
 * Subscription data structure
 */
export interface Subscription {
    id: string;
    status: string;
    current_period_end: string;
    current_period_start: string;
    cancel_at_period_end: boolean;
    prices?: {
        currency?: string;
        unit_amount?: number;
        interval?: string;
        products?: {
            name?: string;
            description?: string;
        };
    };
}

/**
 * Authentication token data
 */
export interface TokenData {
    /** JWT access token */
    accessToken: string;
    /** Refresh token for obtaining new access tokens */
    refreshToken: string;
    /** Timestamp when the token expires */
    expiresAt: number;
}

/**
 * Authentication session information
 */
export interface Session {
    /** JWT access token */
    access_token: string;
    /** Refresh token */
    refresh_token: string;
    /** Timestamp when the session expires */
    expires_at: number;
    /** Token for backend services */
    backend_token?: string;
}

/**
 * Response from authentication operations
 */
export interface AuthResponse {
    /** User data if operation was successful */
    user: User | null;
    /** Session data if operation was successful */
    session: Session | null;
    /** Whether email confirmation is required */
    emailConfirmationRequired?: boolean;
}

/**
 * Error information for authentication operations
 */
export interface AuthError {
    /** Error message */
    message: string;
    /** HTTP status code if applicable */
    status?: number;
}

/**
 * Current application authentication state
 */
export interface AuthState {
    /** Current authenticated user or null */
    user: User | null;
    /** Whether authentication state is being loaded */
    isLoading: boolean;
    /** Whether the user is authenticated */
    isAuthenticated: boolean;
    /** Current authentication error if any */
    error: AuthError | null;
}

/**
 * Create default AuthState
 */
const createDefaultAuthState = (): AuthState => ({
    user: null,
    isLoading: false,
    isAuthenticated: false,
    error: null,
});

/**
 * Backend response format
 */
export interface BackendResponse {
    /** Whether the operation was successful */
    success: boolean;
    /** Error message if operation failed */
    error?: string;
    /** User data if applicable */
    user?: User;
    /** Session information if applicable */
    session?: {
        expires_at: number;
    };
    /** Backend token for internal authentication */
    backendToken?: string;
    /** Whether email confirmation is required */
    emailConfirmationRequired?: boolean;
}

export {
    createDefaultUser,
    createDefaultMetadata,
    createDefaultAuthState,
    createCredentials,
    createSignupData,
};
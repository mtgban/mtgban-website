// ========================================================================
// Backend API Response Structures
// ========================================================================

/**
 * Mirrors the Go backend's `UserResponse` struct.
 * Expected structure within the 'data' field of successful
 * user-related API responses (login, refresh, get user).
 */
export interface BackendUserResponse {
    user_id: string;
    email: string;
    tier: string;
    role: string;
    expires_at: number;
    csrf_token: string;
}

/**
 * Mirrors the Go backend's top-level `APIResponse` struct.
 * Generic wrapper for most backend responses.
 * @template T The type of the data expected in the 'data' field.
 */
export interface BackendApiResponse<T = any> {
    success: boolean;
    message?: string;
    error?: string;
    code?: string;
    data?: T | null;
    redirectTo?: string;
}

// --- Specific Backend Response Type Aliases ---

export type BackendUserApiResponse = BackendApiResponse<BackendUserResponse>;
export type BackendSimpleApiResponse = BackendApiResponse<null | Record<string, unknown>>;

// ========================================================================
// Frontend Application State & Context Types
// ========================================================================

/**
 * Represents the user object as stored and used within the frontend application state.
 * Derived from BackendUserResponse.
 */
export interface AppUser {
    id: string; 
    email: string;
    tier: string;
    role: string;
}

export type AuthContextUser = AppUser | null;
export interface AuthContextError {
    message: string;
    code?: string;
}

export interface AuthContextType {
    user: AuthContextUser;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: AuthContextError | null;
    csrfToken: string | null;

    
    login: (credentials: UserCredentials) => Promise<boolean>;
    logout: () => Promise<void>;
    signup: (data: SignupFormData) => Promise<{ success: boolean, emailConfirmationRequired?: boolean }>;
    fetchUser: () => Promise<AuthContextUser>;
    refreshSession: () => Promise<boolean>;
    clearError: () => void;
    forgotPassword: (email: string) => Promise<boolean>;
    resetPassword: (password: string, token: string) => Promise<boolean>;
}

// ========================================================================
// Frontend Action Input Data Structures
// ========================================================================

/** Data needed for the login action/form */
export interface UserCredentials {
    email: string;
    password: string;
    remember?: boolean;
}

/** Data needed for the signup action/form */
export interface SignupFormData {
    email: string;
    password: string;
    confirmPassword?: string;
    fullName: string;
}

// ========================================================================
// Factory Functions
// ========================================================================

/** Creates default UserCredentials */
export const createCredentials = (
    partial?: Partial<UserCredentials>
): UserCredentials => ({
    email: "",
    password: "",
    remember: false,
    ...partial,
});

/** Creates default SignupFormData */
export const createSignupFormData = (partial?: Partial<SignupFormData>): SignupFormData => ({
    email: "",
    password: "",
    confirmPassword: "",
    fullName: "",
    ...partial,
});

/** Creates a default/empty AppUser */
export const createDefaultAppUser = (): AppUser => ({
    id: "",
    email: "",
    tier: "free",
    role: "user",
});

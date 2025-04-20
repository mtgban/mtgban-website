import type {
    UserCredentials,
    SignupFormData,
    AppUser,
    BackendUserApiResponse,
    BackendSimpleApiResponse,
    BackendApiResponse,
    BackendUserResponse,
} from '@/types/auth';

const AUTH_API_PATH = process.env.NEXT_PUBLIC_AUTH_API_PATH || '/next-api/auth';

/**
 * Core authentication service to interact with the backend API
 * and manage local auth state (user, csrf token).
 */
export class AuthService {
    private user: AppUser | null = null;
    private csrfToken: string | null = null;
    private refreshTimer: ReturnType<typeof setTimeout> | null = null;
    private refreshing = false;
    private loggingOut = false;
    private listeners: ((user: AppUser | null) => void)[] = [];
    private tokenExpiryKey = 'token_expires_at'; // Used for scheduling refresh

  /** Gets the full API URL for an endpoint */
  private getApiUrl(endpoint: string): string {
    const cleanEndpoint = endpoint.startsWith('/')
      ? endpoint.substring(1)
      : endpoint;
    return `${AUTH_API_PATH}/${cleanEndpoint}`;
  }

  /** Adds the current CSRF token to request headers */
  addCsrfToken(headers: HeadersInit = {}): HeadersInit {
    if (this.csrfToken) {
      return { ...headers, 'X-CSRF-Token': this.csrfToken };
    }
    return headers;
  }

  /** Notifies subscribed components of auth state changes */
  private notifyListeners(): void {
    this.listeners.forEach((listener) => listener(this.user));
  }

  /** Clears all local authentication state */
  private clearLocalState(): void {
    this.user = null;
    this.csrfToken = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    try {
      localStorage.removeItem(this.tokenExpiryKey);
    } catch (e) {
        console.warn('Local storage not available for clearing state');
      }
    }

    /** Updates state after a successful login or refresh */
  private handleAuthSuccess(apiData: BackendUserResponse): void {
    this.user = {
      id: apiData.user_id,
      email: apiData.email,
      tier: apiData.tier,
      role: apiData.role,
    };
    this.csrfToken = apiData.csrf_token;

    // Store expiry for refresh scheduling
    try {
       // Backend sends seconds, JS needs milliseconds
      localStorage.setItem(this.tokenExpiryKey, String(apiData.expires_at * 1000));
    } catch (e) {
      console.warn('Local storage not available for token expiry');
    }

    this.setupTokenRefresh(); // Schedule next refresh
    this.notifyListeners(); // Inform components
 }

 /**
   * Initializes the service state. Often called on app startup.
   */
 public init(initialUser: AppUser | null, csrfToken: string | null): void {
    console.warn("AuthService.init called directly. Consider using fetchUser on startup.");
    this.user = initialUser;
    this.csrfToken = csrfToken; // Usually fetched or set via cookies
    if (initialUser) {
      this.setupTokenRefresh(); // Requires expiry info from localStorage ideally
    }
    this.notifyListeners();
  }

  /**
   * Logs in a user with email and password.
   * Returns the user object on success, null otherwise.
   */
  public async login(credentials: UserCredentials): Promise<{ success: boolean; user: AppUser | null; error?: string }> {
    try {
      const response = await fetch(this.getApiUrl('login'), {
        method: 'POST',
        headers: this.addCsrfToken({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(credentials),
        credentials: 'same-origin',
      });

      // Parse even for non-ok responses to get error details
      const responseData = await response.json() as BackendUserApiResponse;

      if (!response.ok || !responseData.success || !responseData.data) {
        throw new Error(responseData.error || `Login failed (${response.status})`);
      }

      this.handleAuthSuccess(responseData.data);

      return { success: true, user: this.user };

    } catch (error: any) {
      console.error('Login error:', error);
      this.clearLocalState(); // Clear state on login failure
      this.notifyListeners();
      return {
        success: false,
        user: null,
        error: error.message || 'Login failed',
      };
    }
  }

  /**
   * Signs up a new user. Handles auto-login if backend supports it.
   */
  public async signup(signupData: SignupFormData): Promise<{ success: boolean; user: AppUser | null; emailConfirmationRequired?: boolean; error?: string }> {
    try {
      if (signupData.password !== signupData.confirmPassword) {
        return { success: false, user: null, error: 'Passwords do not match' };
      }

      // Prepare payload for Go backend
      const backendPayload = {
        email: signupData.email,
        password: signupData.password,
        userData: {
          full_name: signupData.fullName,
        },
      };

      const response = await fetch(this.getApiUrl('signup'), {
        method: 'POST',
        headers: this.addCsrfToken({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(backendPayload),
        credentials: 'same-origin',
      });

      // Use generic BackendApiResponse as success might not contain user data
      const responseData = await response.json() as BackendApiResponse;

      if (!response.ok || !responseData.success) {
        throw new Error(responseData.error || `Signup failed (${response.status})`);
      }

      // Check if backend returned user data (auto-login successful)
      const apiUserData = responseData.data as BackendUserResponse | null;
      if (apiUserData?.user_id) {
        this.handleAuthSuccess(apiUserData);
        return { success: true, user: this.user };
      } else {
         // Signup succeeded but didn't auto-login
         return { success: true, user: null };
      }

    } catch (error: any) {
      console.error('Signup error:', error);
      return {
        success: false,
        user: null,
        error: error.message || 'Signup failed',
      };
    }
  }

  /**
   * Logs out the current user by calling the backend and clearing local state.
   */
  public async logout(): Promise<void> {
    if (this.loggingOut) {
      console.debug('Logout already in progress');
      return;
    }
    this.loggingOut = true;
    console.debug('Logging out user...');

    const previousUser = this.user; // Keep track if someone was logged in

    // Clear local state immediately for faster UI update
    this.clearLocalState();
    // Notify listeners immediately that user is null
    if (previousUser) {
        this.notifyListeners();
    }


    try {
      // Call backend to invalidate session/tokens server-side
      const response = await fetch(this.getApiUrl('logout'), {
        method: 'POST',
        headers: this.addCsrfToken(),
        credentials: 'same-origin',
      });
      const responseData = await response.json() as BackendSimpleApiResponse;
      if (!response.ok || !responseData.success) {
          console.warn('Backend logout call failed:', responseData.error || response.status);
          // State is already cleared locally, so just log warning
      }
    } catch (error) {
      console.error('Error during backend logout call:', error);
      // Local state is already cleared
    } finally {
      this.loggingOut = false;
      console.debug('User logged out (local state cleared).');
    }
  }

  /**
   * Fetches the current user's data from the backend (/me).
   * Updates local state and returns the user or null.
   */
  public async fetchUser(): Promise<AppUser | null> {
    try {
      const response = await fetch(this.getApiUrl('me'), {
        headers: this.addCsrfToken(),
        credentials: 'same-origin', // Ensure cookies are sent
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Unauthorized - session is invalid or missing
          if (this.user) { // Only clear/notify if user *was* logged in
            console.debug('fetchUser received 401, clearing local state.');
            this.clearLocalState();
            this.notifyListeners();
          }
          return null;
        }
        // Other server error
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Failed to fetch user (${response.status})`);
      }

      const responseData = await response.json() as BackendUserApiResponse;

      if (!responseData.success || !responseData.data) {
        throw new Error(responseData.error || 'Failed to fetch user data');
      }

      // User data received successfully
      this.handleAuthSuccess(responseData.data);
      return this.user;

    } catch (error: any) {
      console.error('Error fetching user:', error);
      // Don't clear local state on general fetch errors (e.g., network)
      // Only 401 should clear the state.
      return null; // Indicate fetch failed
    }
  }

  /**
   * Attempts to refresh the session using the refresh token (via backend).
   * Returns true on success, false on failure (and triggers logout).
   */
  public async refreshSession(): Promise<boolean> {
    if (this.refreshing) {
        console.debug("Session refresh already in progress.");
        return false; // Avoid concurrent refreshes
    }
    this.refreshing = true;
    console.debug("Attempting session refresh...");

    try {
      const response = await fetch(this.getApiUrl('refresh-token'), {
        method: 'POST',
        headers: this.addCsrfToken(), // Include current CSRF if available
        credentials: 'same-origin', // Needed to send cookies
      });

      // Attempt to parse JSON regardless of status for error messages
      const responseData = await response.json() as BackendUserApiResponse;

      if (!response.ok || !responseData.success || !responseData.data) {
        // Refresh failed (expired refresh token, server error, etc.)
        console.warn('Session refresh failed:', responseData.error || `Status ${response.status}`);
        await this.logout(); // Treat refresh failure as needing logout
        this.refreshing = false;
        return false;
      }

      // Refresh successful
      console.debug("Session refresh successful.");
      this.handleAuthSuccess(responseData.data); // Update user, csrf, expiry, reschedule
      this.refreshing = false;
      return true;

    } catch (error: any) {
      console.error('Network or parsing error during session refresh:', error);
      await this.logout(); // Logout on unexpected errors during refresh
      this.refreshing = false;
      return false;
    }
  }

  /**
   * Sends a password reset request email.
   */
  public async forgotPassword(email: string): Promise<{ success: boolean; error?: string }> {
    try {
      const response = await fetch(this.getApiUrl('forgot-password'), {
        method: 'POST',
        headers: this.addCsrfToken({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ email }),
        credentials: 'same-origin'
      });

      const responseData = await response.json() as BackendSimpleApiResponse;

      if (!response.ok || !responseData.success) {
        throw new Error(responseData.error || 'Failed to process request');
      }
      // Backend sends success even if email doesn't exist for security
      return { success: true };
    } catch (error: any) {
      console.error('Forgot password error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Resets the password using a token (typically from email link).
   * NOTE: IN PROGRESS
   */
  public async resetPassword(password: string, token: string): Promise<{ success: boolean; error?: string }> {
      console.warn("resetPassword called, ensure backend endpoint '/next-api/auth/reset-password' exists and accepts {password, token}.");
      try {
          const response = await fetch(this.getApiUrl('reset-password'), {
              method: 'POST',
              headers: this.addCsrfToken({ 'Content-Type': 'application/json' }),
              body: JSON.stringify({ password, token })
          });

          const responseData = await response.json() as BackendSimpleApiResponse;

          if (!response.ok || !responseData.success) {
              throw new Error(responseData.error || 'Failed to reset password');
          }

          return { success: true };
      } catch (error: any) {
          console.error('Reset password error:', error);
          return { success: false, error: error.message };
      }
  }

  // --- State Getters ---

  /** Gets the current logged-in user state */
  public getUser(): AppUser | null {
    return this.user;
  }

  /** Gets the current CSRF token */
  public getCsrfToken(): string | null {
    return this.csrfToken;
  }

  /** Checks if a user is currently authenticated */
  public isAuthenticated(): boolean {
    return !!this.user;
  }

  // --- Subscription ---

  /** Subscribes to authentication state changes */
  public subscribe(listener: (user: AppUser | null) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  // --- Token Refresh Scheduling ---

  /** Sets up the timer for automatic token refresh before expiry */
  private setupTokenRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    const refreshBuffer = 5 * 60 * 1000; // 5 minutes in milliseconds

    let expiresAtMs = 0;
    try {
      const expiryData = localStorage.getItem(this.tokenExpiryKey);
      if (expiryData) {
        expiresAtMs = parseInt(expiryData, 10);
        if (isNaN(expiresAtMs)) expiresAtMs = 0; // Handle parsing errors
      }
    } catch (e) {
      console.warn('Local storage not available for reading token expiry');
    }

    if (expiresAtMs <= 0) {
      this.refreshTimer = setTimeout(() => this.refreshSession(), 30 * 60 * 1000);
      return;
    }

    const now = Date.now();
    // Calculate time until buffer point before expiry
    const timeUntilRefresh = expiresAtMs - now - refreshBuffer;

    if (timeUntilRefresh <= 0) {
      // Expiry is already past the buffer point, or in the past. Refresh soon.
      console.log(`Token expiry (or buffer point) reached (${timeUntilRefresh}ms), scheduling immediate refresh.`);
      // Add a small delay to avoid instant refresh loops if clocks are slightly off
      this.refreshTimer = setTimeout(() => this.refreshSession(), 1000);
    } else {
      // Schedule refresh at the calculated time
      console.log(`Scheduling token refresh in ${Math.round(timeUntilRefresh / 1000 / 60)} minutes.`);
      this.refreshTimer = setTimeout(() => this.refreshSession(), timeUntilRefresh);
    }
  }
}

export const authService = new AuthService();

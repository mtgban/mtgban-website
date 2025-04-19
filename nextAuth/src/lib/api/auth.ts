import type { AppUser } from '@/types/auth';
// Define response types
interface AuthResponse {
  success: boolean;
  message?: string;
  error?: string;
  data?: any;
  user?: AppUser;
  session?: {
    expires_at: number;
    csrf_token: string;
  };
  redirectTo?: string;
  emailConfirmationRequired?: boolean;
}

// Define refresh token response type
interface RefreshResponse {
  success: boolean;
  user?: AppUser;
  error?: string;
  session?: {
    csrf_token: string;
  };
}

// API base URL
const API_BASE_URL = '/next-api';

// Helper function to make API requests with CSRF handling
async function apiRequest<T>(
  endpoint: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
  body?: any,
  csrfToken?: string | null // Pass CSRF token as argument
): Promise<T> {
  const headers: HeadersInit = {
      'Content-Type': 'application/json',
  };

  // Add CSRF token header if available and not a GET request
  if (csrfToken && method !== 'GET') {
      headers['X-CSRF-Token'] = csrfToken; 
  }

  const config: RequestInit = {
      method,
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
      credentials: 'omit' 
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  if (!response.ok) {
      if (response.status === 403 || response.status === 400) { 
          if (endpoint !== '/auth/refresh-token') { 
              throw new Error('CSRF token invalid or expired'); 
          }
      }

      const errorData = await response.json(); 
      const errorMessage = errorData?.error || `API request failed with status ${response.status}`;
      throw new Error(errorMessage);
  }

  return response.json() as Promise<T>; // Or response.text() if needed
}


export const authApi = {
  getUser: async (): Promise<AppUser | null> => {
      return apiRequest<AppUser | null>('/auth/user');
  },

  login: async (credentials: any): Promise<AuthResponse> => {
      return apiRequest<AuthResponse>('/auth/login', 'POST', credentials);
  },

  signup: async (credentials: any): Promise<AuthResponse> => {
      return apiRequest<AuthResponse>('/auth/signup', 'POST', credentials);
  },

  logout: async (): Promise<AuthResponse> => {
      return apiRequest<AuthResponse>('/auth/logout', 'POST');
  },

  forgotPassword: async (email: string): Promise<AuthResponse> => {
      return apiRequest<AuthResponse>('/auth/forgot-password', 'POST', { email });
  },

  resetPassword: async (password: string, token: string): Promise<AuthResponse> => {
      return apiRequest<AuthResponse>('/auth/reset-password', 'POST', { password, token });
  },

  refreshToken: async (): Promise<RefreshResponse> => {
      return apiRequest<RefreshResponse>('/auth/refresh-token', 'POST');
  }
};

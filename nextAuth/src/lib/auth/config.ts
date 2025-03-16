// Define how links should be formatted
export const AUTH_CONFIG = {
    // Set to empty string if your app is mounted at /auth already
    basePath: '',
    
    // Path builder function that handles the base path
    buildPath: (path: string) => {
      // Strip leading slash if present
      const cleanPath = path.startsWith('/') ? path.substring(1) : path;
      return `${AUTH_CONFIG.basePath}/${cleanPath}`;
    },
    
    // Auth routes
    routes: {
      login: 'login',
      signup: 'signup',
      forgotPassword: 'forgot-password',
      resetPassword: 'reset-password',
      confirmation: 'confirmation',
      signupSuccess: 'signup-success',
      resetPasswordSent: 'reset-password-sent',
      success: 'success',
    }
  };
  
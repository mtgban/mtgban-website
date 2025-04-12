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
    pricing: 'pricing',
    search: 'search',
    account: 'account',
  },

  // Custom pages
  pages: {
    signup: '/auth/signup',
    login: '/auth/login',
    forgotPassword: '/auth/forgot-password',
    resetPassword: '/auth/reset-password',
    confirmation: '/auth/confirmation',
  },

  // Custom session options
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // 24 hours
  },

  // Custom callbacks
  callbacks: {
    async session({ session, user }: { session: any, user: any }) {
      if (user) {
        session.user.id = user.id;
      }
      return session;
    },
  },
};

export default AUTH_CONFIG;


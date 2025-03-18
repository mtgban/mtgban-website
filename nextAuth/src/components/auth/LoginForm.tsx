// src/components/auth/LoginForm.tsx
import React, { useState, FormEvent, useEffect } from 'react';
import { useRouter } from 'next/router';
import { MailIcon, LockIcon } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import AuthLink from './AuthLink';

export interface LoginFormProps {
  redirectTo?: string;
}

const LoginForm: React.FC<LoginFormProps> = ({ redirectTo }) => {
  // Get auth context and router
  const { login, loading, error, clearError } = useAuth();
  const router = useRouter();

  // Form state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Animation state
  const [formVisible, setFormVisible] = useState(false);

  useEffect(() => {
    clearError();
    setLocalError(null);
  }, [email, password, clearError, setLocalError]);


  // Show form with animation after component mounts
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  // Handle form submission
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    // Clear any previous errors
    clearError();
    setLocalError(null);

    // Client-side validation
    if (!email || !password) {
      setLocalError('Please enter your email and password');
      return;
    }

    try {
      // Call login function from auth context
      const success = await login(email, password, rememberMe);

      if (success) {
        // Navigate to success page with redirect destination
        const destination = redirectTo || router.query.return_to?.toString() || '/';
        router.push({
          pathname: '/auth/success',
          query: {
            redirectTo: destination,
            message: 'You have successfully logged in.'
          }
        });
      } else {
        // Only set error if login returned false but didn't throw an error
        setLocalError('Login failed. Please check your credentials.');
      }
    } catch (err) {
      // This will only execute if an exception was thrown during login
      setLocalError(err instanceof Error ? err.message : 'An unexpected error occurred');
    }
  };

  const displayError = error || localError;

  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <div className="auth-header">
        <h1 className="auth-title">Welcome Back</h1>
        <p className="auth-subtitle">Log in to your account to continue</p>
      </div>

      {displayError && (
        <div className="auth-message error-message" role="alert">
          <span>{displayError}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group">
          <label htmlFor="email" className="form-label">
            Email Address
          </label>
          <div className="input-wrapper">
            <MailIcon className="form-icon" />
            <input
              id="email"
              type="email"
              className="form-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              required
              disabled={loading}
              autoComplete="email"
            />
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="password" className="form-label">
            Password
          </label>
          <div className="input-wrapper">
            <LockIcon className="form-icon" />
            <input
              id="password"
              type="password"
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              disabled={loading}
              autoComplete="current-password"
            />
          </div>
        </div>

        <div className="form-check">
          <input
            id="rememberMe"
            type="checkbox"
            className="form-check-input"
            checked={rememberMe}
            onChange={(e) => setRememberMe(e.target.checked)}
            disabled={loading}
          />
          <label htmlFor="rememberMe" className="form-check-label">
            Remember me for 30 days
          </label>
        </div>

        <button
          type="submit"
          className="btn btn-primary btn-block"
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="spinner"></span>
              <span>Logging in...</span>
            </>
          ) : (
            'Log In'
          )}
        </button>
      </form>

      <div className="auth-links">
        <AuthLink href="/auth/forgot-password">
          Forgot your password?
        </AuthLink>
        <p>
          Don't have an account?{' '}
          <AuthLink href="/auth/signup">
            Sign up
          </AuthLink>
        </p>
      </div>
    </div>
  );
};

export default LoginForm;

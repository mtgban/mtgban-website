// src/components/auth/LoginForm.tsx
import React, { useState, FormEvent, useEffect, useRef } from 'react';
import { useRouter } from 'next/router';
import { MailIcon, LockIcon, ArrowLeftIcon, CheckCircleIcon, AlertCircleIcon } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import AuthLink from '@/components/auth/AuthLink';

export interface LoginFormProps {
  redirectTo?: string;
}

export default function LoginForm({ redirectTo }: LoginFormProps) {
  // Get auth context and router
  const { login, loading, error, clearError } = useAuth();
  const router = useRouter();
  
  // Extract email from query parameters if available (for pre-filling)
  const urlEmail = router.query.email as string | undefined;

  // Form state - initialize email from URL if available
  const [email, setEmail] = useState(urlEmail || '');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Message transitions
  const [status, setStatus] = useState('idle'); // 'idle' | 'loading' | 'success' | 'error'
  const [message, setMessage] = useState('');
  const [messageTransition, setMessageTransition] = useState(''); // '' | 'entering' | 'exiting'
  const messageRef = useRef(null);
  
  // Animation state
  const [formVisible, setFormVisible] = useState(false);

  // Handle message transitions
  useEffect(() => {
    if (status !== 'idle' && messageTransition === '') {
      // Start enter transition
      setMessageTransition('entering');
      
      // After a brief delay, remove the entering class
      setTimeout(() => {
        setMessageTransition('');
      }, 50);
    }
  }, [status, message]);

  // Function to change message with transition
  const changeMessage = (newStatus: React.SetStateAction<string>, newMessage: React.SetStateAction<string>) => {
    // If we already have a message, fade it out first
    if (status !== 'idle') {
      setMessageTransition('exiting');
      
      // After exit animation completes, change the message and start entry animation
      setTimeout(() => {
        setStatus(newStatus);
        setMessage(newMessage);
        setMessageTransition('entering');
        
        // Remove entering class after brief delay
        setTimeout(() => {
          setMessageTransition('');
        }, 50);
      }, 300);
    } else {
      // No existing message, just set the new one
      setStatus(newStatus);
      setMessage(newMessage);
    }
  };

  // Clear errors when form data changes
  useEffect(() => {
    if (error || localError) {
      clearError();
      setLocalError(null);
    }
  }, [email, password, clearError, error]);

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
      changeMessage('error', 'Please enter your email and password');
      return;
    }

    // Show loading state
    changeMessage('loading', 'Logging in...');

    try {
      // Call login function from auth context
      const success = await login(email, password, rememberMe);

      if (success) {
        // Show success message with animation
        changeMessage('success', 'Login successful! Redirecting...');
        
        // Get redirect destination
        const destination = redirectTo || router.query.return_to?.toString() || '/home';
        
        // Brief delay to show the success message
        setTimeout(() => {
          router.push(destination);
        }, 1500);
      } else {
        // Only set error if login returned false but didn't throw an error
        changeMessage('error', 'Login failed. Please check your credentials.');
      }
    } catch (err) {
      // This will only execute if an exception was thrown during login
      changeMessage('error', err instanceof Error ? err.message : 'An unexpected error occurred');
    }
  };

  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <div className="auth-back-container">
        <AuthLink href="/home" className="back-link">
          <ArrowLeftIcon size={16} />
          Back to Home
        </AuthLink>
      </div>
      
      <div className="auth-header">
        <h1 className="auth-title">Welcome To MTGBAN</h1>
        <p className="auth-subtitle">Log in to your account to continue</p>
      </div>

      {/* Dynamic message based on login status */}
      {status !== 'idle' && (
        <div 
          ref={messageRef}
          className={`auth-message ${status}-message ${messageTransition}`} 
          role={status === 'error' ? 'alert' : 'status'}
        >
          {status === 'loading' && <span className="spinner"></span>}
          {status === 'success' && <CheckCircleIcon className="icon-success" size={18} />}
          {status === 'error' && <AlertCircleIcon className="icon-error" size={18} />}
          <span>{message}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="auth-form" name="login-form">
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
              disabled={loading || status === 'success'}
              autoComplete="username email"
              name="email"
              autoFocus={!email} // Auto-focus if email isn't pre-filled
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
              disabled={loading || status === 'success'}
              autoComplete="current-password"
              name="password"
              autoFocus={!!email} // Auto-focus if email is pre-filled
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
            disabled={loading || status === 'success'}
            name="remember-me"
          />
          <label htmlFor="rememberMe" className="form-check-label">
            Remember me
          </label>
        </div>

        <button
          type="submit"
          className="btn btn-primary btn-block"
          disabled={loading || status === 'success'}
        >
          {loading || status === 'loading' ? (
            <>
              <span className="spinner"></span>
              <span>Logging in...</span>
            </>
          ) : status === 'success' ? (
            <>
              <CheckCircleIcon size={18} className="mr-2" />
              <span>Login Successful</span>
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
          <AuthLink href={`/auth/signup${email ? `?email=${encodeURIComponent(email)}` : ''}`}>
            Sign up
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
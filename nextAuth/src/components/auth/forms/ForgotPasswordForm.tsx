import React, { useState, FormEvent, useEffect } from 'react';
import { useRouter } from 'next/router';
import { MailIcon, ArrowLeftIcon } from 'lucide-react';
import AuthLink from './AuthLink';

export default function ForgotPasswordForm() {
  const router = useRouter();
  const urlError = router.query.error as string | undefined;
  const urlMessage = router.query.message as string | undefined;
  
  // Form state
  const [email, setEmail] = useState('');
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);
    
    if (urlError || urlMessage) {
      setError(urlMessage || 'An error occurred. Please try again.');
    }
    
    return () => clearTimeout(timer);
  }, [urlError, urlMessage]);
  
  // Clear error when email changes
  useEffect(() => {
    if (error && email) {
      setError(null);
    }
  }, [email, error]);
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (isSubmitting) return;
    
    // Validation
    if (!email) {
      setError('Please enter your email address');
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      // Send reset password request
      const response = await fetch('/next-api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Navigate to reset password sent page
        router.push({
          pathname: '/auth/reset-password-sent',
          query: { email },
        });
      } else {
        setError(data.error || 'Failed to send reset email. Please try again.');
      }
    } catch (err) {
      setError('An unexpected error occurred. Please try again.');
      console.error('Forgot password error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <div className="auth-back-container">
        <AuthLink href="/auth/login" className="back-link">
          <ArrowLeftIcon size={16} />
          Back to Login
        </AuthLink>
      </div>
      
      <h1 className="auth-title">Reset Password</h1>
      <p className="auth-subtitle">Enter your email to receive a password reset link</p>
      
      {error && (
        <div className="auth-message error-message" role="alert">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group">
          <label htmlFor="email" className="form-label">Email Address</label>
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
              disabled={isSubmitting}
              autoComplete="email"
            />
          </div>
        </div>
        
        <div className="form-group">
          <button 
            type="submit" 
            className="btn btn-primary btn-block" 
            disabled={isSubmitting || !email}
          >
            {isSubmitting ? (
              <>
                <span className="spinner"></span>
                Sending Reset Link...
              </>
            ) : 'Send Reset Link'}
          </button>
        </div>
      </form>
      
      <div className="auth-info">
        <p>We'll send you an email with a link to reset your password.</p>
        <p>If you don't receive an email within a few minutes, please check your spam folder.</p>
      </div>
      
      <div className="auth-links">
        <p>
          Remember your password?{' '}
          <AuthLink href="/auth/login">
            Log in
          </AuthLink>
        </p>
        <p>
          Don't have an account?{' '}
          <AuthLink href="/auth/signup">
            Sign up
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
// src/components/auth/ResetPasswordForm.tsx
import React, { useState, FormEvent } from 'react';
import { useRouter } from 'next/router';
import AuthLink from './AuthLink';

export default function ResetPasswordForm() {
  const router = useRouter();
  const { token } = router.query;
  
  // Form state
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Password validation
  const hasMinLength = password.length >= 8;
  const hasLetter = /[A-Za-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const isPasswordValid = hasMinLength && hasLetter && hasNumber;
  const passwordsMatch = password === confirmPassword;
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (isSubmitting) return;
    
    // Validation
    if (!password || !confirmPassword) {
      setError('Both fields are required');
      return;
    }
    
    if (!isPasswordValid) {
      setError('Please ensure your password meets all requirements');
      return;
    }
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    if (!token) {
      setError('Invalid or missing reset token');
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      // Use the API endpoint directly here
      const response = await fetch('/next-api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          password,
          token: token
        })
      });
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Failed to reset password');
      }
      
      // Redirect to success page
      router.push({
        pathname: '/success',
        query: {
          redirectTo: '/auth/login',
          message: 'Your password has been reset successfully. You can now log in with your new password.'
        }
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  // Show error if no token is provided
  if (router.isReady && !token) {
    return (
      <div className="auth-container">
        <h1 className="auth-title">Invalid Reset Link</h1>
        <div className="auth-message error-message" role="alert">
          The password reset link is invalid or has expired.
        </div>
        <div className="auth-links">
          <p>
            {/* FIXED: Text and link destination now match */}
            <AuthLink href="forgot-password">
              Forgot Password
            </AuthLink>
            {' '} - Request a new reset link.
          </p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="auth-container">
      <h1 className="auth-title">Set New Password</h1>
      <p className="auth-subtitle">Please enter your new password</p>
      
      {error && (
        <div className="auth-message error-message" role="alert">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group">
          <label htmlFor="password" className="form-label">New Password</label>
          <input
            id="password"
            type="password"
            className={`form-input ${password && !isPasswordValid ? 'error' : ''}`}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={isSubmitting}
          />
          <div className="form-hint">
            Password must:
            <ul style={{ margin: '0.5rem 0 0 1.5rem', padding: 0 }}>
              <li style={{ color: hasMinLength ? 'var(--success-color)' : 'var(--text-light)' }}>
                Be at least 8 characters
              </li>
              <li style={{ color: hasLetter ? 'var(--success-color)' : 'var(--text-light)' }}>
                Include at least one letter
              </li>
              <li style={{ color: hasNumber ? 'var(--success-color)' : 'var(--text-light)' }}>
                Include at least one number
              </li>
            </ul>
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
          <input
            id="confirmPassword"
            type="password"
            className={`form-input ${confirmPassword && !passwordsMatch ? 'error' : ''}`}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={isSubmitting}
          />
        </div>
        
        {/* Hidden input for token */}
        <input type="hidden" name="token" value={token as string} />
        
        <div className="form-group">
          <button 
            type="submit" 
            className="btn btn-primary btn-block" 
            disabled={isSubmitting || !isPasswordValid || !passwordsMatch}
          >
            {isSubmitting ? (
              <>
                <span className="form-loader"></span>
                Resetting Password...
              </>
            ) : 'Reset Password'}
          </button>
        </div>
      </form>
      
      <div className="auth-links">
        <p>
          Remember your password?{' '}
          <AuthLink href="login">
            Log in
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
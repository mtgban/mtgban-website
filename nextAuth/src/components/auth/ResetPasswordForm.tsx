import React, { useState, FormEvent, useEffect } from 'react';
import { useRouter } from 'next/router';
import { LockIcon, ArrowLeftIcon } from 'lucide-react';
import AuthLink from '@/components/auth/AuthLink';

interface ResetPasswordFormProps {
  token: string;
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
}

export default function ResetPasswordForm({ token, onSuccess, onError }: ResetPasswordFormProps) {
  const router = useRouter();
  const urlError = router.query.error as string | undefined;
  const urlMessage = router.query.message as string | undefined;
  
  // Form state
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  
  // Password validation
  const hasMinLength = password.length >= 8;
  const hasLetter = /[A-Za-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const isPasswordValid = hasMinLength && hasLetter && hasNumber;
  const passwordsMatch = password === confirmPassword && password !== '';
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);
    
    if (urlError || urlMessage) {
      setError(urlMessage || 'An error occurred. Please try again.');
    }
    
    return () => clearTimeout(timer);
  }, [urlError, urlMessage]);
  
  // Clear error when form fields change
  useEffect(() => {
    if (error) {
      setError(null);
    }
  }, [password, confirmPassword, error]);
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (isSubmitting) return;
    
    // Clear previous errors
    setError(null);
    
    // Validation
    if (!password) {
      const errorMsg = 'Please enter a new password';
      setError(errorMsg);
      if (onError) onError(errorMsg);
      return;
    }
    
    if (!confirmPassword) {
      const errorMsg = 'Please confirm your new password';
      setError(errorMsg);
      if (onError) onError(errorMsg);
      return;
    }
    
    if (!isPasswordValid) {
      const errorMsg = 'Password does not meet requirements';
      setError(errorMsg);
      if (onError) onError(errorMsg);
      return;
    }
    
    if (password !== confirmPassword) {
      const errorMsg = 'Passwords do not match';
      setError(errorMsg);
      if (onError) onError(errorMsg);
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      const response = await fetch('/next-api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password,
          token,
        }),
      });
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Failed to reset password');
      }
      
      const successMsg = 'Your password has been reset successfully';
      setSuccessMessage(successMsg);
      if (onSuccess) onSuccess(successMsg);
      
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMsg);
      if (onError) onError(errorMsg);
    } finally {
      setIsSubmitting(false);
    }
  };
  
  // If we have a success message, show only that
  if (successMessage) {
    return (
      <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
        <h1 className="auth-title">Password Reset Complete</h1>
        <div className="auth-message success-message" role="status">
          {successMessage}
        </div>
        <div className="auth-links">
          <p>
            You can now{' '}
            <AuthLink href="/auth/login">
              Log in
            </AuthLink>
            {' '}with your new password.
          </p>
        </div>
      </div>
    );
  }
  
  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <div className="auth-back-container">
        <AuthLink href="/auth/login" className="back-link">
          <ArrowLeftIcon size={16} />
          Back to Login
        </AuthLink>
      </div>
      
      <h1 className="auth-title">Reset Your Password</h1>
      <p className="auth-subtitle">Create a new password for your account</p>
      
      {error && (
        <div className="auth-message error-message" role="alert">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group">
          <label htmlFor="password" className="form-label">
            New Password
          </label>
          <div className="input-wrapper">
            <LockIcon className="form-icon" />
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
          </div>
          <div className="form-hint">
            <ul className="password-requirements">
              <li className={hasMinLength ? 'met' : ''}>
                Be at least 8 characters
              </li>
              <li className={hasLetter ? 'met' : ''}>
                Include at least one letter
              </li>
              <li className={hasNumber ? 'met' : ''}>
                Include at least one number
              </li>
            </ul>
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="confirmPassword" className="form-label">
            Confirm Password
          </label>
          <div className="input-wrapper">
            <LockIcon className="form-icon" />
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
          {confirmPassword && !passwordsMatch && (
            <div className="form-hint" style={{ color: 'var(--error-color)' }}>
              Passwords do not match
            </div>
          )}
        </div>
        
        <div className="form-group">
          <button 
            type="submit" 
            className="btn btn-primary btn-block" 
            disabled={isSubmitting || !isPasswordValid || !passwordsMatch}
          >
            {isSubmitting ? (
              <>
                <span className="spinner"></span>
                <span>Resetting Password...</span>
              </>
            ) : (
              'Reset Password'
            )}
          </button>
        </div>
      </form>
      
      <div className="auth-links">
        <p>
          Remember your password?{' '}
          <AuthLink href="/auth/login">
            Log in
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
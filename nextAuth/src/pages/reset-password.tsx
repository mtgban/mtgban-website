'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import AuthLink from '@/components/auth/AuthLink';

export default function ResetPasswordPage() {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [token, setToken] = useState('');
  
  const searchParams = useSearchParams();
  const errorMessage = searchParams?.get('error') || null;
  
  // Animation effect on mount
  useEffect(() => {
    // Small delay for animation
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);
    
    // Check URL for error messages and token
    if (errorMessage) {
      setError(errorMessage);
    }
    
    // Get token from URL
    const tokenParam = searchParams?.get('token') || '';
    if (tokenParam) {
      setToken(tokenParam);
    } else {
      const hashToken = window.location.hash.replace('#', '').split('=')[1];
      if (hashToken) {
        setToken(hashToken);
      }
    }
    
    return () => clearTimeout(timer);
  }, [errorMessage, searchParams]);
  
  // Password strength requirements
  const passwordRequirements = [
    { id: 'length', text: 'At least 8 characters', met: password.length >= 8 },
    { 
      id: 'letter', 
      text: 'Contains at least one letter', 
      met: /[a-zA-Z]/.test(password) 
    },
    { 
      id: 'number', 
      text: 'Contains at least one number', 
      met: /\d/.test(password) 
    }
  ];
  
  const showPasswordRequirements = password.length > 0;
  
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    
    // Basic client-side validation
    if (password !== confirmPassword) {
      setError("Passwords don't match");
      return;
    }
    
    // Check password requirements
    const allRequirementsMet = passwordRequirements.every(req => req.met);
    if (!allRequirementsMet) {
      setError("Please meet all password requirements");
      return;
    }
    
    setLoading(true);
  };
  
  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className={`auth-container ${isVisible ? 'visible' : ''}`}>
        <h1 className="auth-title">Reset Your Password</h1>
        <p className="auth-subtitle">Create a new secure password for your account</p>
        
        {error && (
          <div className="auth-message error-message">
            <svg className="icon-error" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12" y2="16"></line>
            </svg>
            {error}
          </div>
        )}
        
        {!token && (
          <div className="auth-message warning-message">
            <svg className="icon-warning" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
              <line x1="12" y1="9" x2="12" y2="13"></line>
              <line x1="12" y1="17" x2="12.01" y2="17"></line>
            </svg>
            Invalid or missing reset token. Please request a new password reset link.
          </div>
        )}
        
        <form className="auth-form" action="/auth/reset-password-submit" method="post" onSubmit={handleSubmit}>
          {/* Hidden token field */}
          <input type="hidden" name="token" value={token} />
          
          <div className="form-group">
            <label htmlFor="password" className="form-label">New Password</label>
            <div className="input-wrapper">
              <input
                id="password"
                type="password"
                name="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="form-input"
                placeholder="••••••••"
                required
                disabled={!token}
              />
              <svg className="form-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
            
            {/* Password requirements list */}
            <div className={`password-requirements-container ${showPasswordRequirements ? 'visible' : ''}`}>
              <ul className="password-requirements">
                {passwordRequirements.map((req) => (
                  <li key={req.id} className={req.met ? 'met' : ''}>
                    {req.text}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          
          <div className="form-group">
            <label htmlFor="confirm-password" className="form-label">Confirm New Password</label>
            <div className="input-wrapper">
              <input
                id="confirm-password"
                type="password"
                name="confirm-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="form-input"
                placeholder="••••••••"
                required
                disabled={!token}
              />
              <svg className="form-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
              </svg>
            </div>
          </div>
          
          <button type="submit" className="btn btn-primary btn-block" disabled={loading || !token}>
            {loading ? (
              <div className="loading-dots">
                <span></span>
                <span></span>
                <span></span>
              </div>
            ) : 'Reset Password'}
          </button>
        </form>
        
        <div className="auth-links">
          <div>
            <AuthLink href="/auth/login" className="link">
              Return to login
            </AuthLink>
          </div>
        </div>
      </div>
    </div>
  );
}
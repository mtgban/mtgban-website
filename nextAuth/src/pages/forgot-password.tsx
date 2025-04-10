'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import AuthLink from '@/components/auth/AuthLink';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  
  const searchParams = useSearchParams();
  const errorMessage = searchParams?.get('error') || null;
  
  // Animation effect on mount
  useEffect(() => {
    // Small delay for animation
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);
    
    // Check URL for error messages
    if (errorMessage) {
      setError(errorMessage);
    }
    
    return () => clearTimeout(timer);
  }, [errorMessage]);
  
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
  };
  
  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className={`auth-container ${isVisible ? 'visible' : ''}`}>
        <div className="auth-back-container">
          <AuthLink href="/auth/login" className="back-link">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
            Back to login
          </AuthLink>
        </div>
        
        <h1 className="auth-title">Reset Password</h1>
        <p className="auth-subtitle">Enter your email to receive a password reset link</p>
        
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
        
        <form className="auth-form" action="/auth/forgot-password-submit" method="post" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email" className="form-label">Email</label>
            <div className="input-wrapper">
              <input
                id="email"
                type="email"
                name="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="form-input"
                placeholder="name@example.com"
                required
              />
              <svg className="form-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                <polyline points="22,6 12,13 2,6"></polyline>
              </svg>
            </div>
          </div>
          
          <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
            {loading ? (
              <div className="loading-dots">
                <span></span>
                <span></span>
                <span></span>
              </div>
            ) : 'Send Reset Link'}
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
import React, { useState, useEffect } from 'react';
import AuthLink from './AuthLink';
import { MailIcon } from 'lucide-react';

interface ResetPasswordSentFormProps {
  email?: string;
  message?: string;
}

export default function ResetPasswordSentForm({ 
  email,
  message = "If an account exists with that email, we've sent password reset instructions."
}: ResetPasswordSentFormProps) {
  const [formVisible, setFormVisible] = useState(false);
  
  // Animation effect
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);
    
    return () => clearTimeout(timer);
  }, []);
  
  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <h1 className="auth-title">Check Your Email</h1>
      
      <div className="auth-message info-message" role="status">
        <MailIcon className="icon-mail" />
        <span>{message}</span>
      </div>
      
      {email && (
        <p className="auth-subtitle">
          We've sent a password reset link to <strong>{email}</strong>
        </p>
      )}
      
      <div className="auth-info">
        <h3>Next Steps:</h3>
        <ol>
          <li>Check your email inbox (and spam folder)</li>
          <li>Click the password reset link in the email</li>
          <li>Follow the instructions to create a new password</li>
        </ol>
      </div>
      
      <div className="auth-footer-info">
        <p>The password reset link will expire in 24 hours for security reasons.</p>
        <p>Didn't receive an email? Check your spam folder or try requesting another reset link.</p>
      </div>
      
      <div className="auth-links">
        <div className="auth-link-row">
          <AuthLink href="/auth/forgot-password">
            <button className="btn btn-secondary">
              Request New Link
            </button>
          </AuthLink>
          <AuthLink href="/auth/login">
            <button className="btn btn-primary">
              Return to Login
            </button>
          </AuthLink>
        </div>
      </div>
    </div>
  );
}
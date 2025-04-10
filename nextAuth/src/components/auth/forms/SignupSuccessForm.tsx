import React, { useState, useEffect } from 'react';
import AuthLink from './AuthLink';
import { CheckCircleIcon, MailIcon } from 'lucide-react';

interface SignupSuccessFormProps {
  email?: string;
  message?: string;
  showEmailVerification?: boolean;
}

export default function SignupSuccessForm({ 
  email,
  message = "Your account has been created successfully.",
  showEmailVerification = true
}: SignupSuccessFormProps) {
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
      <h1 className="auth-title">Account Created</h1>
      
      <div className="auth-message success-message" role="status">
        <CheckCircleIcon className="icon-success" />
        <span>{message}</span>
      </div>
      
      {showEmailVerification && (
        <>
          {email && (
            <p className="auth-subtitle">
              We've sent a verification email to <strong>{email}</strong>
            </p>
          )}
          
          <div className="auth-info">
            <h3>Next Steps:</h3>
            <ol>
              <li>Check your email inbox (and spam folder)</li>
              <li>Click the verification link in the email</li>
              <li>Once verified, you can log in to your account</li>
            </ol>
          </div>
          
          <div className="auth-message info-message" role="status">
            <MailIcon className="icon-mail" />
            <span>Please verify your email address to activate your account.</span>
          </div>
        </>
      )}
      
      <div className="auth-footer-info">
        <p>Thank you for joining MTGBAN! We're excited to have you as part of our community.</p>
      </div>
      
      <div className="auth-links">
        <div className="auth-link-row">
          <AuthLink href="/auth/login">
            <button className="btn btn-primary btn-block">
              Proceed to Login
            </button>
          </AuthLink>
        </div>
      </div>
    </div>
  );
}
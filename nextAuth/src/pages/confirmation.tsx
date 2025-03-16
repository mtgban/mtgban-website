// src/pages/confirmation.tsx
import React from 'react';
import AuthLink from '../components/auth/AuthLink';
import AuthLayout from '../components/auth/AuthLayout';

export default function ConfirmationPage() {
  return (
    <AuthLayout 
      title="Confirm Your Email" 
      description="Email confirmation page for MTGBAN"
    >
      <div className="auth-container">
        <h1 className="auth-title">Check Your Email</h1>
        
        <div className="auth-message info-message" role="status">
          Please check your email to verify your account.
        </div>
        
        <div className="auth-info">
          <h3>Next Steps:</h3>
          <ol>
            <li>Check your email inbox (and spam folder)</li>
            <li>Click the verification link in the email</li>
            <li>Once verified, you can log in to your account</li>
          </ol>
        </div>
        
        <div className="auth-links">
          <p>
            Return to{' '}
            <AuthLink href="/auth/login">
              Login
            </AuthLink>
          </p>
        </div>
      </div>
    </AuthLayout>
  );
}
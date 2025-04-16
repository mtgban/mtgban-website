// src/pages/signup-success.tsx
import React from 'react';
import AuthLink from '@/components/auth/AuthLink';
import AuthLayout from '@/components/auth/AuthLayout';

export default function SignupSuccessPage() {
  return (
    <AuthLayout 
      title="Signup Successful" 
      description="Account created successfully"
    >
      <div className="auth-container">
        <h1 className="auth-title">Account Created</h1>
        
        <div className="auth-message success-message" role="status">
          Your account has been created successfully.
        </div>
        
        <p className="auth-subtitle">
          Please check your email to verify your account.
          You'll need to verify your email before you can log in.
        </p>
        
        <div className="auth-links">
          <p>
            Already verified?{' '}
            <AuthLink href="/auth/login">
              Log in
            </AuthLink>
          </p>
        </div>
      </div>
    </AuthLayout>
  );
}
// src/pages/reset-password.tsx
import React from 'react';
import { useRouter } from 'next/router';
import AuthLayout from '../components/auth/AuthLayout';
import ResetPasswordForm from '../components/auth/ResetPasswordForm';

export default function ResetPasswordPage() {
  const router = useRouter();
  const { token, error } = router.query;
  
  const handleSuccess = (message: string) => {
    // Redirect to login page after a delay
    setTimeout(() => {
      router.push('/auth/login');
    }, 3000);
  };
  
  return (
    <AuthLayout 
      title="Reset Password" 
      description="Reset your password"
    >
      {token ? (
        <ResetPasswordForm 
          token={token as string} 
          onSuccess={handleSuccess}
        />
      ) : (
        <div className="auth-container">
          <h1 className="auth-title">Invalid Reset Link</h1>
          <div className="auth-message error-message" role="alert">
            This password reset link is invalid or has expired.
          </div>
          <div className="auth-links">
            <p>
              Need a new reset link?{' '}
              <a href="/auth/forgot-password">Request a new one</a>
            </p>
          </div>
        </div>
      )}
    </AuthLayout>
  );
}
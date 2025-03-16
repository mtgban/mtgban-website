// src/pages/reset-password-sent.tsx
import React from 'react';
import { useRouter } from 'next/router';
import AuthLayout from '../components/auth/AuthLayout';
import ResetPasswordSentForm from '../components/auth/ResetPasswordSentForm';

export default function ResetPasswordSentPage() {
  const router = useRouter();
  const { email } = router.query;
  
  return (
    <AuthLayout 
      title="Reset Email Sent" 
      description="Password reset instructions sent"
    >
      <ResetPasswordSentForm 
        email={email as string} 
        message="If an account exists with that email, we've sent password reset instructions."
      />
    </AuthLayout>
  );
}
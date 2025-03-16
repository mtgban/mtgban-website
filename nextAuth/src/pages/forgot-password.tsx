// src/pages/forgot-password.tsx
import React from 'react';
import { useRouter } from 'next/router';
import ForgotPasswordForm from '../components/auth/ForgotPasswordForm';
import AuthLayout from '../components/auth/AuthLayout';

export default function ForgotPasswordPage() {
  const router = useRouter();
  
  return (
    <AuthLayout 
      title="Reset Password" 
      description="Reset your account password"
    >
      <ForgotPasswordForm />
    </AuthLayout>
  );
}
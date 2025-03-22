'use client'

import React from 'react';
import { useRouter } from 'next/navigation';
import ForgotPasswordForm from '@/components/auth/ForgotPasswordForm';
import AuthLayout from '@/components/auth/AuthLayout';

// Forgot password page
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
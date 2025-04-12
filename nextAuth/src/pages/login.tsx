'use client'

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import LoginForm from '@/components/auth/forms/LoginForm';
import { useAuth } from '@/context/AuthProvider';
import AuthLayout from '@/components/auth/AuthLayout';
import { AuthProvider } from '@/context/AuthContext';

export interface LoginPageProps {
  redirectTo?: string;
}

export default function LoginPage() {
  const router = useRouter();
  const { user, loading } = useAuth();
  const redirectTo = router.query.redirectTo as string | undefined;

  // Redirect if already logged in
  useEffect(() => {
    if (user && !loading) {
      const destination = redirectTo || '/home';
      router.push(destination);
    }
  }, [user, loading, router, redirectTo]);

  // Don't render the form if already logged in or still loading
  if (loading || user) {
    return (
      <div className="auth-container visible">
        <div className="auth-loading">
          <div className="spinner large"></div>
          <p>{user ? 'Redirecting...' : 'Loading...'}</p>
        </div>
      </div>
    );
  }

  return (
    <AuthLayout
      title="Login"
      description="Sign in to your MTGBAN account"
    >
      <AuthProvider>
        <LoginForm redirectTo={redirectTo} />
      </AuthProvider>
    </AuthLayout>
  );
}
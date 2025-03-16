import React from 'react';
import AuthLink from './AuthLink';
import { useRouter } from 'next/router';
import { User } from '@/context/AuthContext';

interface AuthSuccessProps {
  user: User | null;
  message: string;
  redirectTo?: string;
  redirectTimeout?: number; 
  title?: string | null;
  linkText?: string | null;
  linkHref?: string | null;
}

export default function AuthSuccess({ 
  user, 
  message, 
  redirectTo = '/', 
  redirectTimeout = 3000 

}: AuthSuccessProps) {
  const router = useRouter();
  const [countdown, setCountdown] = React.useState(redirectTimeout / 1000);

  // Auto-redirect after timeout
  React.useEffect(() => {
    const timer = setTimeout(() => {
      router.push(redirectTo);
    }, redirectTimeout);

    // Countdown timer
    const countdownInterval = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          clearInterval(countdownInterval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      clearTimeout(timer);
      clearInterval(countdownInterval);
    };
  }, [router, redirectTo, redirectTimeout]);

  return (
    <div className="auth-container">
      <h1 className="auth-title">Authentication Successful</h1>
      
      <div className="auth-message success-message" role="status">
        {message}
      </div>
      
      {user && (
        <div className="user-welcome">
          <p>Welcome, {user.email}!</p>
          {user.tier && <p>Account tier: {user.tier}</p>}
        </div>
      )}
      
      <div className="redirect-message">
        <p>
          Redirecting to dashboard in {countdown} seconds...
        </p>
        <button 
          onClick={() => router.push(redirectTo)} 
          className="btn btn-primary btn-block"
        >
          Continue Now
        </button>
      </div>
      
      <div className="auth-links">
        <p>
          <AuthLink href="/auth/settings">
            Manage account settings
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
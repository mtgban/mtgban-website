'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import AuthLink from '@/components/auth/AuthLink';

export default function SuccessPage() {
  const [countdown, setCountdown] = useState(3);
  const [isVisible, setIsVisible] = useState(false);
  
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams?.get('redirectTo') || '/';
  const message = searchParams?.get('message') || 'Your action was completed successfully.';
  
  // Animation effect on mount
  useEffect(() => {
    // Small delay for animation
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);
    
    return () => clearTimeout(timer);
  }, []);
  
  // Countdown to auto-redirect
  useEffect(() => {
    if (countdown <= 0) {
      router.push(redirectTo);
      return;
    }
    
    const timer = setTimeout(() => {
      setCountdown(countdown - 1);
    }, 1000);
    
    return () => clearTimeout(timer);
  }, [countdown, redirectTo, router]);
  
  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className={`auth-container ${isVisible ? 'visible' : ''}`}>
        <h1 className="auth-title">Success</h1>
        
        <div className="auth-message success-message">
          <svg className="icon-success" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <polyline points="22 4 12 14.01 9 11.01"></polyline>
          </svg>
          {message}
        </div>
        
        <p className="auth-subtitle">
          Redirecting you automatically in {countdown} second{countdown !== 1 ? 's' : ''}...
        </p>
        
        <AuthLink href={redirectTo} className="btn btn-primary btn-block">
          Continue Now
        </AuthLink>
      </div>
    </div>
  );
}
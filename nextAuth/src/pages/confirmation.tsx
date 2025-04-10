'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import AuthLink from '@/components/auth/AuthLink';

export default function ConfirmationPage() {
  const [isVisible, setIsVisible] = useState(false);
  
  const searchParams = useSearchParams();
  const email = searchParams?.get('email') || '';
  const message = searchParams?.get('message') || 'Please check your email to verify your account.';
  
  // Mask email for privacy/security
  const maskedEmail = email ? maskEmail(email) : '';
  
  // Animation effect on mount
  useEffect(() => {
    // Small delay for animation
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);
    
    return () => clearTimeout(timer);
  }, []);
  
  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className={`auth-container ${isVisible ? 'visible' : ''}`}>
        <h1 className="auth-title">Check Your Email</h1>
        
        <div className="auth-message info-message">
          <svg className="icon-info" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
          {message}
        </div>
        
        {email && (
          <div className="user-welcome">
            <p>We've sent a verification email to:</p>
            <p className="auth-title" style={{ fontSize: '1.5rem', marginTop: '0.5rem' }}>{maskedEmail}</p>
          </div>
        )}
        
        <div className="auth-info" style={{ marginTop: '1rem' }}>
          <p>Please check your inbox and follow the instructions in the email to verify your account.</p>
          <p style={{ marginTop: '0.5rem' }}>If you don't see the email, check your spam folder.</p>
        </div>
        
        <div className="auth-links">
          <AuthLink href="/auth/login" className="btn btn-secondary btn-block">
            Return to login
          </AuthLink>
        </div>
      </div>
    </div>
  );
}

// Utility function to mask email for privacy
function maskEmail(email: string): string {
  if (!email || !email.includes('@')) return email;
  
  const [localPart, domain] = email.split('@');
  
  // Mask local part (username)
  let maskedLocal: string;
  if (localPart.length <= 2) {
    maskedLocal = '*'.repeat(localPart.length);
  } else {
    maskedLocal = localPart[0] + '*'.repeat(localPart.length - 2) + localPart[localPart.length - 1];
  }
  
  // Mask domain (except TLD)
  const domainParts = domain.split('.');
  let maskedDomain: string;
  
  if (domainParts.length <= 1) {
    maskedDomain = domain; // Unusual case, don't mask
  } else {
    const tld = domainParts.pop(); // Get the TLD (.com, .org, etc.)
    const domainName = domainParts.join('.'); // Rejoin remaining parts
    
    if (domainName.length <= 2) {
      maskedDomain = '*'.repeat(domainName.length) + '.' + tld;
    } else {
      maskedDomain = domainName[0] + '*'.repeat(domainName.length - 2) + domainName[domainName.length - 1] + '.' + tld;
    }
  }
  
  return `${maskedLocal}@${maskedDomain}`;
}
import React, { useState, useEffect } from 'react';
import AuthLink from './AuthLink';
import { MailIcon, CheckCircleIcon, AlertCircleIcon } from 'lucide-react';

interface ConfirmationFormProps {
  email?: string;
  message?: string;
  token?: string;
  redirectUrl?: string;
}

export default function ConfirmationForm({ 
  email, 
  message, 
  token,
  redirectUrl = '/auth/login' 
}: ConfirmationFormProps) {
  // UI state
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  
  // Animation effect
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);
    
    return () => clearTimeout(timer);
  }, []);
  
  // Handle token verification if present
  useEffect(() => {
    if (token && !isVerifying && !verificationResult) {
      verifyEmailToken(token);
    }
  }, [token, isVerifying, verificationResult]);
  
  const verifyEmailToken = async (token: string) => {
    setIsVerifying(true);
    
    try {
      const response = await fetch('/next-api/auth/verify-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });
      
      const data = await response.json();
      
      setVerificationResult({
        success: data.success,
        message: data.success 
          ? 'Your email has been verified successfully. You can now log in.'
          : (data.error || 'Failed to verify email. Please try again or contact support.')
      });
      
    } catch (err) {
      setVerificationResult({
        success: false,
        message: 'An error occurred during verification. Please try again later.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const displayMessage = message || 'Please check your email to verify your account.';
  
  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      {isVerifying ? (
        <>
          <h1 className="auth-title">Verifying Your Email</h1>
          <div className="auth-loading">
            <div className="spinner large"></div>
            <p>Verifying your email address...</p>
          </div>
        </>
      ) : verificationResult ? (
        <>
          <h1 className="auth-title">
            {verificationResult.success ? 'Email Verified' : 'Verification Failed'}
          </h1>
          <div className={`auth-message ${verificationResult.success ? 'success-message' : 'error-message'}`} role={verificationResult.success ? 'status' : 'alert'}>
            {verificationResult.success ? (
              <CheckCircleIcon className="icon-success" />
            ) : (
              <AlertCircleIcon className="icon-error" />
            )}
            <span>{verificationResult.message}</span>
          </div>
          <div className="auth-links">
            <AuthLink href={redirectUrl}>
              <button className="btn btn-primary btn-block">
                {verificationResult.success ? 'Proceed to Login' : 'Back to Login'}
              </button>
            </AuthLink>
          </div>
        </>
      ) : (
        <>
          <h1 className="auth-title">Check Your Email</h1>
          
          <div className="auth-message info-message" role="status">
            <MailIcon className="icon-mail" />
            <span>{displayMessage}</span>
          </div>
          
          {email && (
            <p className="auth-subtitle">
              We've sent a verification email to <strong>{email}</strong>
            </p>
          )}
          
          <div className="auth-info">
            <h3>Next Steps:</h3>
            <ol>
              <li>Check your email inbox (and spam folder)</li>
              <li>Click the verification link in the email</li>
              <li>Once verified, you can log in to your account</li>
            </ol>
          </div>
          
          <div className="auth-footer-info">
            <p>Didn't receive an email? Check your spam folder or try signing up again with a different email address.</p>
          </div>
          
          <div className="auth-links">
            <p>
              Return to{' '}
              <AuthLink href="/auth/login">
                Login
              </AuthLink>
            </p>
          </div>
        </>
      )}
    </div>
  );
}
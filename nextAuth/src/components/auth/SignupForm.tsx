import React, { useState, FormEvent, useEffect, useRef } from 'react';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { useLegalNavigation } from '@/lib/legal';
import { UserIcon, MailIcon, LockIcon, ArrowLeftIcon, CheckCircleIcon, AlertCircleIcon} from 'lucide-react';
import AuthLink from './AuthLink';
import { authService } from '@/lib/auth/authService';

export interface SignupFormProps {
  redirectTo?: string;
}

export default function SignupForm({ redirectTo }: SignupFormProps) {
  const router = useRouter();
  const { goToCasualTerms, goToCasualPrivacy } = useLegalNavigation();
  const urlError = router.query.error as string | undefined;
  const urlMessage = router.query.message as string | undefined;
  const urlEmail = router.query.email as string | undefined;
  
  // Form state - initialize email from URL if available
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState(urlEmail || '');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [termsAccepted, setTermsAccepted] = useState(false);
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formVisible, setFormVisible] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);
  
  // Message transition states
  const [status, setStatus] = useState('idle'); // 'idle' | 'loading' | 'success' | 'error'
  const [message, setMessage] = useState('');
  const [messageTransition, setMessageTransition] = useState(''); // '' | 'entering' | 'exiting'
  const messageRef = useRef(null);
  
  // Password validation states
  const hasMinLength = password.length >= 8;
  const hasLetter = /[A-Za-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const isPasswordValid = hasMinLength && hasLetter && hasNumber;
  const passwordsMatch = password === confirmPassword && password !== '';
  
  // Determine if we should show password requirements and confirm field
  const showPasswordRequirements = passwordFocused || password.length > 0;
  const showConfirmPassword = passwordFocused || password.length > 0;
  
  useEffect(() => {
    const timer = setTimeout(() => {
      setFormVisible(true);
    }, 100);
    
    if (urlError || urlMessage) {
      changeMessage('error', urlMessage || 'An error occurred. Please try again.');
    }
    
    return () => clearTimeout(timer);
  }, [urlError, urlMessage]);
  
  // Clear error when form fields change
  useEffect(() => {
    if (error) {
      setError(null);
    }
  }, [fullName, email, password, confirmPassword, termsAccepted]);
  
  // Handle message transitions
  useEffect(() => {
    if (status !== 'idle' && messageTransition === '') {
      // Start enter transition
      setMessageTransition('entering');
      
      // After a brief delay, remove the entering class
      setTimeout(() => {
        setMessageTransition('');
      }, 50);
    }
  }, [status, message]);
  
  // Function to change message with transition
  const changeMessage = (newStatus: React.SetStateAction<string>, newMessage: React.SetStateAction<string>) => {
    // If we already have a message, fade it out first
    if (status !== 'idle') {
      setMessageTransition('exiting');
      
      // After exit animation completes, change the message and start entry animation
      setTimeout(() => {
        setStatus(newStatus);
        setMessage(newMessage);
        setMessageTransition('entering');
        
        // Remove entering class after brief delay
        setTimeout(() => {
          setMessageTransition('');
        }, 50);
      }, 300);
    } else {
      // No existing message, just set the new one
      setStatus(newStatus);
      setMessage(newMessage);
    }
  };
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (isSubmitting) return;
    
    // Validation
    if (!fullName) {
      changeMessage('error', 'Please enter your full name');
      return;
    }
    
    if (!email) {
      changeMessage('error', 'Please enter your email address');
      return;
    }
    
    if (!password) {
      changeMessage('error', 'Please enter a password');
      return;
    }
    
    if (!isPasswordValid) {
      changeMessage('error', 'Please ensure your password meets all requirements');
      return;
    }
    
    if (password !== confirmPassword) {
      changeMessage('error', 'Passwords do not match');
      return;
    }
    
    if (!termsAccepted) {
      changeMessage('error', 'You must accept the Terms of Service');
      return;
    }
    
    setIsSubmitting(true);
    changeMessage('loading', 'Creating your account...');
    
    try {
      const result = await authService.signup({
        email,
        password,
        fullName,
        confirmPassword
      });
      
      if (result.success) {
        // Show success animation
        changeMessage('success', 'Account created successfully!');
        
        // Wait for animation to complete before redirecting
        setTimeout(() => {
          const destination = redirectTo || '/home';
          router.replace(destination);
        }, 1500);
      } else {
        changeMessage('error', result.error || 'Signup failed');
        setIsSubmitting(false);
      }
    } catch (err) {
      changeMessage('error', 'An unexpected error occurred. Please try again.');
      console.error('Signup error:', err);
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className={`auth-container ${formVisible ? 'visible' : ''}`}>
      <div className="auth-back-container">
        <AuthLink href="/home" className="back-link">
          <ArrowLeftIcon size={16} />
          Back to Home
        </AuthLink>
      </div>
      
      <h1 className="auth-title">Create Account</h1>
      <p className="auth-subtitle">Sign up to get started</p>
      
      {/* Dynamic message based on signup status */}
      {status !== 'idle' && (
        <div 
          ref={messageRef}
          className={`auth-message ${status}-message ${messageTransition}`} 
          role={status === 'error' ? 'alert' : 'status'}
        >
          {status === 'loading' && <span className="spinner"></span>}
          {status === 'success' && <CheckCircleIcon className="icon-success" size={18} />}
          {status === 'error' && <AlertCircleIcon className="icon-error" size={18} />}
          <span>{message}</span>
        </div>
      )}
      
      <form onSubmit={handleSubmit} className={`auth-form ${isSubmitting ? 'form-control-transition disabled' : ''}`} name="signup-form">
        <div className="form-group">
          <label htmlFor="fullName" className="form-label">Full Name</label>
          <div className="input-wrapper">
            <UserIcon className="form-icon" />
            <input
              id="fullName"
              type="text"
              className="form-input"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="John Doe"
              required
              disabled={isSubmitting}
              autoComplete="name"
              name="fullName"
              autoFocus={!email} // Auto-focus if email isn't pre-filled
            />
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="email" className="form-label">Email Address</label>
          <div className="input-wrapper">
            <MailIcon className="form-icon" />
            <input
              id="email"
              type="email"
              className="form-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              required
              disabled={isSubmitting}
              autoComplete="username email"
              name="email"
              autoFocus={!!email && !fullName} // Auto-focus if email is pre-filled but name isn't
            />
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="password" className="form-label">Password</label>
          <div className="input-wrapper">
            <LockIcon className="form-icon" />
            <input
              id="password"
              type="password"
              className={`form-input ${password && !isPasswordValid ? 'error' : ''}`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onFocus={() => setPasswordFocused(true)}
              placeholder="••••••••"
              required
              disabled={isSubmitting}
              autoComplete="new-password"
              name="password"
            />
          </div>
          
          {/* Password requirements */}
          <div className={`form-hint password-requirements-container ${showPasswordRequirements ? 'visible' : ''}`}>
            <ul className="password-requirements">
              <li className={hasMinLength ? 'met' : ''}>
                Be at least 8 characters
              </li>
              <li className={hasLetter ? 'met' : ''}>
                Include at least one letter
              </li>
              <li className={hasNumber ? 'met' : ''}>
                Include at least one number
              </li>
            </ul>
          </div>
        </div>
        
        {/* Confirm password field */}
        <div className={`form-group confirm-password-group ${showConfirmPassword ? 'visible' : ''}`}>
          <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
          <div className="input-wrapper">
            <LockIcon className="form-icon" />
            <input
              id="confirmPassword"
              type="password"
              className={`form-input ${confirmPassword && !passwordsMatch ? 'error' : ''}`}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              required
              disabled={isSubmitting}
              autoComplete="new-password"
              name="confirmPassword"
            />
          </div>
          {confirmPassword && !passwordsMatch && (
            <div className="form-hint" style={{ color: 'var(--error-color)' }}>
              Passwords do not match
            </div>
          )}
        </div>
        
        <div className="form-check">
          <input
            id="terms"
            type="checkbox"
            className="form-check-input"
            checked={termsAccepted}
            onChange={(e) => setTermsAccepted(e.target.checked)}
            required
            disabled={isSubmitting}
            name="terms"
          />
          <label htmlFor="terms" className="form-check-label">
            I accept the{' '}
            <Link href="/legal/casual-terms">
              Terms of Service
            </Link>{' '}
              and{' '}
            <Link href="/legal/casual-privacy">
              Privacy Policy
            </Link>
          </label>
        </div>
        
        <div className="form-group">
          <button 
            type="submit" 
            className="btn btn-primary btn-block" 
            disabled={isSubmitting || !isPasswordValid || !passwordsMatch || !termsAccepted}
          >
            {isSubmitting ? (
              <>
                <span className="spinner"></span>
                {status === 'success' ? 'Account Created!' : 'Creating Account...'}
              </>
            ) : 'Sign Up'}
          </button>
        </div>
      </form>
      
      <div className="auth-links">
        <p>
          Already have an account?{' '}
          <AuthLink href={`/auth/login${email ? `?email=${encodeURIComponent(email)}` : ''}`}>
            Log in
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
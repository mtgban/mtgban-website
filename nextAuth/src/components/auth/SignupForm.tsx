import React, { useState, FormEvent } from 'react';
import { useRouter } from 'next/router';
import AuthLink from './AuthLink';
import { authService } from '@/lib/auth/authService';

export interface SignupFormProps {
  redirectTo?: string;
}

export default function SignupForm({ redirectTo }: SignupFormProps) {
  const router = useRouter();
  
  // Form state
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [termsAccepted, setTermsAccepted] = useState(false);
  
  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  
  // Password validation
  const hasMinLength = password.length >= 8;
  const hasLetter = /[A-Za-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const isPasswordValid = hasMinLength && hasLetter && hasNumber;
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (isSubmitting) return;
    
    // Validation
    if (!fullName || !email || !password) {
      setError('All fields are required');
      return;
    }
    
    if (!isPasswordValid) {
      setError('Please ensure your password meets all requirements');
      return;
    }
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    if (!termsAccepted) {
      setError('You must accept the Terms of Service');
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      const result = await authService.signup({
        email,
        password,
        fullName,
        confirmPassword
      });
      
      if (result.success) {
        if (result.emailConfirmationRequired) {
          // Redirect to confirmation page
          router.push({
            pathname: '/auth/confirmation',
            query: { email }
          });
        } else {
          // Redirect to success page
          const destination = redirectTo || '/';
          router.push({
            pathname: '/auth/success',
            query: { 
              redirectTo: destination,
              message: 'Your account has been created successfully!' 
            }
          });
        }
      } else {
        setError(result.error || 'Signup failed');
      }
    } catch (err) {
      setError('An unexpected error occurred. Please try again.');
      console.error('Signup error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };
  
  // If we have a success message, show only that
  if (successMessage) {
    return (
      <div className="auth-container">
        <h1 className="auth-title">Account Created</h1>
        <div className="auth-message success-message" role="status">
          {successMessage}
        </div>
        <div className="auth-links">
          <p>
            Ready to login?{' '}
            <AuthLink href="/auth/login">
              Sign in
            </AuthLink>
          </p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="auth-container">
      <h1 className="auth-title">Create Account</h1>
      <p className="auth-subtitle">Sign up to get started</p>
      
      {error && (
        <div className="auth-message error-message" role="alert">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="auth-form">
        <div className="form-group">
          <label htmlFor="fullName" className="form-label">Full Name</label>
          <input
            id="fullName"
            type="text"
            className="form-input"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            placeholder="John Doe"
            required
            disabled={isSubmitting}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="email" className="form-label">Email Address</label>
          <input
            id="email"
            type="email"
            className="form-input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="your@email.com"
            required
            disabled={isSubmitting}
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="password" className="form-label">Password</label>
          <input
            id="password"
            type="password"
            className={`form-input ${password && !isPasswordValid ? 'error' : ''}`}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={isSubmitting}
          />
          <div className="form-hint">
            Password must:
            <ul style={{ margin: '0.5rem 0 0 1.5rem', padding: 0 }}>
              <li style={{ color: hasMinLength ? 'var(--success-color)' : 'var(--text-light)' }}>
                Be at least 8 characters
              </li>
              <li style={{ color: hasLetter ? 'var(--success-color)' : 'var(--text-light)' }}>
                Include at least one letter
              </li>
              <li style={{ color: hasNumber ? 'var(--success-color)' : 'var(--text-light)' }}>
                Include at least one number
              </li>
            </ul>
          </div>
        </div>
        
        <div className="form-group">
          <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
          <input
            id="confirmPassword"
            type="password"
            className={`form-input ${confirmPassword && password !== confirmPassword ? 'error' : ''}`}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            required
            disabled={isSubmitting}
          />
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
          />
          <label htmlFor="terms" className="form-check-label">
            I accept the{' '}
            <AuthLink href="/terms">
              Terms of Service
            </AuthLink>{' '}
            and{' '}
            <AuthLink href="/privacy">
              Privacy Policy
            </AuthLink>
          </label>
        </div>
        
        <div className="form-group">
          <button 
            type="submit" 
            className="btn btn-primary btn-block" 
            disabled={isSubmitting || !isPasswordValid || !termsAccepted}
          >
            {isSubmitting ? (
              <>
                <span className="form-loader"></span>
                Creating Account...
              </>
            ) : 'Sign Up'}
          </button>
        </div>
      </form>
      
      <div className="auth-links">
        <p>
          Already have an account?{' '}
          <AuthLink href="/auth/login">
            Log in
          </AuthLink>
        </p>
      </div>
    </div>
  );
}
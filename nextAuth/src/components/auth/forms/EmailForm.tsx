'use client';
import { updateEmail } from '@/lib/auth/helpers/server';
import { handleRequest } from '@/lib/auth/helpers/client';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

export default function EmailForm({
  userEmail
}: {
  userEmail: string | undefined;
}) {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    setIsSubmitting(true);
    // Check if the new email is the same as the old email
    if (e.currentTarget.newEmail.value === userEmail) {
      e.preventDefault();
      setIsSubmitting(false);
      return;
    }
    handleRequest(e, updateEmail, router);
    setIsSubmitting(false);
  };

  return (
    <div className="form-group">
      <h2 className="auth-title" style={{fontSize: '1.5rem', marginBottom: '0.5rem'}}>Your Email</h2>
      <p className="form-hint" style={{marginBottom: '1.5rem'}}>
        Please enter the email address you want to use to login.
      </p>
      
      <form id="emailForm" onSubmit={(e) => handleSubmit(e)} className="auth-form">
        <div className="input-wrapper">
          <input
            type="email"
            name="newEmail"
            className="form-input"
            defaultValue={userEmail ?? ''}
            placeholder="Your email"
            maxLength={64}
          />
          <svg className="form-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
            <polyline points="22,6 12,13 2,6"></polyline>
          </svg>
        </div>
      </form>
      
      <div className="auth-link-row" style={{justifyContent: 'space-between', marginTop: '1.5rem'}}>
        <p className="form-hint">We will email you to verify the change.</p>
        <button 
          className="btn btn-primary" 
          type="submit"
          form="emailForm"
          disabled={isSubmitting}
        >
          {isSubmitting && <span className="spinner"></span>}
          Update Email
        </button>
      </div>
    </div>
  );
}
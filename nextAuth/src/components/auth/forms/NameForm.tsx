'use client';
import { updateName } from '@/lib/auth/helpers/server';
import { handleRequest } from '@/lib/auth/helpers/client';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

export default function NameForm({ userName }: { userName: string }) {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    setIsSubmitting(true);
    // Check if the new name is the same as the old name
    if (e.currentTarget.fullName.value === userName) {
      e.preventDefault();
      setIsSubmitting(false);
      return;
    }
    handleRequest(e, updateName, router);
    setIsSubmitting(false);
  };

  return (
    <div className="form-group">
      <h2 className="auth-title" style={{fontSize: '1.5rem', marginBottom: '0.5rem'}}>Your Name</h2>
      <p className="form-hint" style={{marginBottom: '1.5rem'}}>
        Please enter your full name, or a username you are comfortable displaying.
      </p>
      
      <form id="nameForm" onSubmit={(e) => handleSubmit(e)} className="auth-form">
        <div className="input-wrapper">
          <input
            type="text"
            name="fullName"
            className="form-input"
            defaultValue={userName}
            placeholder="Your name"
            maxLength={64}
          />
          <svg className="form-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
            <circle cx="12" cy="7" r="4"></circle>
          </svg>
        </div>
      </form>
      
      <div className="auth-link-row" style={{justifyContent: 'space-between', marginTop: '1.5rem'}}>
        <p className="form-hint">64 characters maximum</p>
        <button 
          className="btn btn-primary" 
          type="submit"
          form="nameForm"
          disabled={isSubmitting}
        >
          {isSubmitting && <span className="spinner"></span>}
          Update Name
        </button>
      </div>
    </div>
  );
}
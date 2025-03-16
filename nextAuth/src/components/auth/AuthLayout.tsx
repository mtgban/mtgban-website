// src/components/auth/AuthLayout.tsx
import React, { ReactNode } from 'react';
import Head from 'next/head';
import Image from 'next/image';
import AuthLink from './AuthLink';

interface AuthLayoutProps {
  children: ReactNode;
  title: string;
  description?: string;
}

const AuthLayout: React.FC<AuthLayoutProps> = ({ 
  children, 
  title, 
  description = 'Authentication page for MTGBAN'
}) => {
  return (
    <>
      <Head>
        <title>{title} | MTGBAN</title>
        <meta name="description" content={description} />
      </Head>
      
      <div className="auth-layout">
        <div className="auth-background">
          <div className="auth-background-pattern"></div>
          <div className="auth-background-gradient"></div>
        </div>
        
        <div className="auth-page">
          <div className="auth-logo-container">
            <AuthLink href="/" className="auth-logo-link">
              <Image 
                src="/logo.png" 
                alt="MTGBAN Logo" 
                width={150} 
                height={40} 
                priority
                className="auth-logo"
              />
            </AuthLink>
          </div>
          
          {children}
          
          <div className="auth-footer">
            <p className="auth-footer-text">
              &copy; {new Date().getFullYear()} MTGBAN. All rights reserved.
            </p>
          </div>
        </div>
      </div>
    </>
  );
};

export default AuthLayout;
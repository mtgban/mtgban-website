// src/components/auth/AuthLayout.tsx
import React, { ReactNode, useEffect } from 'react';
import Head from 'next/head';

interface LegalLayoutProps {
  children: ReactNode;
  title: string;
  description?: string;
}

export default function LegalLayout({ 
  children, 
  title, 
  description = 'Legal page for MTGBAN'
}: LegalLayoutProps ) {
  // Apply dark mode based on system preference
  useEffect(() => {
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    // Add data attribute to document
    if (prefersDarkMode) {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
    }
    
    // Listen for changes color scheme
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
    };
    
    mediaQuery.addEventListener('change', handleChange);
    
    return () => {
      mediaQuery.removeEventListener('change', handleChange);
    };
  }, []);

  return (
    <>
      <Head>
        <title>{title} | MTGBAN</title>
        <meta name="description" content={description} />
        <meta name="color-scheme" content="light dark" />
        <meta name="theme-color" media="(prefers-color-scheme: light)" content="#ffffff" />
        <meta name="theme-color" media="(prefers-color-scheme: dark)" content="#121212" />
      </Head>
      
      <div className="auth-layout">
        <div className="auth-background">
          <div className="auth-background-pattern"></div>
          <div className="auth-background-gradient"></div>
        </div>
        
        <div className="legal-page">
          </div>
          
          {children}
          
          <div className="auth-footer">
            <p className="auth-footer-text">
              &copy; {new Date().getFullYear()} MTGBAN. All rights reserved.
            </p>
          </div>
        </div>
    </>
  );
};
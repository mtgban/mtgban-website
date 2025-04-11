'use client';

import React, { useEffect } from 'react';
import { Metadata } from 'next';
import { getURL } from '@/lib/helpers';
import type { AppProps } from 'next/app';
import { useRouter } from 'next/router';
import { AuthProvider } from '../context/AuthProvider';
import  '../../public/globals.css';
import  '../../public/search.css';

const title = 'MTGBAN User Portal';
const description = 'Manage your MTGBAN subscription.';

export const metadata: Metadata = {
  metadataBase: new URL(getURL()),
  title,
  description,
  openGraph: {
    title,
    description
  }
};

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter();

  // Add route change handling for page transitions
  useEffect(() => {
    const handleStart = () => {
      // Show loading state on route change start
      document.body.classList.add('loading');
    };
    
    const handleComplete = () => {
      document.body.classList.remove('loading');
    };
    
    router.events.on('routeChangeStart', handleStart);
    router.events.on('routeChangeComplete', handleComplete);
    router.events.on('routeChangeError', handleComplete);
    
    return () => {
      router.events.off('routeChangeStart', handleStart);
      router.events.off('routeChangeComplete', handleComplete);
      router.events.off('routeChangeError', handleComplete);
    };
  }, [router]);

  return (
    <AuthProvider>
      <Component {...pageProps} />
    </AuthProvider>
  );
}


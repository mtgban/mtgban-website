import React, { useEffect } from 'react';
import { AppProps } from 'next/app';
import { AuthProvider } from '@/context/AuthProvider';
import { createFetchInterceptor } from '@/lib/auth/interceptor';
import '../../public/globals.css';

function MyApp({ Component, pageProps }: AppProps) {
  useEffect(() => {
    const restoreFetch = createFetchInterceptor();
    return () => {
      restoreFetch();
    }
  }, []);

  return (
    <AuthProvider>
      <Component {...pageProps} />
    </AuthProvider>
  );
};

export default MyApp;
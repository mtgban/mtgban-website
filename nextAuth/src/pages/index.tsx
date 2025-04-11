'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';

export default function Home() {
  const router = useRouter();
  
  useEffect(() => {
    // Redirect to login page on client side
    router.push('/home');
  }, [router]);
  
  return (
    <>
      <Head>
        <title>MTGBAN Authentication</title>
        <meta name="description" content="MTGBAN Authentication" />
        
      </Head>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        Redirecting...
      </div>
    </>
  );
}
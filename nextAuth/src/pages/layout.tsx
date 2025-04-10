'use client';

import { useEffect, useState } from 'react';
import AuthLink from '@/components/auth/AuthLink';
import { usePathname, useRouter } from 'next/navigation';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  
  // Check if user is authenticated on client-side
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Simple check for cookie existence - the actual auth verification will be done by the server
        const cookies = document.cookie.split(';');
        const hasAuthCookie = cookies.some(cookie => 
          cookie.trim().startsWith('auth_token=') || 
          cookie.trim().startsWith('MTGBAN=')
        );
        
        setUser(hasAuthCookie ? { isAuthenticated: true } : null);
      } catch (error) {
        console.error('Auth check error:', error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, [pathname]);
  
  // Handle logout
  const handleLogout = (e: React.MouseEvent) => {
    e.preventDefault();
    // Redirect to backend logout endpoint
    window.location.href = '/auth/logout';
  };
  
  return (
    <html lang="en">
      <head>
        <title>MTGBAN User Portal</title>
        <meta name="description" content="Manage your MTGBAN subscription." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body>
        <div className="main-layout">
          <header className="navbar">
            <div className="navbar-container">
              <AuthLink href="/" className="navbar-logo">
                MTGBAN
              </AuthLink>
              
              <nav className="navbar-links">
                <AuthLink 
                  href="/" 
                  className={`navbar-link ${pathname === '/' ? 'active' : ''}`}
                >
                  Home
                </AuthLink>
                
                <AuthLink 
                  href="/pricing/details" 
                  className={`navbar-link ${pathname?.startsWith('/pricing') ? 'active' : ''}`}
                >
                  Pricing
                </AuthLink>
                
                {!loading && (
                  user ? (
                    <>
                      <AuthLink 
                        href="/account" 
                        className={`navbar-link ${pathname === '/account' ? 'active' : ''}`}
                      >
                        Account
                      </AuthLink>
                      
                      <a 
                        href="#" 
                        onClick={handleLogout} 
                        className="navbar-link"
                      >
                        Sign Out
                      </a>
                    </>
                  ) : (
                    <AuthLink 
                      href="/auth/login" 
                      className={`navbar-link ${pathname?.startsWith('/auth') ? 'active' : ''}`}
                    >
                      Sign In
                    </AuthLink>
                  )
                )}
              </nav>
            </div>
          </header>
          
          <main className="main-content">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
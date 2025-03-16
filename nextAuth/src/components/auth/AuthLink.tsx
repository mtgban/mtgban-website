// src/components/auth/AuthLink.tsx
import React, { ReactNode } from 'react';
import Link from 'next/link';

interface AuthLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}

/**
 * Special Link component that properly handles auth paths
 * Use this instead of Next.js Link for auth navigation
 */
const AuthLink: React.FC<AuthLinkProps> = ({ href, children, className, onClick }) => {
  // Determine the correct path based on the href
  const getLinkPath = (href: string): string => {
    // If it's an absolute URL or anchored URL, return as is
    if (href.startsWith('http') || href.startsWith('#') || href.startsWith('/')) {
      return href;
    }
    
    // If it already has /auth/, remove it to avoid duplication
    if (href.startsWith('auth/')) {
      href = href.substring(5);
    }
    
    // Remove any leading slash if present
    if (href.startsWith('/')) {
      href = href.substring(1);
    }
    
    // Return a relative path - this is key to avoiding /auth/auth
    return `./${href}`;
  };
  
  const linkPath = getLinkPath(href);
  
  return (
    <Link href={linkPath} className={className} onClick={onClick}>
      {children}
    </Link>
  );
};

export default AuthLink;
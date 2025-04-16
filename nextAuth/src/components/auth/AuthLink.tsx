import React, { FC } from 'react';
import Link from 'next/link';

interface AuthLinkProps {
  href: string;
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}

/**
 * Special Link component that properly handles auth paths
 * Use this instead of Next.js Link for auth navigation
 */
const AuthLink: FC<AuthLinkProps> = ({ href, children, className, onClick }) => {
  // Determine the correct path based on the href
  const getLinkPath = (href: string): string => {
    // If it's an absolute URL or anchored URL, return as is
    if (href.startsWith('http') || href.startsWith('#') || href.startsWith('/')) {
      return href;
    }
    
    if (href.startsWith('auth/')) {
      href = href.substring(5);
    }
    
    // Remove any leading slash if present
    if (href.startsWith('/')) {
      href = href.substring(1);
    }
    
    // Return a relative path
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
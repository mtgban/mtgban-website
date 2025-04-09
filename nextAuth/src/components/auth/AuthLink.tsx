// src/components/auth/AuthLink.tsx
import React, { ReactNode } from 'react';
import Link, {LinkProps } from 'next/link';

interface AuthLinkProps extends Omit<LinkProps, 'href'> {
  href: string;
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}

/**
 * Special Link component that properly handles auth paths
 * Use this instead of Next.js Link for auth navigation
 */
export default function AuthLink({ href, children, className, onClick, ...props }: AuthLinkProps) {
  const getLinkPath = (href: string): string => {
    if (href.startsWith('http') || href.startsWith('#') || href.startsWith('/')) {
      return href;
    }

    if (href.startsWith('auth/')) {
      href = href.substring(5);
    }

    if (href.startsWith('/')) {
      href = href.substring(1);
    }

    return `./${href}`;
  }

  const linkPath = getLinkPath(href);
  
  return (
    <Link href={linkPath} className={className} onClick={onClick} {...props}>
      {children}
    </Link>
  );
};
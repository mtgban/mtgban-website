import React from 'react';
import Link from 'next/link';

interface LegalLinksProps {
  casual?: boolean;
  className?: string;
  linkClassName?: string;
  separator?: React.ReactNode;
  newTab?: boolean;
}

/**
 * A component that renders links to legal pages
 */
const LegalLinks: React.FC<LegalLinksProps> = ({
  casual = false,
  className = 'legal-links',
  linkClassName = 'legal-link',
  separator = ' | ',
  newTab = false,
}) => {

  return (
    <div className={className}>
      <Link href="/legal/terms" passHref>
      <a target={newTab ? '_blank' : undefined} rel={newTab ? 'noopener noreferrer' : undefined}>
          <button className={linkClassName}>
            Terms & Conditions
          </button>
        </a>
      </Link>

      {separator}

      <Link href="/legal/privacy" passHref>
        <a target={newTab ? '_blank' : undefined} rel={newTab ? 'noopener noreferrer' : undefined}>
          <button className={linkClassName}>
            Privacy Policy
          </button>
        </a>
      </Link>
    </div>
  );
};

export default LegalLinks;
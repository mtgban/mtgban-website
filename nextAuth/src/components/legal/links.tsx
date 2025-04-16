import React from 'react';
import { useLegalNavigation } from '@/lib/legal';

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
  const { 
    goToTerms, 
    goToCasualTerms, 
    goToPrivacyPolicy, 
    goToCasualPrivacy 
  } = useLegalNavigation();

  const handleTermsClick = () => {
    if (casual) {
      goToCasualTerms({ newTab });
    } else {
      goToTerms({ newTab });
    }
  };

  const handlePrivacyClick = () => {
    if (casual) {
      goToCasualPrivacy({ newTab });
    } else {
      goToPrivacyPolicy({ newTab });
    }
  };

  return (
    <div className={className}>
      <button 
        className={linkClassName} 
        onClick={handleTermsClick}
      >
        Terms & Conditions
      </button>
      
      {separator}
      
      <button 
        className={linkClassName} 
        onClick={handlePrivacyClick}
      >
        Privacy Policy
      </button>
    </div>
  );
};

export default LegalLinks;
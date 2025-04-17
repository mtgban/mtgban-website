// components/Footer.tsx
import React from 'react';
import css from 'styled-jsx';
import Link from 'next/link';
import LegalLinks from '@/components/legal/LegalLinks';

interface FooterProps {
    companyName: string;
    useCasualLegal?: boolean;
}

const Footer: React.FC<FooterProps> = ({ 
  useCasualLegal = false,
  companyName = 'MTGBAN'
}) => {
  return (
    <footer className="site-footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-logo">
            <Link href="/">
              <a>{companyName}</a>
            </Link>
          </div>
          
          <div className="footer-nav">
            <nav>
              <Link href="/about">
                <a>About Us</a>
              </Link>
              <Link href="/contact">
                <a>Contact</a>
              </Link>
              <Link href="/faq">
                <a>FAQ</a>
              </Link>
            </nav>
          </div>
          
          <div className="footer-bottom">
            <p className="copyright">
              &copy; {new Date().getFullYear()} {companyName}. All rights reserved.
            </p>
            
            {/* Legal links component */}
            <LegalLinks 
              casual={useCasualLegal} 
              className="footer-legal" 
              linkClassName="footer-legal-link"
            />
          </div>
        </div>
      </div>
      
      <style jsx>{`
        .site-footer {
          background-color: var(--bg-dark);
          border-top: 1px solid var(--border-color);
          color: var(--text-light);
          padding: 3rem 0 1.5rem;
        }
        
        .container {
          margin: 0 auto;
          max-width: 1200px;
          padding: 0 2rem;
        }
        
        .footer-content {
          display: flex;
          flex-direction: column;
          gap: 2rem;
        }
        
        .footer-logo a {
          color: var(--primary-color);
          font-size: 1.5rem;
          font-weight: 700;
          text-decoration: none;
        }
        
        .footer-nav nav {
          display: flex;
          flex-wrap: wrap;
          gap: 1.5rem;
        }
        
        .footer-nav a {
          color: var(--text-light);
          text-decoration: none;
          transition: color 0.3s ease;
        }
        
        .footer-nav a:hover {
          color: var(--primary-color);
        }
        
        .footer-bottom {
          border-top: 1px solid var(--border-color);
          display: flex;
          flex-wrap: wrap;
          justify-content: space-between;
          padding-top: 1.5rem;
        }
        
        .copyright {
          font-size: 0.9rem;
          margin: 0;
        }
        
        @media (max-width: 768px) {
          .footer-bottom {
            flex-direction: column;
            gap: 1rem;
          }
        }
      `}</style>
    </footer>
  );
};

export default Footer;
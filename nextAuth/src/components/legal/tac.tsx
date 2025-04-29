'use client';

import React from 'react';
import Head from 'next/head';
import AuthLink from '@/components/auth/AuthLink';
import styles from './legal.module.css';

interface CompanyInfo {
  name: string;
  website: string;
  email: string;
  jurisdiction: string;
  lastUpdated: string;
}

const TermsAndConditions: React.FC = () => {
  const companyInfo: CompanyInfo = {
    name: "MTGBAN",
    website: "mtgban.com",
    email: "contact@mtgban.com",
    jurisdiction: "United States of America",
    lastUpdated: "April 16, 2025"
  };

  return (
    <div className={styles.mainLayout}>
      <Head>
        <title>Terms and Conditions | {companyInfo.name}</title>
        <meta name="description" content={`Terms and Conditions for ${companyInfo.name}`} />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <header className={styles.header}>
        <div className={styles.headerContainer}>
          <AuthLink href="/">
            <a className={styles.logo}>{companyInfo.name}</a>
          </AuthLink>
        </div>
      </header>

      <div className={styles.contentContainer}>
        <h1>Terms and Conditions</h1>

        <section>
          <h2>1. Introduction</h2>
          <p>Welcome to {companyInfo.name} ("we," "our," or "us"). By accessing or using our website at {companyInfo.website} (the "Service"), you agree to be bound by these Terms and Conditions ("Terms"). If you disagree with any part of these Terms, you may not access the Service.</p>
        </section>

        <section>
          <h2>2. Definitions</h2>
          <ul>
            <li>"Account" means a unique account created for you to access our Service.</li>
            <li>"Content" means data, information, or material that is provided through the Service.</li>
            <li>"Subscription" means the recurring payment arrangement for access to the Service.</li>
            <li>"User," "You," and "Your" refer to the person accessing or using the Service.</li>
          </ul>
        </section>

        <section>
          <h2>3. Accounts and Subscriptions</h2>
          
          <h3>3.1 Account Registration</h3>
          <p>To access the Service, you may be required to register for an account. You agree to provide accurate, current, and complete information during the registration process and to update such information to keep it accurate, current, and complete.</p>
          
          <h3>3.2 Account Security</h3>
          <p>You are responsible for safeguarding the password that you use to access the Service and for any activities or actions under your password.</p>
          
          <h3>3.3 Subscription Terms</h3>
          <ul>
            <li>The Service is available on a subscription basis.</li>
            <li>Subscription fees are charged in advance on a monthly or annual basis as selected by you.</li>
            <li>Subscriptions automatically renew unless cancelled at least 24 hours before the end of the current period.</li>
            <li>You can cancel your subscription at any time through your account settings or by contacting our customer support.</li>
          </ul>
          
          <h3>3.4 Payment</h3>
          <p>All payments shall be processed through our third-party payment processors. By providing payment information, you represent that you are authorized to use the payment method.</p>
        </section>

        <section>
          <h2>4. Intellectual Property</h2>
          
          <h3>4.1 Our Intellectual Property</h3>
          <p>The Service and its original content, features, and functionality are and will remain the exclusive property of {companyInfo.name} and its licensors. The Service is protected by copyright, trademark, and other laws.</p>
          
          <h3>4.2 License to Use the Service</h3>
          <p>Subject to these Terms, we grant you a limited, non-exclusive, non-transferable, and revocable license to use the Service for your personal or business purposes.</p>
          
          <h3>4.3 User Content</h3>
          <p>You retain any rights you have in the content you submit, post, or display on or through the Service. By submitting content to the Service, you grant us a worldwide, non-exclusive, royalty-free license to use, reproduce, and display the content in connection with providing the Service to you.</p>
        </section>

        <section>
          <h2>5. Prohibited Uses</h2>
          <p>You agree not to:</p>
          <ul>
            <li>Use the Service in any way that violates any applicable law or regulation.</li>
            <li>Attempt to probe, scan, or test the vulnerability of the Service or breach any security or authentication measures.</li>
            <li>Interfere with the proper working of the Service or any activities conducted on the Service.</li>
            <li>Engage in unauthorized framing of or linking to the Service.</li>
            <li>Scrape, collect, or harvest any data from the Service beyond what is necessary for your use of the Service.</li>
            <li>Use the Service to transmit any malware, spyware, or other harmful code.</li>
          </ul>
        </section>

        <section>
          <h2>6. Third-Party Services</h2>
          <p>The Service may contain links to third-party websites, services, or resources that are not owned or controlled by us. We have no control over, and assume no responsibility for, the content, privacy policies, or practices of any third-party websites or services.</p>
        </section>

        <section>
          <h2>7. Disclaimer of Warranties</h2>
          <p>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.</p>
        </section>

        <section>
          <h2>8. Limitation of Liability</h2>
          <p>IN NO EVENT SHALL {companyInfo.name.toUpperCase()} BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING WITHOUT LIMITATION, LOSS OF PROFITS, DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES, RESULTING FROM YOUR ACCESS TO OR USE OF OR INABILITY TO ACCESS OR USE THE SERVICE.</p>
        </section>

        <section>
          <h2>9. Indemnification</h2>
          <p>You agree to defend, indemnify, and hold harmless {companyInfo.name} and its officers, directors, employees, and agents, from and against any claims, liabilities, damages, losses, and expenses, including without limitation reasonable attorney fees and costs, arising out of or in any way connected with your access to or use of the Service.</p>
        </section>

        <section>
          <h2>10. Changes to Terms</h2>
          <p>We reserve the right to modify or replace these Terms at any time. If a revision is material, we will provide at least 30 days' notice prior to any new terms taking effect. What constitutes a material change will be determined at our sole discretion.</p>
        </section>

        <section>
          <h2>11. Governing Law</h2>
          <p>These Terms shall be governed by and construed in accordance with the laws of {companyInfo.jurisdiction}, without regard to its conflict of law provisions.</p>
        </section>

        <section>
          <h2>12. Contact Us</h2>
          <p>If you have any questions about these Terms, please contact us at {companyInfo.email}.</p>
        </section>

        <section>
          <h2>13. Termination</h2>
          <p>We may terminate or suspend your account and access to the Service immediately, without prior notice or liability, for any reason, including without limitation if you breach the Terms.</p>
        </section>

        <section>
          <h2>14. Severability</h2>
          <p>If any provision of these Terms is held to be unenforceable or invalid, such provision will be changed and interpreted to accomplish the objectives of such provision to the greatest extent possible under applicable law and the remaining provisions will continue in full force and effect.</p>
        </section>

        <section>
          <h2>15. Entire Agreement</h2>
          <p>These Terms constitute the entire agreement between us regarding our Service and supersede and replace any prior agreements we might have had between us regarding the Service.</p>
        </section>

        <div className={styles.lastUpdated}>
          <p>Last updated: {companyInfo.lastUpdated}</p>
        </div>
      </div>

      <footer className={styles.footer}>
        <div className={styles.footerContent}>
          <p>&copy; {new Date().getFullYear()} {companyInfo.name}. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default TermsAndConditions;
'use client';

import React from 'react';
import Head from 'next/head';
import AuthLink from '@/components/auth/AuthLink';
import styles from '@/styles/legal.module.css';

interface CompanyInfo {
  name: string;
  website: string;
  email: string;
  address: string;
  lastUpdated: string;
}

const PrivacyPolicy: React.FC = () => {
  const companyInfo: CompanyInfo = {
    name: "MTGBAN",
    website: "mtgban.com",
    email: "contact@mtgban.com",
    address: "The Internet, Mostly",
    lastUpdated: "April 16, 2025"
  };

  return (
    <div className={styles.mainLayout}>
      <Head>
        <title>Privacy Policy | {companyInfo.name}</title>
        <meta name="description" content={`Privacy Policy for ${companyInfo.name}`} />
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
        <h1>Privacy Policy</h1>

        <section>
          <h2>1. Introduction</h2>
          <p>This Privacy Policy describes how {companyInfo.name} ("we," "our," or "us") collects, uses, and discloses your information when you use our website at {companyInfo.website} (the "Service"). By using the Service, you agree to the collection and use of information in accordance with this policy.</p>
        </section>

        <section>
          <h2>2. Information We <strong>Do Not</strong> Collect</h2>
          <div className={`${styles.infoBox} ${styles.emphasis}`}>
            <p>We want to be clear about our data practices. Our Service:</p>
            <ul>
              <li>Does not collect user metrics or usage data</li>
              <li>Does not sell any user data to third parties</li>
              <li>Does not share your personal information with advertisers or marketing companies</li>
              <li>Does not track your online behavior across other websites or services</li>
            </ul>
          </div>
        </section>

        <section>
          <h2>3. Information We <strong>Do</strong> Collect</h2>
          
          <h3>3.1 Account Information</h3>
          <p>When you create an account, we collect:</p>
          <ul>
            <li>Name</li>
            <li>Email address</li>
            <li>Password (stored in an encrypted format)</li>
            <li>Billing information (processed by our payment processor)</li>
          </ul>
          
          <h3>3.2 Cookies and Similar Technologies</h3>
          <p>We use only essential cookies necessary for the functionality of our website, such as:</p>
          <ul>
            <li>Session cookies to keep you logged in during your visit</li>
            <li>Cookies to remember your preferences</li>
            <li>Cookies necessary for secure authentication</li>
          </ul>
          <p>These cookies are required for the Service to function properly and cannot be switched off in our systems.</p>
          
          <h3>3.3 Log Data</h3>
          <p>Our servers automatically record certain information when you use the Service, including:</p>
          <ul>
            <li>IP address (temporarily stored for security purposes)</li>
            <li>Browser type</li>
            <li>Access times</li>
            <li>Pages viewed</li>
            <li>System errors</li>
          </ul>
          <p>This information is used solely for troubleshooting, security, and ensuring proper operation of the Service.</p>
        </section>

        <section>
          <h2>4. How We Use Your Information</h2>
          <p>We use the information we collect for the following purposes:</p>
          <ul>
            <li>To provide and maintain the Service</li>
            <li>To process your subscription payments</li>
            <li>To respond to your requests or inquiries</li>
            <li>To detect and prevent security incidents</li>
            <li>To debug and fix problems with the Service</li>
          </ul>
        </section>

        <section>
          <h2>5. Information Sharing and Disclosure</h2>
          
          <h3>5.1 Service Providers</h3>
          <p>We may employ third-party companies and individuals to facilitate our Service ("Service Providers"), provide the Service on our behalf, perform Service-related services, or assist us in analyzing how our Service is used. These third parties have access to your Personal Data only to perform these tasks on our behalf and are obligated not to disclose or use it for any other purpose.</p>
          
          <h3>5.2 Payment Processors</h3>
          <p>Subscription payments are processed by third-party payment processors. We do not store your full credit card details on our servers. The payment processors we use adhere to the standards set by PCI-DSS as managed by the PCI Security Standards Council.</p>
          
          <h3>5.3 Legal Requirements</h3>
          <p>We may disclose your information if required to do so by law or in response to valid requests by public authorities (e.g., a court or a government agency).</p>
        </section>

        <section>
          <h2>6. Data Retention</h2>
          <p>We will retain your information only for as long as your account is active or as needed to provide you with our Service. We will retain and use your information to the extent necessary to comply with our legal obligations, resolve disputes, and enforce our policies.</p>
        </section>

        <section>
          <h2>7. Data Security</h2>
          <p>The security of your data is important to us. We implement appropriate technical and organizational measures to protect the information we collect and maintain. However, no method of transmission over the Internet, or method of electronic storage is 100% secure. While we strive to use commercially acceptable means to protect your personal information, we cannot guarantee its absolute security.</p>
        </section>

        <section>
          <h2>8. Your Data Protection Rights</h2>
          <p>Depending on your location, you may have certain rights regarding your personal information, including:</p>
          <ul>
            <li>Right to access the personal information we hold about you</li>
            <li>Right to request correction of inaccurate information</li>
            <li>Right to request deletion of your personal information</li>
            <li>Right to object to or restrict processing of your personal information</li>
            <li>Right to data portability</li>
          </ul>
          <p>To exercise these rights, please contact us using the information provided in the "Contact Us" section.</p>
        </section>

        <section>
          <h2>9. Children's Privacy</h2>
          <p>Our Service does not address anyone under the age of 18 ("Children"). We do not knowingly collect personally identifiable information from anyone under the age of 18. If you are a parent or guardian and you are aware that your Child has provided us with personal information, please contact us.</p>
        </section>

        <section>
          <h2>10. Changes to This Privacy Policy</h2>
          <p>We may update our Privacy Policy from time to time. We will notify you of any changes by posting the new Privacy Policy on this page and updating the "Last updated" date. You are advised to review this Privacy Policy periodically for any changes.</p>
        </section>

        <section>
          <h2>11. Contact Us</h2>
          <p>If you have any questions about this Privacy Policy, please contact us at:</p>
          <ul>
            <li>Email: {companyInfo.email}</li>
            <li>Address: {companyInfo.address}</li>
          </ul>
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

export default PrivacyPolicy;
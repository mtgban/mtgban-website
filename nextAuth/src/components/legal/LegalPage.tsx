'use client';

import React, { useState } from 'react';
import Head from 'next/head';
import AuthLink from '@/components/auth/AuthLink';
import styles from './legal.module.css';
import Link from 'next/link';

interface CompanyInfo {
  name: string;
  website: string;
  email: string;
  address?: string;
  jurisdiction?: string;
  lastUpdated: string;
}

interface LegalPageProps {
  pageType: 'terms' | 'privacy';
  signupUrl?: string;
}

const LegalPage: React.FC<LegalPageProps> = ({ pageType, signupUrl }) => {
  const companyInfo: CompanyInfo = {
    name: "MTGBAN",
    website: "mtgban.com",
    email: "contact@mtgban.com",
    address: "The Internet, Mostly",
    jurisdiction: "United States of America",
    lastUpdated: "April 16, 2025"
  };

  const [isCasual, setIsCasual] = useState(true);

  const toggleVersion = () => {
    setIsCasual(!isCasual);
  };

  const renderContent = () => {
    if (pageType === 'privacy') {
      return isCasual ? (
        <>
          <h1>No-Nonsense Privacy Policy</h1>

          <section>
            <h2>TLDR:</h2>
            <p>Selling data is what we do. We just dont sell <strong>your</strong> data. <br />
            Also, we put some cookies on your computer to make the site work. <br />
            If you want to know more, read on.</p>
          </section>

          <section className={styles.infoBox}>
            <h2>Stuff We Don't Do</h2>
            <ul>
              <li>We don't collect user metrics or tracking data</li>
              <li>We don't sell your information to anyone</li>
              <li>We don't share your info with advertisers</li>
              <li>We don't follow you around the internet</li>
            </ul>
          </section>

          <section>
            <h2>Stuff We Do Do. (lol, 💩)</h2>

            <h3>Account Stuff</h3>
            <p>Just the basics required to run your account:</p>
            <ul>
              <li>Your name</li>
              <li>Email address</li>
              <li>Password (encrypted, we can't read it)</li>
              <li>Billing info (handled by our payment processor, not stored on our servers)</li>
            </ul>

            <h3>Cookies</h3>
            <p>Only the essential ones that make the website function:</p>
            <ul>
              <li>Session cookies (so you stay logged in)</li>
              <li>Preference cookies (so we remember how you like things)</li>
              <li>Authentication cookies (so we know it's really you)</li>
            </ul>
            <p>These cookies are required for the Service to function properly and cannot be switched off in our systems.</p>

            <h3>Technical Stuff</h3>
            <p>Basic server logs that every website collects:</p>
            <ul>
              <li>IP address (temporarily, for security)</li>
              <li>Browser type</li>
              <li>When you visited</li>
              <li>What pages you looked at</li>
              <li>Any errors that happened</li>
            </ul>
            <p>We only use this to troubleshoot problems and keep the site secure.</p>
          </section>

          <section>
            <h2>How We Use This Stuff</h2>
            <p>We only use your info to:</p>
            <ul>
              <li>Run the service</li>
              <li>Process your payments</li>
              <li>Answer your questions</li>
              <li>Fix problems</li>
              <li>Keep things secure</li>
            </ul>
          </section>

          <section>
            <h2>Who Else Might See Your Stuff</h2>

            <h3>Service Providers</h3>
            <p>Some companies help us run our service (like our hosting provider and payment processor). They can only use your data to provide their specific service.</p>

            <h3>If The Law Requires It</h3>
            <p>If we get a court order or similar legal requirement, we might have to share some information.</p>
          </section>

          <section>
            <h2>How Long We Keep Your Stuff</h2>
            <p>Only as long as you have an account with us, plus any period required by law. After that, we delete it.</p>
          </section>

          <section>
            <h2>Rights To Your Stuff</h2>
            <p>Depending on where you live, you can:</p>
            <ul>
              <li>See what data we have about you</li>
              <li>Correct mistakes in your data</li>
              <li>Delete your data</li>
              <li>Restrict how we use your data</li>
              <li>Get a copy of your data</li>
            </ul>
            <p>Just email us to exercise these rights.</p>
          </section>

          <section>
            <h2>Kids' Stuff</h2>
            <p>Our service isn't for people under 18. If you're a parent and discover your kid signed up, let us know and we'll delete their account.</p>
          </section>

          <section>
            <h2>Changes to This Stuff</h2>
            <p>If we update this policy, we'll post the new version here and update the date at the bottom.</p>
          </section>

          <section>
            <h2>If You Want To Talk To Us About Stuff</h2>
            <p>Email us at {companyInfo.email}</p>
          </section>

          <div className={styles.bottomLine}>
            <p><strong>The Bottom Line</strong>: We collect the minimum information needed to provide you with the service, and We respect your privacy.</p>
          </div>
        </>
      ) : (
        <>
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
        </>
      );
    } else if (pageType === 'terms') {
      return isCasual ? (
        <>
          <h1>Terms, Conditions, and Other Stuff</h1>

          <section>
            <h2>Hey There!</h2>
            <p>Welcome to {companyInfo.name}. This is the internet, and as such, Here's the deal:</p>
          </section>

          <section>
            <h2>What We're About</h2>
            <p>We offer subscription access to our data service. No fancy software to download, just a website with the data you need.</p>
          </section>

          <section>
            <h2>Basic Stuff</h2>
            <ul>
              <li><strong>Account Stuff</strong>: Sign up with real info. Keep your password to yourself.</li>
              <li><strong>Subscription Details</strong>: You pay monthly or maybe yearly. It auto-renews (we'll remind you). Cancel whenever you want.</li>
              <li><strong>Payments</strong>: We use standard payment processors. We don't see your full card details.</li>
            </ul>
          </section>

          <section>
            <h2>Common Sense Stuff</h2>
            <ul>
              <li>Don't do crimes.</li>
              <li>Don't mess with how the site works.</li>
              <li>Don't scrape tons of data beyond what you reasonably need.</li>
              <li>No spreading viruses or malware.</li>
            </ul>
          </section>

          <section>
            <h2>Who's Stuff is This?</h2>
            <ul>
              <li>Our stuff is our stuff. The service and how it works belong to us.</li>
              <li>Your stuff is your stuff. We're just displaying it for you.</li>
            </ul>
          </section>

          <section className={styles.highlightSection}>
            <h2>The "Sometimes Stuff Breaks" Clause</h2>
            <p>Listen, technology isn't perfect. We provide this service "as is." Sometimes stuff breaks - if it does, we'll try to fix it, but we can't guarantee the service will always be flawless.</p>
          </section>

          <section>
            <h2>If Stuff Goes Wrong</h2>
            <p>We're not liable for indirect damages if stuff goes sideways. We'll do our best to make things right, but there are limits to what we're on the hook for.</p>
          </section>

          <section>
            <h2>Other Folks' Stuff</h2>
            <p>There might be links to other websites or services. That's their stuff, not ours. We don't control what they do with their stuff.</p>
          </section>

          <section>
            <h2>Changes to This Stuff</h2>
            <p>We might update these terms. If it's a big change, we'll let you know 30 days before it happens.</p>
          </section>

          <section>
            <h2>Breaking Up</h2>
            <p>We can close your account if you break these rules. You can leave anytime by canceling your subscription.</p>
          </section>

          <section>
            <h2>Wanna Talk About Stuff?</h2>
            <p>Hit us up at {companyInfo.email}</p>
          </section>

          <div className={styles.bottomLine}>
            <p><strong>Bottom Line</strong>: Use the service for its intended purpose, understand sometimes technology hiccups, and we'll all get along fine.</p>
          </div>
        </>
      ) : (
        <>
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
        </>
      );
    }
    return null;
  };

  const pageTitle = pageType === 'privacy' ? "Privacy Policy" : "Terms and Conditions";
  const casualTitle = pageType === 'privacy' ? "Casual" : "Casual";
  const professionalTitle = pageType === 'privacy' ? "Legalese" : "Legalese";
  const professionalLink = pageType === 'privacy' ? "/legal/privacy" : "/legal/terms";
  const otherDocumentPage = pageType === 'privacy' ? 'terms' : 'privacy';
  const otherDocumentTitle = pageType === 'privacy' ? "Terms & Conditions" : "Privacy Policy";
  const otherDocumentLink = `/legal/${otherDocumentPage}`;

  return (
    <div className={styles.mainLayout}>
      <Head>
        <title>{isCasual ? `${casualTitle} ${pageTitle}` : `${professionalTitle} ${pageTitle}`} | {companyInfo.name}</title>
        <meta name="description" content={`${isCasual ? casualTitle : professionalTitle} ${pageTitle} for ${companyInfo.name}`} />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <header className={styles.header}>
        <div className={styles.headerContainer}>
          <div className={styles.headerLinks}> {/* Container for header links */}
            <AuthLink href="/">
              <a className={styles.logo}>{companyInfo.name}</a> {/* Home Link (Logo) */}
            </AuthLink>

            <Link href="/" passHref>
                <a className={styles.headerLink}>Home</a>
            </Link>

            <Link href={otherDocumentLink} passHref>
                <a className={styles.headerLink}>{otherDocumentTitle}</a>
            </Link>

            {signupUrl && ( // "Back to Signup" link - Conditional
              <Link href={signupUrl} passHref>
                <a className={styles.headerLink}>← Back to Signup</a>
              </Link>
            )}
          </div>
        </div>
      </header>

      <div className={styles.contentContainer}>
        <div className={styles.tabButtons}>
          <button
            className={`${styles.tabButton} ${isCasual ? styles.activeTab : ''}`}
            onClick={toggleVersion}
          >
            {casualTitle} Version
          </button>
          <button
            className={`${styles.tabButton} ${!isCasual ? styles.activeTab : ''}`}
            onClick={toggleVersion}
          >
            {professionalTitle} Version
          </button>
        </div>

        {renderContent()}

        <div className={styles.lastUpdated}>
          <p>Last updated: {companyInfo.lastUpdated}</p>
        </div>
      </div>

      <footer className={styles.footer}>
        <div className={styles.footerContent}>
          <p>© {new Date().getFullYear()} {companyInfo.name}. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default LegalPage;
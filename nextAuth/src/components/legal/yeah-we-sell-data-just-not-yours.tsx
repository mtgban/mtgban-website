import React from 'react';
import Head from 'next/head';
import AuthLink from '@/components/auth/AuthLink';
import styles from '../../../public/legal.module.css';

interface CompanyInfo {
  name: string;
  website: string;
  email: string;
  lastUpdated: string;
}

const CasualPrivacyComponent: React.FC = () => {
  const companyInfo: CompanyInfo = {
    name: "MTGBAN",
    website: "mtgban.com",
    email: "contact@mtgban.com",
    lastUpdated: "April 16, 2025"
  };

  return (
    <div className={styles.mainLayout}>
      <Head>
        <title>No-Nonsense Privacy | {companyInfo.name}</title>
        <meta name="description" content={`No-Nonsense Privacy Policy for ${companyInfo.name}`} />
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
        <h1>No-Nonsense Privacy Policy</h1>

        <section>
          <h2>TLDR:</h2>
          <p>Selling data is what we do. We just dont sell <strong>your</strong> data. <br />
          Also, we put some cookies on your computer to make the site work. <br />
          If you want to know more, read on.</p>
        </section>

        <section className={styles.highlightSection}>
          <h2>Stuff We Don't Do</h2>
          <ul>
            <li>We don't collect user metrics or tracking data</li>
            <li>We don't sell your information to anyone</li>
            <li>We don't share your info with advertisers</li>
            <li>We don't follow you around the internet</li>
          </ul>
        </section>

        <section>
          <h2>Stuff We Do Do. (lol, doodoo)</h2>
          
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
          <h2>Your Rights</h2>
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
          <h2>Questions?</h2>
          <p>Email us at {companyInfo.email}</p>
        </section>

        <div className={styles.bottomLine}>
          <p><strong>The Bottom Line</strong>: We collect the minimum information needed to provide you with the service. We don't do creepy tracking stuff. We respect your privacy.</p>
        </div>

        <div className={styles.lastUpdated}>
          <p>Last updated: {companyInfo.lastUpdated}</p>
        </div>
        <div className={styles.legalJargon}>
            <p>If you want the legal jargon, click <AuthLink href="/legal/privacy">here</AuthLink>.</p>
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

export default CasualPrivacyComponent;
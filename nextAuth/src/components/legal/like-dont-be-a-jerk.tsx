import React, { FC } from 'react';
import Head from 'next/head';
import AuthLink from '@/components/auth/AuthLink';
import styles from './legal.module.css';

interface CompanyInfo {
  name: string;
  website: string;
  email: string;
  lastUpdated: string;
}

const CasualTerms: FC = () => {
  const companyInfo: CompanyInfo = {
    name: "MTGBAN",
    website: "mtgban.com",
    email: "contact@mtgban.com",
    lastUpdated: "April 16, 2025"
  };

  return (
    <div className={styles.mainLayout}>
      <Head>
        <title>Terms, Conditions, and Other Stuff | {companyInfo.name}</title>
        <meta name="description" content={`Terms, Conditions, and Other Stuff for ${companyInfo.name}`} />
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
          <h2>I Think We Should See Other Stuff</h2>
          <p>We can close your account if you break these rules. You can leave anytime by canceling your subscription.</p>
        </section>

        <section>
          <h2>Wanna Talk About Stuff?</h2>
          <p>Hit us up at {companyInfo.email}</p>
        </section>

        <div className={styles.bottomLine}>
          <p><strong>Bottom Line</strong>: Use the service for its intended purpose, understand sometimes technology hiccups, and we'll all get along fine.</p>
        </div>

        <div className={styles.lastUpdated}>
          <p>Last updated: {companyInfo.lastUpdated}</p>
        </div>
        <div className={styles.legalJargon}>
                <p>If you want the legal jargon, click <AuthLink href="/legal/tos">here</AuthLink>.</p>
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

export default CasualTerms;
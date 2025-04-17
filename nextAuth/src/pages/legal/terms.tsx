'use client';

import LegalPage from '@/components/legal/LegalPage';
import LegalLayout from '@/components/legal/LegalLayout';

const TermsPage = () => {
  return (
    <LegalLayout title="Terms & Conditions">
      <LegalPage pageType="terms" signupUrl="/signup" />
    </LegalLayout>
  );
};

export default TermsPage;
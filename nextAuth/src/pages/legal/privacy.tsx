'use client';

import LegalPage from '@/components/legal/LegalPage';
import LegalLayout from '@/components/legal/LegalLayout';

const PrivacyPage = () => {
  return (
    <LegalLayout title="Privacy Policy">
      <LegalPage pageType="privacy" signupUrl="/signup" />
    </LegalLayout>
  );
};

export default PrivacyPage;
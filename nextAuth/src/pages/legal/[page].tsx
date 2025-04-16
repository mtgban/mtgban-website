import React from 'react';
import { LegalPage } from '@/lib/legal';
import LegalLayout from '@/components/legal/LegalLayout';
import '../../../out/legal.module.css';

const CasualTerms = React.lazy(() => import('@/components/legal/like-dont-be-a-jerk'));
const CasualPrivacy = React.lazy(() => import('@/components/legal/yeah-we-sell-data-just-not-yours'));
const LegalTerms = React.lazy(() => import('@/components/legal/tac'));
const LegalPrivacy = React.lazy(() => import('@/components/legal/privacy'));

export default function DynamicLegalPage({ page }: { page: string }) {
    const renderContent = () => {
        switch (page) {
            case LegalPage.TERMS:
                return <LegalTerms />;
            case LegalPage.CASUAL_TERMS:
                return <CasualTerms />;
            case LegalPage.PRIVACY:
                return <LegalPrivacy />;
            case LegalPage.CASUAL_PRIVACY:
                return <CasualPrivacy />;
            default:
                return <div>Legal page not found</div>;
        }
    }

    return (
        <LegalLayout title={page}>
            <React.Suspense fallback={<div>Loading...</div>}>
                {renderContent()}
            </React.Suspense>
        </LegalLayout>
    )
}

export async function getStaticPaths() {
  const paths = Object.values(LegalPage).map(page => ({
    params: { page }
  }));
  
  return {
    paths,
    fallback: false
  };
}

export async function getStaticProps({ params }: { params: { page: string } }) {
  return {
    props: {
      page: params.page
    }
  };
}
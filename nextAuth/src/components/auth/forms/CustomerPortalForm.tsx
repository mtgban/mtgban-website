'use client';

import { useRouter, usePathname } from 'next/navigation';
import { useState } from 'react';
import { createStripePortal } from '@/lib/stripe/server';
import AuthLink from '@/components/auth/AuthLink';
import { Tables } from '@/types/types_db';

type Subscription = Tables<'subscriptions'>;
type Price = Tables<'prices'>;
type Product = Tables<'products'>;
type SubscriptionWithPriceAndProduct = Subscription & {
  prices:
    | (Price & {
        products: Product | null;
      })
    | null;
};

interface Props {
  subscription: SubscriptionWithPriceAndProduct | null;
}

export default function CustomerPortalForm({ subscription }: Props) {
  const router = useRouter();
  const currentPath = usePathname();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const subscriptionPrice =
    subscription &&
    new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: subscription?.prices?.currency!,
      minimumFractionDigits: 0
    }).format((subscription?.prices?.unit_amount || 0) / 100);

  const handleStripePortalRequest = async () => {
    setIsSubmitting(true);
    const redirectUrl = await createStripePortal(currentPath);
    setIsSubmitting(false);
    return router.push(redirectUrl);
  };

  return (
    <div className="form-group">
      <h2 className="auth-title" style={{fontSize: '1.5rem', marginBottom: '0.5rem'}}>Your Plan</h2>
      <p className="form-hint" style={{marginBottom: '1.5rem'}}>
        {subscription
          ? `You are currently on the ${subscription?.prices?.products?.name} plan.`
          : 'You are not currently subscribed to any plan.'}
      </p>
      
      <div className="user-welcome">
        <div style={{fontSize: '1.2rem', fontWeight: '600', marginBottom: '0.5rem'}}>
          {subscription ? (
            `${subscriptionPrice}/${subscription?.prices?.interval}`
          ) : (
            <AuthLink href="/" className="btn-link">Choose your plan</AuthLink>
          )}
        </div>
      </div>
      
      <div className="auth-link-row" style={{justifyContent: 'space-between', marginTop: '1.5rem'}}>
        <p className="form-hint">Manage your subscription. Powered by Stripe.</p>
        <button 
          className="btn btn-primary" 
          onClick={handleStripePortalRequest}
          disabled={isSubmitting}
        >
          {isSubmitting && <span className="spinner"></span>}
          Open customer portal
        </button>
      </div>
    </div>
  );
}


'use client';

import type { Tables } from '@/utils/types_db';
import { getStripe } from '@/utils/stripe/client';
import { checkoutWithStripe } from '@/utils/stripe/server';
import { getErrorRedirect } from '@/utils/helpers';
import { User } from '@supabase/supabase-js';
import { CircleDollarSign } from 'lucide-react';
import { useRouter, usePathname } from 'next/navigation';
import { Key, useCallback, useEffect, useMemo, useState } from 'react';
import '@/styles/pricing.css';

type Subscription = Tables<'subscriptions'>;
type Product = Tables<'products'>;
type Price = Tables<'prices'>;
interface ProductWithPrices extends Product {
  prices: Price[];
  
}
interface PriceWithProduct extends Price {
  products: Product | null;
}
interface SubscriptionWithProduct extends Subscription {
  prices: PriceWithProduct | null;
}

interface Props {
  user: User | null | undefined;
  products: ProductWithPrices[];
  subscription: SubscriptionWithProduct | null;
}

type BillingInterval = 'month' | 'year';

const formatPrice = (amount: number, currency: string): string =>
  new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency,
    minimumFractionDigits: 0
  }).format(amount / 100);

export default function Pricing({ user, products, subscription }: Props) {
  const router = useRouter();
  const currentPath = usePathname();
  const [billingInterval, setBillingInterval] = useState<BillingInterval>('month');
  const [priceIdLoading, setPriceIdLoading] = useState<string>();
  const [mounted, setMounted] = useState<boolean>(false);

  // Memoize active subscription check
  const isActiveSubscription = useCallback(
    (productName: string): boolean =>
      subscription
        ? productName === subscription?.prices?.products?.name
        : productName === 'Free Trial',
    [subscription]
  );

  useEffect(() => {
    setMounted(true);
  }, []);

  const sortedProducts = useMemo(() => {
    return [...products].sort((a, b) => {
      const priceA = a.prices?.find(p => p.interval === billingInterval)?.unit_amount || 0;
      const priceB = b.prices?.find(p => p.interval === billingInterval)?.unit_amount || 0;
      return priceA - priceB;
    });
  }, [products, billingInterval]);

  const handleStripeCheckout = async (price: Price): Promise<void> => {
    setPriceIdLoading(price.id);
    try {
      if (!user) {
        return router.push('/signin/signup');
      }

      const { errorRedirect, sessionId } = await checkoutWithStripe(
        price,
        currentPath
      );

      if (errorRedirect) {
        return router.push(errorRedirect);
      }

      if (!sessionId) {
        return router.push(
          getErrorRedirect(
            currentPath,
            'An unknown error occurred.',
            'Please try again later or contact a system administrator.'
          )
        );
      }

      const stripe = await getStripe();
      if (!stripe) {
        throw new Error('Failed to load Stripe');
      }

      await stripe.redirectToCheckout({ sessionId });
    } catch (error) {
      console.error('Checkout error:', error);
      router.push(
        getErrorRedirect(
          currentPath,
          'Payment processing failed.',
          'Please try again later.'
        )
      );
    } finally {
      setPriceIdLoading(undefined);
    }
  };

  if (!mounted) {
    return null;
  }

  if (!products.length) {
    return (
      <section className="auth-layout">
        <div className="auth-background">
          <div className="auth-background-pattern"></div>
          <div className="auth-background-gradient"></div>
        </div>
        <div className="auth-container visible">
          <div className="auth-header">
            <h2 className="auth-title">No Subscription Plans Found</h2>
            <p className="auth-subtitle">
              Please create subscription plans in your{' '}
              <a
                className="btn-link"
                href="https://dashboard.stripe.com/products"
                rel="noopener noreferrer"
                target="_blank"
              >
                Stripe Dashboard
              </a>
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className="pricing-container">
        <div className="auth-header">
          <h2 className="auth-title">Choose Your Perfect Plan</h2>
          <p className="auth-subtitle">Select the subscription that fits your needs</p>
          
          {/* Billing interval toggle */}
          <div className="form-group">
            <div className="billing-toggle">
              <button
                className={`btn ${billingInterval === 'month' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setBillingInterval('month')}
              >
                Monthly
              </button>
              <button
                className={`btn ${billingInterval === 'year' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setBillingInterval('year')}
              >
                Yearly
              </button>
            </div>
          </div>
          
          <div className="auth-divider"></div>
        </div>
        
        <div className="pricing-grid">
          {sortedProducts.map((product, index) => {
            const price = product?.prices?.find(
              (price) => price.interval === billingInterval
            );

            if (!price || !price.currency) {
              return null;
            }
            
            const priceString = formatPrice(price.unit_amount || 0, price.currency);
            const isActive = isActiveSubscription(product.name || '');
            const planType = index === 0 ? 'plan-pioneer' : (index === 1 ? 'plan-pro' : 'plan-enterprise');
            
            return (
              <div 
                key={product.id} 
                className={`auth-container pricing-plan ${planType} ${isActive ? 'pricing-active' : ''} visible`}
              >
                <div className="pricing-plan-inner">
                  {/* Header section */}
                  <div className="pricing-header">
                    <h3 className="pricing-title">{product.name}</h3>
                    <div className="pricing-price">
                      <span className="pricing-amount">{priceString}</span>
                      <span className="pricing-interval">/{billingInterval}</span>
                    </div>
                  </div>

                  {/* Features section */}
                  <div className="pricing-features">
                    <ul className="feature-list">
                      {product.description
                        ?.split(',')
                        .map((item: string, index: Key | null | undefined) => (
                          <li className="feature-item" key={index}>
                            <CircleDollarSign className="feature-icon" />
                            <span className="feature-text">{item.trim()}</span>
                          </li>
                        ))}
                    </ul>
                  </div>

                  {/* Button section */}
                  <div className="pricing-action">
                    <button
                      type="button"
                      disabled={priceIdLoading === price.id}
                      onClick={() => handleStripeCheckout(price)}
                      className="btn btn-primary btn-block"
                    >
                      {priceIdLoading === price.id && (
                        <span className="spinner"></span>
                      )}
                      {isActive ? 'Manage' : 'Subscribe'}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
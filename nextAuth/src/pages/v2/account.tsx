'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client-pages';
import { User } from '@supabase/supabase-js';

import CustomerPortalForm from '@/components/auth/forms/CustomerPortalForm';
import EmailForm from '@/components/auth/forms/EmailForm';
import NameForm from '@/components/auth/forms/NameForm';

// Define types based on your database schema
type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

type PricingPlanInterval = "day" | "week" | "month" | "year";
type PricingType = "one_time" | "recurring";
type SubscriptionStatus = "trialing" | "active" | "canceled" | "incomplete" | "incomplete_expired" | "past_due" | "unpaid" | "paused";

type Price = {
  id: string;
  active: boolean | null;
  currency: string | null;
  description: string | null;
  interval: PricingPlanInterval | null;
  interval_count: number | null;
  metadata: Json | null;
  product_id: string | null;
  trial_period_days: number | null;
  type: PricingType | null;
  unit_amount: number | null;
  products?: Product | null;
};

type Product = {
  id: string;
  active: boolean | null;
  description: string | null;
  image: string | null;
  metadata: Json | null;
  name: string | null;
};

type Subscription = {
  id: string;
  user_id: string;
  status: SubscriptionStatus | null;
  metadata: Json | null;
  price_id: string | null;
  quantity: number | null;
  cancel_at_period_end: boolean | null;
  created: string;
  current_period_start: string;
  current_period_end: string;
  ended_at: string | null;
  cancel_at: string | null;
  canceled_at: string | null;
  trial_start: string | null;
  trial_end: string | null;
};

type UserDetails = {
  avatar_url: string | null;
  billing_address: Json | null;
  full_name: string | null;
  id: string;
  payment_method: Json | null;
};

// Create combined type for subscription with joined price and product
type SubscriptionWithPriceAndProduct = Subscription & {
  prices: (Price & {
    products: Product | null;
  }) | null;
};

export default function Account() {
  const [user, setUser] = useState<User | null>(null);
  const [userDetails, setUserDetails] = useState<UserDetails | null>(null);
  const [subscription, setSubscription] = useState<SubscriptionWithPriceAndProduct | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    async function loadData() {
      const supabase = createClient();
      
      try {
        // Fetch user, user details, and subscription data
        const userResponse = await supabase.auth.getUser();
        const user = userResponse.data.user;
        
        if (!user) {
          router.push('/login');
          return;
        }
        
        // Fetch user details
        const { data: userDetails } = await supabase
          .from('users')
          .select('*')
          .single();
          
        // Fetch subscription
        const { data: subscription } = await supabase
          .from('subscriptions')
          .select('*, prices(*, products(*))')
          .in('status', ['trialing', 'active'])
          .maybeSingle();
          
        setUser(user);
        setUserDetails(userDetails as UserDetails);
        setSubscription(subscription as SubscriptionWithPriceAndProduct);
      } catch (error) {
        console.error('Error loading account data:', error);
      } finally {
        setLoading(false);
      }
    }
    
    loadData();
  }, [router]);
  
  if (loading) {
    return (
      <div className="auth-layout">
        <div className="auth-background">
          <div className="auth-background-pattern"></div>
          <div className="auth-background-gradient"></div>
        </div>
        <div className="auth-container">
          <p>Loading account information...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>
      
      <div className="auth-header" style={{maxWidth: '700px', width: '100%', textAlign: 'center'}}>
        <h1 className="auth-title">MTGBAN User Account</h1>
        <p className="auth-subtitle">
          Manage your account settings and set e-mail preferences.
        </p>
      </div>
      
      <div className="auth-container visible" style={{maxWidth: '700px'}}>
        <CustomerPortalForm subscription={subscription} />
        <div style={{marginTop: '2rem'}}></div>
        <NameForm userName={userDetails?.full_name ?? ''} />
        <div style={{marginTop: '2rem'}}></div>
        <EmailForm userEmail={user?.email ?? ''} />
      </div>
    </div>
  );
}
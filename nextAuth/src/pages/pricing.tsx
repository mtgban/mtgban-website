'use client';

import { useState, useEffect } from 'react';
import Pricing from '@/components/sub/Pricing';
import { createClient } from '@/lib/supabase/client-pages';
import { User } from '@supabase/supabase-js';

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
};

type Product = {
  id: string;
  active: boolean | null;
  description: string | null;
  image: string | null;
  metadata: Json | null;
  name: string | null;
  prices?: Price[]; // For the join query
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

// Create combined type for subscription with joined price and product
type SubscriptionWithPriceAndProduct = Subscription & {
  prices: (Price & {
    products: Product | null;
  }) | null;
};

// Create a type for products with prices
type ProductWithPrices = Product & {
  prices: Price[];
};

export default function PricingPage() {
    const [user, setUser] = useState<User | null>(null);
    const [products, setProducts] = useState<ProductWithPrices[] | null>(null);
    const [subscription, setSubscription] = useState<SubscriptionWithPriceAndProduct | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function loadData() {
            const supabase = createClient();
            
            try {
                // Get user
                const userResponse = await supabase.auth.getUser();
                
                // Get products
                const { data: productsData } = await supabase
                    .from('products')
                    .select('*, prices(*)')
                    .eq('active', true)
                    .eq('prices.active', true)
                    .order('metadata->index')
                    .order('unit_amount', { referencedTable: 'prices' });
                
                // Get subscription if user is logged in
                let subscriptionData = null;
                if (userResponse.data.user) {
                    const { data: subData } = await supabase
                        .from('subscriptions')
                        .select('*, prices(*, products(*))')
                        .in('status', ['trialing', 'active'])
                        .maybeSingle();
                    
                    subscriptionData = subData;
                }
                
                setUser(userResponse.data.user);
                setProducts(productsData as ProductWithPrices[]);
                setSubscription(subscriptionData as SubscriptionWithPriceAndProduct);
            } catch (error) {
                console.error('Error loading pricing data:', error);
            } finally {
                setLoading(false);
            }
        }
        
        loadData();
    }, []);

    if (loading) {
        return <div>Loading pricing information...</div>;
    }

    return (
        <>
            {products ? (
                <Pricing
                    user={user}
                    products={products}
                    subscription={subscription}
                />
            ) : (
                <div>No products available</div>
            )}
        </>
    );
}
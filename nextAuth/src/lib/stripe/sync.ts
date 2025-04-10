import { stripe } from './config';
import type { Stripe } from 'stripe';
import { supabaseAdmin } from '../supabase/admin';
import { Database } from '@/types/types_db';

export async function syncStripeCustomer(customerId: string) {
    try {
        const [subscription, customerResponse] = await Promise.all([
            stripe.subscriptions.list({
                customer: customerId,
                limit: 1,
                status: 'all',
                expand: ['data.default_payment_method', 'data.items.data.price.product']
            }),
            stripe.customers.retrieve(customerId, {
                expand: ['invoice_settings.default_payment_method']
            })
        ]);

        if (customerResponse.deleted) {
            console.log(`Customer ${customerId} has been deleted`);
            return null;
        }

        const customer = customerResponse as Stripe.Customer;
        const sub = subscription.data[0] as Stripe.Subscription;

        const latestData = {
            customer: {
                id: customer.id,
                email: customer.email,
                metadata: customer.metadata
            },
            subscription: sub ? {
                id: sub.id,
                status: sub.status as Database['public']['Enums']['subscription_status'],
                price_id: sub.items.data[0].price.id,
                product_id: typeof sub.items.data[0].price.product ==='string'
                    ? sub.items.data[0].price.product
                    : sub.items.data[0].price.product.id,
                current_period_end: new Date((sub as any).current_period_end * 1000).toISOString(),
                current_period_start: new Date((sub as any).current_period_start * 1000).toISOString(),
                cancel_at_period_end: sub.cancel_at_period_end,
                payment_method: sub.default_payment_method && 
                    typeof sub.default_payment_method !== 'string' ? {
                    brand: sub.default_payment_method.card?.brand ?? null,
                    last4: sub.default_payment_method.card?.last4 ?? null
                } : null
            } : null
        };

        await supabaseAdmin.rpc('sync_stripe_state', {
            p_customer_data: latestData.customer,
            p_subscription_data: latestData.subscription
        });

        return latestData;
    } catch (error) {
        console.error('Error syncing stripe customer:', error);
        throw error;
    }
}
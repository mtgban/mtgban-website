import Stripe from 'stripe';

export const stripe = new Stripe(
  process.env.STRIPE_SECRET_KEY_LIVE ?? process.env.STRIPE_SECRET_KEY ?? '',
  {
    // https://github.com/stripe/stripe-node#configuration
    // https://stripe.com/docs/api/versioning
    // @ts-ignore
    apiVersion: null,
    // Pin the API version if Stripe's latest causes issues
    appInfo: {
      name: 'MTGBAN Stripe Portal',
      version: '0.0.0',
      url: 'https://github.com/the-muppet/mtgban-stripe-payments',
    }
  }
);

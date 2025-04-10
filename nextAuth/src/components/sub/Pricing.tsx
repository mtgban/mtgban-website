"use client";

import type { Tables } from "@/types/types_db";
import { getStripe } from "@/lib/stripe/client";
import { checkoutWithStripe } from "@/lib/stripe/server";
import { getErrorRedirect } from "@/lib/helpers";
import { User } from "@supabase/supabase-js";
import { useRouter, usePathname } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import PricingCard from "./PricingCard";

type Subscription = Tables<"subscriptions">;
type Product = Tables<"products">;
type Price = Tables<"prices">;

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

const COLOR_SCHEMES = {
  pioneer: {
    primary: "#4f46e5",
    secondary: "#3730a3",
    hover: "rgba(79,70,229,0.15)",
    glow: "rgba(199,210,254,0.3)",
    accent: "#818cf8",
  },
  pro: {
    primary: "#9333ea",
    secondary: "#7e22ce",
    hover: "rgba(147,51,234,0.15)",
    glow: "rgba(233,213,255,0.3)",
    accent: "#c084fc",
  },
  enterprise: {
    primary: "#f59e0b",
    secondary: "#d97706",
    hover: "rgba(245,158,11,0.15)",
    glow: "rgba(255,233,213,0.3)",
    accent: "#fcd34d",
  },
};

type BillingInterval = "month" | "year";

const formatPrice = (amount: number, currency: string): string =>
  new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency,
    minimumFractionDigits: 0,
  }).format(amount / 100);


function getInitialData(): { user?: any; products?: any[]; subscription?: any; userDetails?: any; csrf_token?: string; } {
  if (typeof window !== "undefined" && window.__INITIAL_DATA__) {
    return window.__INITIAL_DATA__;
  }
  return { user: null, subscription: null, products: [] };
}

export default function Pricing({ 
  user: propUser, 
  products: propProducts, 
  subscription: propSubscription 
}: Props) {
  const router = useRouter();
  const currentPath = usePathname();
  const [billingInterval, setBillingInterval] = useState<BillingInterval>('month');
  const [priceIdLoading, setPriceIdLoading] = useState<string>();
  const [mounted, setMounted] = useState<boolean>(false);
  
  // Use initial data from server if available
  const initialData = useMemo(() => getInitialData(), []);
  const user = useMemo(() => propUser || initialData.user, [propUser, initialData.user]);
  const products = useMemo(() => 
    propProducts && propProducts.length > 0 
      ? propProducts 
      : initialData.products, 
    [propProducts, initialData.products]
  );
  const subscription = useMemo(() => 
    propSubscription || initialData.subscription, 
    [propSubscription, initialData.subscription]
  );


  // Memoize active subscription check
  const isActiveSubscription = useCallback(
    (productName: string): boolean =>
      subscription
        ? productName === subscription?.prices?.products?.name
        : productName === "Free Trial",
    [subscription]
  );

  useEffect(() => {
    setMounted(true);

    // Add animation to make the auth-container visible after mounting
    const timer = setTimeout(() => {
      const containers = document.querySelectorAll(".auth-container");
      containers.forEach((container) => {
        if (container instanceof HTMLElement) {
          container.classList.add("visible");
        }
      });
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  const sortedProducts = useMemo(() => {
    return [...(products || [])].sort((a, b) => {
      const priceA: number =
        a.prices?.find((p: Price) => p.interval === billingInterval)?.unit_amount || 0;
      const priceB =
        b.prices?.find((p: Price) => p.interval === billingInterval)?.unit_amount || 0;
      return priceA - priceB;
    });
  }, [products, billingInterval]);

  const handleStripeCheckout = async (price: Price): Promise<void> => {
    setPriceIdLoading(price.id);
    try {
      if (!user) {
        return router.push("/signin/signup");
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
            "An unknown error occurred.",
            "Please try again later or contact a system administrator."
          )
        );
      }

      const stripe = await getStripe();
      if (!stripe) {
        throw new Error("Failed to load Stripe");
      }

      await stripe.redirectToCheckout({ sessionId });
    } catch (error) {
      console.error("Checkout error:", error);
      router.push(
        getErrorRedirect(
          currentPath,
          "Payment processing failed.",
          "Please try again later."
        )
      );
    } finally {
      setPriceIdLoading(undefined);
    }
  };

  if (!mounted) {
    return null;
  }

  if (!products?.length) {
    return (
      <div className="auth-layout">
        <div className="auth-background">
          <div className="auth-background-pattern"></div>
          <div className="auth-background-gradient"></div>
        </div>

        <div className="auth-container visible" style={{ maxWidth: "800px" }}>
          <div className="auth-message error-message">
            <svg
              className="icon-error"
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <p>
              No subscription plan found. Create them in your{" "}
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
      </div>
    );
  }

  return (
    <div className="auth-layout">
      <div className="auth-background">
        <div className="auth-background-pattern"></div>
        <div className="auth-background-gradient"></div>
      </div>

      <div
        className="auth-header"
        style={{
          maxWidth: "900px",
          width: "100%",
          textAlign: "center",
          marginBottom: "2rem",
        }}
      >
        <h1 className="auth-title">Choose Your Plan</h1>
        <p className="auth-subtitle">
          Select the perfect subscription to unlock all features
        </p>

        {/* Billing Interval Selector */}
        <div
          className="auth-divider"
          style={{ margin: "2rem auto", maxWidth: "400px" }}
        >
          <span>Billing Interval</span>
        </div>

        <div
          className="user-welcome"
          style={{ maxWidth: "300px", margin: "0 auto" }}
        >
          <div
            className="form-check"
            style={{ justifyContent: "center", gap: "2rem", marginBottom: "0" }}
          >
            <label className="form-check-label">
              <input
                type="radio"
                name="billingInterval"
                className="form-check-input"
                checked={billingInterval === "month"}
                onChange={() => setBillingInterval("month")}
              />
              Monthly
            </label>

            <label className="form-check-label">
              <input
                type="radio"
                name="billingInterval"
                className="form-check-input"
                checked={billingInterval === "year"}
                onChange={() => setBillingInterval("year")}
              />
              Yearly
            </label>
          </div>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: "2rem",
          flexWrap: "wrap",
          justifyContent: "center",
          maxWidth: "1200px",
          margin: "0 auto",
        }}
      >
        {sortedProducts.map((product, index) => {
          const price = product?.prices?.find(
            (price: Price) => price.interval === billingInterval
          );

          if (!price || !price.currency) {
            return null;
          }

          const priceString = formatPrice(
            price.unit_amount || 0,
            price.currency
          );
          // Determine which color scheme to use based on product index or name
          const colorKey = Object.keys(COLOR_SCHEMES)[
            index % Object.keys(COLOR_SCHEMES).length
          ] as keyof typeof COLOR_SCHEMES;
          const colorScheme = COLOR_SCHEMES[colorKey];

          return (
            <PricingCard
              key={product.id}
              isActive={isActiveSubscription(product.name || "")}
              onSubscribeClick={async () => handleStripeCheckout(price)}
              className="pricing-card"
              style={{
                flex: "1 1 350px",
                maxWidth: "400px",
                animationDelay: `${index * 0.2}s`,
                marginBottom: "2rem",
                minHeight: "600px",
              }}
            >
              {({ handleSubscribe, isAnimating }) => (
                <>
                  {/* Header */}
                  <div
                    className="auth-title"
                    style={{
                      fontSize: "1.75rem",
                      textAlign: "left",
                      marginBottom: "0.5rem",
                    }}
                  >
                    {product.name}
                  </div>

                  <div
                    style={{
                      fontSize: "2.5rem",
                      fontWeight: "bold",
                      margin: "1.5rem 0",
                      color: "var(--primary-color)",
                    }}
                  >
                    {priceString}
                    <span
                      style={{
                        fontSize: "1rem",
                        opacity: 0.8,
                        marginLeft: "0.25rem",
                      }}
                    >
                      /{billingInterval}
                    </span>
                  </div>

                  {/* Features List */}
                  <div className="form-group" style={{ marginBottom: "4rem" }}>
                    <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                      {product.description?.split(",").map((item: any | null, index: number) => (
                        <li
                          key={index}
                          className="description-item"
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            marginBottom: "1rem",
                            animation:
                              "fadeSlideUp 0.8s var(--transition-smooth) forwards",
                            animationDelay: `${0.3 + index * 0.1}s`,
                            opacity: 0,
                            transform: "translateY(20px)",
                          }}
                        >
                          <svg
                            style={{
                              width: "1.25rem",
                              height: "1.25rem",
                              color: "var(--success-color)",
                              flexShrink: 0,
                              marginRight: "0.75rem",
                              marginTop: "0.25rem",
                            }}
                            xmlns="http://www.w3.org/2000/svg"
                            width="24"
                            height="24"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          >
                            <circle cx="12" cy="12" r="10"></circle>
                            <path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"></path>
                            <path d="M12 18V6"></path>
                          </svg>
                          <span>{item.trim()}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Button */}
                  <div
                    style={{
                      position: "absolute",
                      bottom: "2rem",
                      left: "2.75rem",
                      right: "2.75rem",
                    }}
                  >
                    <button
                      className="btn btn-primary btn-block"
                      disabled={priceIdLoading === price.id || isAnimating}
                      onClick={handleSubscribe}
                    >
                      {(priceIdLoading === price.id || isAnimating) && (
                        <span className="spinner"></span>
                      )}
                      {subscription ? "Manage" : "Subscribe"}
                    </button>
                  </div>
                </>
              )}
            </PricingCard>
          );
        })}
      </div>
    </div>
  );
}

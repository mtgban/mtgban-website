// Initialize Stripe (key will be set server-side)
let stripe = null;

document.addEventListener('DOMContentLoaded', function () {
    loadSubscriptionPlans();
});

async function loadSubscriptionPlans() {
    const plansDiv = document.getElementById('subscriptionPlans');
    const errorDiv = document.getElementById('errorMessage');

    try {
        const response = await fetch('/api/plans', {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to load plans');
        }

        const plans = await response.json();

        plansDiv.innerHTML = '';

        const sortedPlans = Object.entries(plans).sort((a, b) => a[1].price - b[1].price);

        sortedPlans.forEach(([planId, plan], index) => {
            const isPopular = index === 1;

            const planCard = document.createElement('div');
            planCard.className = 'column';
            planCard.style.cssText = 'max-width: 300px; margin: 10px; padding: 20px; border: 2px solid var(--paleblue); border-radius: 8px; text-align: center;';

            if (isPopular) {
                planCard.style.borderColor = 'var(--asuccess)';
                planCard.style.transform = 'scale(1.05)';
            }

            planCard.innerHTML = `
                ${isPopular ? '<div style="background: var(--asuccess); color: white; padding: 5px; margin: -20px -20px 10px -20px; border-radius: 6px 6px 0 0;">MOST POPULAR</div>' : ''}
                <h2 style="color: var(--headingtext); margin-bottom: 10px;">${plan.name}</h2>
                <div style="margin: 20px 0;">
                    <span style="font-size: 36px; font-weight: bold; color: var(--headingtext);">$${(plan.price / 100).toFixed(0)}</span>
                    <span style="color: var(--greytext);">/month</span>
                </div>
                <p style="color: var(--greytext); margin-bottom: 20px; min-height: 60px;">${plan.description}</p>
                <ul style="list-style: none; padding: 0; margin: 20px 0; text-align: left;">
                    ${plan.features.map(feature => `<li style="padding: 5px 0;">✓ ${feature}</li>`).join('')}
                </ul>
                <button onclick="selectPlan('${planId}')" class="btn ${isPopular ? 'success' : 'normal'}" 
                        style="padding: 12px 30px; font-size: 16px; width: 100%; margin-top: 20px;">
                    ${isPopular ? 'Get Started' : 'Select Plan'}
                </button>
            `;

            plansDiv.appendChild(planCard);
        });

    } catch (error) {
        console.error('Error loading plans:', error);
        errorDiv.textContent = 'Failed to load subscription plans. Please refresh the page or try again later.';
        errorDiv.style.display = 'block';
        plansDiv.innerHTML = '';
    }
}

async function selectPlan(planId, event) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.style.display = 'none';

    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Processing...';
    button.disabled = true;

    try {
        const response = await fetch('/api/checkout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ plan_id: planId })
        });

        if (response.status === 401) {
            window.location.href = '/auth?redirect=' + encodeURIComponent(window.location.pathname);
            return;
        }

        if (!response.ok) {
            throw new Error('Failed to create checkout session');
        }

        const data = await response.json();

        if (data.url) {
            window.location.href = data.url;
        } else {
            throw new Error('No checkout URL received');
        }

    } catch (error) {
        console.error('Checkout error:', error);
        errorDiv.textContent = 'Failed to start checkout process. Please try again.';
        errorDiv.style.display = 'block';

        button.textContent = originalText;
        button.disabled = false;
    }
}

// Format price for display
function formatPrice(cents) {
    return (cents / 100).toFixed(2);
}
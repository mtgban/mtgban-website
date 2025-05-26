document.addEventListener('DOMContentLoaded', function () {
    loadSubscriptionInfo();
    loadPreferences();

    // Handle preferences form submission
    const preferencesForm = document.getElementById('preferencesForm');
    if (preferencesForm) {
        preferencesForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            await savePreferences();
        });
    }
});

// Load subscription information
async function loadSubscriptionInfo() {
    const subscriptionDiv = document.getElementById('subscriptionInfo');

    try {
        const response = await fetch('/api/user/subscription', {
            credentials: 'include'
        });

        const data = await response.json();

        if (response.ok) {
            if (data.has_subscription) {
                const sub = data.subscription;
                const plan = data.plan_info;

                let statusClass = 'success';
                if (sub.status === 'canceled' || sub.status === 'past_due') {
                    statusClass = 'danger';
                } else if (sub.status === 'trialing') {
                    statusClass = 'warning';
                }

                subscriptionDiv.innerHTML = `
                    <table style="margin: 20px 0;">
                        <tr>
                            <td style="font-weight: bold; padding-right: 20px;">Plan:</td>
                            <td>${plan.name || 'Unknown Plan'}</td>
                        </tr>
                        <tr>
                            <td style="font-weight: bold; padding-right: 20px;">Status:</td>
                            <td class="${statusClass}">${sub.status.charAt(0).toUpperCase() + sub.status.slice(1)}</td>
                        </tr>
                        <tr>
                            <td style="font-weight: bold; padding-right: 20px;">Next Billing Date:</td>
                            <td>${new Date(sub.current_period_end).toLocaleDateString()}</td>
                        </tr>
                        <tr>
                            <td style="font-weight: bold; padding-right: 20px;">Features:</td>
                            <td>${plan.features ? plan.features.join(', ') : 'Standard access'}</td>
                        </tr>
                    </table>
                    <div style="margin-top: 20px;">
                        <a href="/subscription/manage" class="btn normal" style="padding: 10px 20px; text-decoration: none;">
                            Manage Subscription
                        </a>
                        ${sub.status === 'active' ? `
                        <button onclick="confirmCancelSubscription()" class="btn warning" style="padding: 10px 20px; margin-left: 10px;">
                            Cancel Subscription
                        </button>
                        ` : ''}
                    </div>
                `;
            } else {
                subscriptionDiv.innerHTML = `
                    <p>You don't have an active subscription.</p>
                    <a href="/subscription/plans" class="btn success" style="padding: 10px 20px; text-decoration: none; display: inline-block; margin-top: 10px;">
                        View Available Plans
                    </a>
                `;
            }
        } else {
            subscriptionDiv.innerHTML = '<p class="danger">Failed to load subscription information.</p>';
        }
    } catch (error) {
        subscriptionDiv.innerHTML = '<p class="danger">An error occurred loading subscription information.</p>';
    }
}

// Load user preferences
async function loadPreferences() {
    try {
        const response = await fetch('/api/user/preferences', {
            credentials: 'include'
        });

        if (response.ok) {
            const prefs = await response.json();

            // Set form values based on loaded preferences
            if (prefs.defaultView) {
                document.getElementById('defaultView').value = prefs.defaultView;
            }
            if (prefs.emailNotifications !== undefined) {
                document.getElementById('emailNotifications').checked = prefs.emailNotifications === 'true';
            }
            if (prefs.showBuylist !== undefined) {
                document.getElementById('showBuylist').checked = prefs.showBuylist === 'true';
            }
        }
    } catch (error) {
        console.error('Failed to load preferences:', error);
    }
}

async function savePreferences() {
    const messageDiv = document.getElementById('prefMessage');

    const preferences = [
        { key: 'defaultView', value: document.getElementById('defaultView').value },
        { key: 'emailNotifications', value: document.getElementById('emailNotifications').checked.toString() },
        { key: 'showBuylist', value: document.getElementById('showBuylist').checked.toString() }
    ];

    try {
        let allSuccess = true;

        for (const pref of preferences) {
            const response = await fetch('/api/preferences', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(pref)
            });

            if (!response.ok) {
                allSuccess = false;
            }
        }

        if (allSuccess) {
            messageDiv.textContent = 'Preferences saved successfully!';
            messageDiv.className = 'success';
        } else {
            messageDiv.textContent = 'Some preferences failed to save. Please try again.';
            messageDiv.className = 'danger';
        }

        messageDiv.style.display = 'block';
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 3000);
    } catch (error) {
        messageDiv.textContent = 'An error occurred. Please try again.';
        messageDiv.className = 'danger';
        messageDiv.style.display = 'block';
    }
}

function copyAPIKey(event) {
    const apiKeyInput = document.getElementById('apiKey');
    navigator.clipboard.writeText(apiKeyInput.value);

    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    setTimeout(() => {
        button.textContent = originalText;
    }, 2000);
}

async function confirmCancelSubscription() {
    if (!confirm('Are you sure you want to cancel your subscription? You will retain access until the end of your billing period.')) {
        return;
    }

    try {
        const response = await fetch('/api/user/subscription/cancel', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            alert('Your subscription has been canceled. You will retain access until the end of your billing period.');
            loadSubscriptionInfo();
        } else {
            alert('Failed to cancel subscription. Please try again or contact support.');
        }
    } catch (error) {
        alert('An error occurred. Please try again.');
    }
}

async function confirmDeleteAccount() {
    const confirmText = prompt('This action cannot be undone. Type "DELETE" to confirm account deletion:');

    if (confirmText !== 'DELETE') {
        return;
    }

    try {
        const response = await fetch('/api/user/delete', {
            method: 'DELETE',
            credentials: 'include'
        });

        if (response.ok) {
            alert('Your account has been deleted.');
            window.location.href = '/';
        } else {
            alert('Failed to delete account. Please contact support.');
        }
    } catch (error) {
        alert('An error occurred. Please try again.');
    }
}
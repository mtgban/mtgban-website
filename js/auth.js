document.addEventListener('DOMContentLoaded', function () {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            const errorDiv = document.getElementById('loginError');

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    const urlParams = new URLSearchParams(window.location.search);
                    const redirect = urlParams.get('redirect') || '/';
                    window.location.href = redirect;
                } else {
                    errorDiv.textContent = data.error || 'Login failed. Please check your credentials.';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'An error occurred. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    }

    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const fullName = document.getElementById('signupName').value;
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            const passwordConfirm = document.getElementById('signupPasswordConfirm').value;
            const errorDiv = document.getElementById('signupError');
            const successDiv = document.getElementById('signupSuccess');

            errorDiv.style.display = 'none';
            successDiv.style.display = 'none';

            if (password !== passwordConfirm) {
                errorDiv.textContent = 'Passwords do not match.';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                const response = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email,
                        password,
                        full_name: fullName
                    })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    if (data.message.includes('check your email')) {
                        successDiv.textContent = data.message;
                        successDiv.style.display = 'block';
                        signupForm.reset();
                    } else {
                        window.location.href = '/';
                    }
                } else {
                    errorDiv.textContent = data.error || 'Signup failed. Please try again.';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'An error occurred. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    }
});

async function handleOAuthLogin(provider) {
    try {
        const response = await fetch('/api/auth/oauth/signin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                provider,
                redirect_to: window.location.origin + '/auth/callback'
            })
        });

        const data = await response.json();

        if (response.ok && data.url) {
            window.location.href = data.url;
        } else {
            alert('Failed to initiate ' + provider + ' login. Please try again.');
        }
    } catch (error) {
        alert('An error occurred. Please try again.');
    }
}

async function handleLogout() {
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            window.location.href = '/';
        }
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/';
    }
}
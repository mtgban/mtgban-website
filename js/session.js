function sessionExpiredInterceptor(response) {
    if (response.status === 401 || response.status === 403) {
        // Check if we're already at the auth page to avoid redirect loops
        if (!window.location.pathname.includes("/auth")) {
            window.location.href = "/auth";
            return Promise.reject("Session expired. Redirecting to login page.");
        }
    }
    return response;
}

// Add the interceptor to fetch API
function fetchWithInterceptor(url, options) {
    return fetch(url, options)
        .then(sessionExpiredInterceptor)
        .catch(error => {
            console.error("Fetch error:", error);
            throw error;
        });
}

fetchWithInterceptor("/api/some-endpoint", {
    method: "GET",
    headers: {
        "Content-Type": "application/json"
    }
})
    .then(response => response.json())
    .then(data => {
        console.log("Data:", data);
    })
    .catch(error => {
        console.error("Error:", error);
    });
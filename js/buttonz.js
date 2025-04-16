function account() {
    window.location.href = "https://mtgban-stripe-payments.vercel.app/account";
}

function subscribe() {
    window.location.href = "https://mtgban-stripe-payments.vercel.app/pricing/details";
}


function logout() {
    fetch("/next-api/auth/logout", {
        method: "POST",
        credentials: "include",
    })
        .then(() => {
            window.location.href = "/";
        })
        .catch(error => {
            console.error("Error logging out:", error);
        });
}

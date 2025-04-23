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

document.addEventListener('DOMContentLoaded', function() {
    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
        const dropdowns = document.getElementsByClassName('dropdown-content');
        const dropdownButtons = document.getElementsByClassName('dropbtn');
        
        let clickedOnDropdown = false;
        
        // Check if click was on dropdown button
        for (let i = 0; i < dropdownButtons.length; i++) {
            if (dropdownButtons[i].contains(event.target)) {
                clickedOnDropdown = true;
                break;
            }
        }
        
        if (!clickedOnDropdown) {
            for (let i = 0; i < dropdowns.length; i++) {
                if (dropdowns[i].classList.contains('show')) {
                    dropdowns[i].classList.remove('show');
                }
            }
        }
    });
    
    // Toggle dropdown on mobile
    const dropdownButtons = document.getElementsByClassName('dropbtn');
    for (let i = 0; i < dropdownButtons.length; i++) {
        dropdownButtons[i].addEventListener('click', function(event) {
            // Only toggle on mobile devices
            if (window.innerWidth <= 768) {
                const content = this.nextElementSibling;
                
                // Close all other dropdowns
                const dropdowns = document.getElementsByClassName('dropdown-content');
                for (let j = 0; j < dropdowns.length; j++) {
                    if (dropdowns[j] !== content && dropdowns[j].classList.contains('show')) {
                        dropdowns[j].classList.remove('show');
                    }
                }
                
                content.classList.toggle('show');
                event.stopPropagation();
            }
        });
    }
});

// The store cart buttons show how to use the BAN-to-Cart loader before
// opening the store, since nothing on the store's cart page tells the user
// to click it. A user who has it set up can skip the panel from then on.
var CART_PROMPT_SKIP_KEY = "cartPromptSkip";
var cartPromptLink = null;

// openCartPrompt is a store button's onclick: true lets the link open the
// store.
function openCartPrompt(link) {
    try {
        if (localStorage.getItem(CART_PROMPT_SKIP_KEY) === "true") {
            return true;
        }
    } catch (e) {}
    return showCartPrompt(link);
}

// showCartPrompt opens the panel for link whatever the skip flag says, for
// the "?" beside the button: a user who skipped it can get the loader back.
function showCartPrompt(link) {
    cartPromptLink = link.href;
    // The box says what is stored, never what the browser restored into it,
    // and unticking it here brings the panel back
    var skip = false;
    try {
        skip = localStorage.getItem(CART_PROMPT_SKIP_KEY) === "true";
    } catch (e) {}
    document.getElementById("cart-prompt-skip").checked = skip;
    var buylist = link.dataset.buylist === "true";
    document.querySelectorAll("#cart-overlay .cart-prompt-store").forEach(function(el) {
        el.textContent = link.dataset.store;
    });
    document.querySelectorAll("#cart-overlay .cart-prompt-buylist").forEach(function(el) {
        el.hidden = !buylist;
    });
    document.querySelectorAll("#cart-overlay .cart-prompt-retail").forEach(function(el) {
        el.hidden = buylist;
    });
    document.getElementById("cart-overlay").classList.add("open");
    return false;
}

function closeCartPrompt() {
    document.getElementById("cart-overlay").classList.remove("open");
}

function openCartStore() {
    try {
        if (document.getElementById("cart-prompt-skip").checked) {
            localStorage.setItem(CART_PROMPT_SKIP_KEY, "true");
        } else {
            localStorage.removeItem(CART_PROMPT_SKIP_KEY);
        }
    } catch (e) {}
    closeCartPrompt();
    window.open(cartPromptLink, "_blank", "noopener");
}

document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeCartPrompt();
});

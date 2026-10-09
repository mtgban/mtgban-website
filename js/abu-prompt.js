// The ABU buttons show how to use the loader before opening ABU, since
// nothing on ABU's cart page tells the user to click it. A user who has
// it set up can skip the panel from then on.
var ABU_PROMPT_SKIP_KEY = "abuPromptSkip";
var abuPromptLink = null;

// openABUPrompt is the ABU button's onclick: true lets the link open ABU.
function openABUPrompt(link) {
    try {
        if (localStorage.getItem(ABU_PROMPT_SKIP_KEY) === "true") {
            return true;
        }
    } catch (e) {}
    return showABUPrompt(link);
}

// showABUPrompt opens the panel for link whatever the skip flag says, for
// the "?" beside the button: a user who skipped it can get the loader back.
function showABUPrompt(link) {
    abuPromptLink = link.href;
    document.getElementById("abu-overlay").classList.add("open");
    return false;
}

function closeABUPrompt() {
    document.getElementById("abu-overlay").classList.remove("open");
}

function openABU() {
    if (document.getElementById("abu-prompt-skip").checked) {
        try {
            localStorage.setItem(ABU_PROMPT_SKIP_KEY, "true");
        } catch (e) {}
    }
    closeABUPrompt();
    window.open(abuPromptLink, "_blank", "noopener");
}

document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeABUPrompt();
});

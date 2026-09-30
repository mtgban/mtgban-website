function openStorePrompt() {
    document.getElementById("store-overlay").classList.add("open");
    document.querySelector('#store-overlay [name="store_name"]').focus();
}
function closeStorePrompt() {
    document.getElementById("store-overlay").classList.remove("open");
}
document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeStorePrompt();
});

// Posts the rows on the page with the store's properties: the form the
// page posts itself back with is hidden, so the prompt lives beside it
// and its fields are copied over.
function runPublishStore() {
    var overlay = document.getElementById("store-overlay");
    var required = ["store_name", "store_shorthand"];
    for (var i = 0; i < required.length; i++) {
        var field = overlay.querySelector('[name="' + required[i] + '"]');
        if (!field.value.trim()) {
            field.focus();
            return;
        }
    }

    ensureHashesLoaded('all');
    var form = document.getElementById("upload_form");
    form.querySelectorAll('input[name^="store_"]').forEach(function(el) { el.remove(); });
    overlay.querySelectorAll('input[name^="store_"]').forEach(function(field) {
        if (field.type === "checkbox" && !field.checked) return;
        var input = document.createElement("input");
        input.type = "hidden";
        input.name = field.name;
        input.value = field.value;
        form.appendChild(input);
    });

    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    var scope = document.getElementById("res_csvscope");
    if (scope) {
        scope.value = "";
    }
    document.getElementById("res_publishstore").value = "true";
    form.target = '';
    form.submit();
}

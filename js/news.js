// Newspaper filter persistence via cookies + tablesort init
(function() {
    var filterKeys = ["filter", "rarity", "finish", "bucket", "min_price", "max_price", "min_change", "max_change"];

    // Save all current filter values to cookies
    function saveFilters(form) {
        filterKeys.forEach(function(key) {
            var el = form.elements[key];
            if (el) {
                setCookie("news_" + key, el.value, 365);
            }
        });
    }

    // Called by dropdown onchange before form.submit()
    // This ensures cookies are saved even though programmatic
    // form.submit() does not fire the "submit" event
    window.newsSubmit = function(el) {
        saveFilters(el.form);
        el.form.submit();
    };

    // Save text input values when form submits via Enter key
    // (Enter-triggered submit DOES fire the "submit" event)
    var form = document.querySelector('form[action="newspaper"]');
    if (form) {
        form.addEventListener("submit", function() {
            saveFilters(form);
        });
    }

    // Tablesort initialization
    var newsTable = document.getElementById('newsTable');
    if (newsTable) new Tablesort(newsTable);
})();

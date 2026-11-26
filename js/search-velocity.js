// Remembers whether the Sales Velocity row was last opened or closed, so
// the next results page draws it the same way (VelocityOpen, search.go).
(function () {
    function remember(e) {
        var row = e && e.target;
        if (!row || !row.classList || !row.classList.contains('sales-velocity')) return;
        setCookie('SearchVelocityOpen', row.open ? 'open' : 'closed', 1000);
    }

    // toggle does not bubble, so it is caught on the way down.
    document.addEventListener('toggle', remember, true);

    self.SearchVelocity = { remember: remember };
})();

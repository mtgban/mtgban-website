// The grants table edits in place: each cell is a field of its row's save
// form. A row's Save stays quiet until a field of it changes, so the rows
// that have something to save stand out, and Escape puts a row back.
(function () {
    var rows = document.querySelectorAll('tr.admin-grant-row');
    rows.forEach(function (row) {
        var fields = Array.prototype.slice.call(row.querySelectorAll('input[form], select[form]'));
        var saved = fields.map(function (field) { return field.value; });
        var refresh = function () {
            var edited = fields.some(function (field, i) { return field.value !== saved[i]; });
            row.classList.toggle('edited', edited);
        };
        fields.forEach(function (field, i) {
            field.addEventListener('input', refresh);
            field.addEventListener('change', refresh);
            field.addEventListener('keydown', function (e) {
                if (e.key !== 'Escape') {
                    return;
                }
                field.value = saved[i];
                refresh();
                field.blur();
            });
        });
    });
})();

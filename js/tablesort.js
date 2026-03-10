(function() {
    document.addEventListener("DOMContentLoaded", function() {
        document.querySelectorAll("table[data-sortable]").forEach(initSortable);
    });

    function initSortable(table) {
        var headers = table.querySelectorAll("th[data-sort-type]");
        headers.forEach(function(th, index) {
            // Find the actual column index in the full header row
            var allTh = Array.from(th.closest("tr").children);
            var colIndex = allTh.indexOf(th);

            th.style.cursor = "pointer";
            th.setAttribute("title", "Click to sort");

            th.addEventListener("click", function(e) {
                // Don't interfere with existing sort links if clicked directly
                if (e.target.tagName === "A" || e.target.tagName === "I") return;
                sortTable(table, colIndex, th);
            });
        });
    }

    function sortTable(table, colIndex, th) {
        var rows = Array.from(table.querySelectorAll("tr"));
        // Skip the header row(s)
        var headerRows = [];
        var dataRows = [];
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].querySelector("th")) {
                headerRows.push(rows[i]);
            } else {
                dataRows.push(rows[i]);
            }
        }

        if (dataRows.length === 0) return;

        var isAsc = th.getAttribute("data-sort-dir") !== "asc";

        // Reset all headers in this table
        th.closest("tr").querySelectorAll("th[data-sort-type]").forEach(function(h) {
            h.removeAttribute("data-sort-dir");
            var old = h.querySelector(".sort-arrow");
            if (old) old.remove();
        });

        th.setAttribute("data-sort-dir", isAsc ? "asc" : "desc");
        var arrow = document.createElement("span");
        arrow.className = "sort-arrow";
        arrow.textContent = isAsc ? " \u25B2" : " \u25BC";
        th.appendChild(arrow);

        var type = th.getAttribute("data-sort-type");

        dataRows.sort(function(a, b) {
            var aVal = getCellValue(a.cells[colIndex], type);
            var bVal = getCellValue(b.cells[colIndex], type);
            if (aVal === bVal) return 0;
            var result = aVal < bVal ? -1 : 1;
            return isAsc ? result : -result;
        });

        // Re-append sorted rows after the last header row
        var parent = headerRows[headerRows.length - 1].parentNode;
        dataRows.forEach(function(row) {
            parent.appendChild(row);
        });
    }

    function getCellValue(cell, type) {
        if (!cell) return "";
        var text = cell.textContent.trim();
        switch (type) {
            case "dollar":
                return parseFloat(text.replace(/[$,]/g, "")) || 0;
            case "percent":
                return parseFloat(text.replace(/[%]/g, "")) || 0;
            case "number":
                return parseFloat(text.replace(/,/g, "")) || 0;
            default:
                return text.toLowerCase();
        }
    }
})();

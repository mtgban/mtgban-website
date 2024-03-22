function filterArbitTable() {
    var input, filter, tables, tr, td, i, j, txtValue;
    input = document.getElementById("filterInput");
    filter = input.value.toUpperCase();
    tables = document.getElementsByClassName("filterable");

    for (j = 0; j < tables.length; j++) {
        tr = tables[j].getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) {
            td = tr[i].getElementsByTagName("td")[1]; // filtering on edition
            if (td) {
                txtValue = td.textContent || td.innerText;
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
    }
};

function filterEditionsTable() {
    var input, filter, tables, tr, td, i, j, txtValue;
    input = document.getElementById("filterInput");
    filter = input.value.toUpperCase();
    tables = document.getElementsByClassName("filterable");

    for (j = 0; j < tables.length; j++) {
        tr = tables[j].getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) {
            td = tr[i].getElementsByTagName("td")[0]; // filtering on Name
            if (td) {
                txtValue = td.textContent || td.innerText;
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
    }
};

function filterPageContent() {
    var input, filter, nobrs, a, i, txtValue;
    input = document.getElementById("filterInput");
    filter = input.value.toUpperCase();
    nobrs = document.getElementsByTagName("nobr");

    for (i = 0; i < nobrs.length; i++) {
        a = nobrs[i].getElementsByTagName("a")[0];
        if (a) {
            txtValue = a.textContent || a.innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                nobrs[i].style.display = "";
            } else {
                nobrs[i].style.display = "none";
            }
        }
    }
};

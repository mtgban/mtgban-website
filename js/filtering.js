function filterTableByEdition() {
    var input, filter, tables, tr, i, j, txtValue, el;
    input = document.getElementById("filterInput");
    filter = input.value.toUpperCase();
    tables = document.getElementsByClassName("filterable");

    for (j = 0; j < tables.length; j++) {
        tr = tables[j].getElementsByTagName("tr");
        for (i = 1; i < tr.length; i++) {
            el = tr[i].querySelector('.card-edition');
            if (!el) {
                el = tr[i].getElementsByTagName("td")[1];
            }
            if (el) {
                txtValue = el.textContent || el.innerText;
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
    }
};

function filterTableByName() {
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

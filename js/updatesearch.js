function getDirectQty(obj, uuid) {
    if (obj) {
        obj.style.opacity = '0';
        window.setTimeout(function restore() {
            obj.style.opacity = '1';
        }, 150);
    }

    fetch('/api/tcgplayer/directqty/' + uuid)
    .then((response) => response.json())
    .then((data) => {
        let span = document.getElementById('directqty-' + uuid);
        if (span) {
            span.setAttribute("onclick", "javascript:void(0)");
        }

        if (data) {
            data.forEach(element => {
                let qtyTd = document.getElementById('qty-TCGDirect-' + element.condition + '-' + uuid);
                if (qtyTd) {
                    qtyTd.innerHTML = '<b>' + element.direct_inventory + '</b>';
                }
            });
        } else {
            const conds = ["NM", "SP", "MP", "HP"];
            conds.forEach(element => {
                let qtyTd = document.getElementById('qty-TCGDirect-' + element + '-' + uuid);
                if (qtyTd) {
                    qtyTd.innerHTML = '<b>N/A</b>';
                }
            });
        }
    });
}


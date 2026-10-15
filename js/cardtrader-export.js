// Downloads the two tables the CardTrader inventory page embeds, built in
// the browser so the seller's token travels to the server exactly once.

(function () {
    "use strict";

    function field(value) {
        var s = value == null ? "" : String(value);
        if (/[",\r\n]/.test(s)) {
            return '"' + s.replace(/"/g, '""') + '"';
        }
        return s;
    }

    function csv(rows) {
        return rows.map(function (row) {
            return row.map(field).join(",");
        }).join("\r\n") + "\r\n";
    }

    function raw(data) {
        return csv(data.raw || []);
    }

    function ban(data) {
        return csv(data.ban || []);
    }

    function download(name, text) {
        var blob = new Blob([text], {type: "text/csv"});
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 0);
    }

    window.CTExport = {csv: csv, raw: raw, ban: ban};

    var data = window.BAN_CT_EXPORT;
    if (!data) {
        return;
    }

    function bind(id, name, build) {
        var button = document.getElementById(id);
        if (button) {
            button.addEventListener("click", function () { download(name, build(data)); });
        }
    }

    bind("ct-download-raw", "cardtrader-raw.csv", raw);
    bind("ct-download-ban", "cardtrader-ban.csv", ban);
})();

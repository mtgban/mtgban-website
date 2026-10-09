(async function () {
    // The BAN-to-Cart loader, installed as a bookmarklet. It runs on the
    // store cart page an upload page "Load at" button opens, reads the list
    // from the page's #ban= fragment, and loads it into the cart of the
    // user on that store. docs/store-carts.md has what each store accepts.
    var match = /[#&]ban=([^&]*)/.exec(location.hash);
    var version = /[#&]v=([^&]*)/.exec(location.hash);
    var store = null;
    if (location.hostname === "abugames.com") {
        store = abuStore();
    } else if (location.hostname === "www.coolstuffinc.com") {
        store = csiStore();
    } else if (location.hostname === "sellyourcards.starcitygames.com") {
        store = scgStore();
    } else if (location.hostname === "www.mtgmintcard.com") {
        store = mintStore();
    } else if (location.hostname === "shop.strikezoneonline.com") {
        store = szStore();
    }
    // A store whose cart names a row other than the link does maps it
    var key = (store && store.key) || function (id) {
        return id;
    };
    if (!store || !match) {
        alert("Drag this link to your bookmarks bar. Then click it after the store's page loads.");
        return;
    }
    // The site stamps this copy and every link with the loader's version, and
    // an older copy must not touch a cart
    if (!version || version[1] !== "__BAN_VERSION__") {
        alert("Your BAN-to-Cart bookmark is out of date. Go back to BAN, press the ? next to the Load button, " +
            "and drag BAN-to-Cart to your bookmarks bar again, replacing the old one.");
        return;
    }
    if (!store.loggedIn()) {
        alert("Log in to " + store.name + " first, then click the BAN-to-Cart bookmark again.");
        return;
    }

    // The page link percent-encodes the separators
    var ids = [];
    var quantities = {};
    decodeURIComponent(match[1]).split(",").forEach(function (pair) {
        var parts = pair.split(":");
        var qty = parseInt(parts[1], 10);
        if (!/^[\w-]+$/.test(parts[0]) || !(qty > 0)) {
            return;
        }
        if (!(parts[0] in quantities)) {
            ids.push(parts[0]);
            quantities[parts[0]] = 0;
        }
        quantities[parts[0]] += qty;
    });

    var banner = document.createElement("div");
    banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:99999;padding:12px;" +
        "background:#1f2937;color:#fff;font:16px sans-serif;text-align:center";
    document.body.appendChild(banner);

    // A store that matches the list itself takes it whole and shows its own
    // review of it
    if (store.upload) {
        banner.textContent = "BAN: handing your list to " + store.name;
        try {
            await store.upload(ids, quantities);
        } catch (err) {
            banner.remove();
            alert(err.message);
        }
        return;
    }

    try {
        // A card already in the cart adds no line
        var present = await store.cartIDs();
        var room = store.maxLines > 0 ? store.maxLines - present.length : Infinity;
        var rows = [];
        var noRoom = 0;
        ids.forEach(function (id) {
            if (present.indexOf(key(id)) >= 0) {
                rows.push(id);
            } else if (room > 0) {
                rows.push(id);
                room--;
            } else {
                noRoom++;
            }
        });

        var done = 0;
        var unknown = 0;
        for (var i = 0; i < rows.length; i += store.chunkSize) {
            var chunk = rows.slice(i, i + store.chunkSize);
            while (chunk.length > 0) {
                banner.textContent = "BAN: loading cards into your " + store.name + " cart, " +
                    done + " of " + rows.length + " done";
                if (await store.send(chunk, quantities, present)) {
                    done += chunk.length;
                    break;
                }
                // ABU stops at an id it does not know, keeping the rows before
                // it without naming it. Its store also skips a row it has none
                // of, so each row missing from the cart is tried alone until
                // one is refused.
                var now = await store.cartIDs();
                var bad = -1;
                for (var j = 0; j < chunk.length && bad < 0; j++) {
                    if (now.indexOf(key(chunk[j])) < 0 && !(await store.send([chunk[j]], quantities))) {
                        bad = j;
                    }
                }
                if (bad < 0) {
                    throw new Error(store.name + " refused part of the list (422).");
                }
                done += bad + 1;
                unknown++;
                chunk = chunk.slice(bad + 1);
            }
        }

        var after = await store.cartIDs();
        var loaded = rows.filter(function (id) {
            return after.indexOf(key(id)) >= 0;
        }).length;
        var message = "Loaded " + loaded + " cards into your " + store.name + " cart.";
        if (unknown > 0) {
            message += " " + unknown + " that " + store.name + " no longer lists were left out.";
        }
        if (rows.length - unknown - loaded > 0) {
            message += " " + (rows.length - unknown - loaded) + " were not taken by " + store.name + ".";
        }
        if (noRoom > 0) {
            message += " " + noRoom + " did not fit: " + store.name + "'s cart holds " + store.maxLines + " lines.";
        }
        alert(message);
        history.replaceState(null, "", location.pathname + location.search);
        location.reload();
    } catch (err) {
        banner.remove();
        alert(err.message);
    }

    // abuStore loads ABU's buylist or store cart, whichever page this is,
    // through the API ABU's own pages call with the user's token.
    function abuStore() {
        var buylist = location.pathname.indexOf("/cartview/buylist") === 0;
        var cart = "https://api.abugames.com/" + (buylist ? "buy-list-cart" : "cart");
        var headers = {
            Authorization: "Bearer " + localStorage.getItem("accessToken-ABU"),
            "Content-Type": "application/json",
            Accept: "application/json"
        };
        return {
            name: "ABU",
            // A guest cannot have a buylist cart, and a guest's store cart is
            // lost at login
            loggedIn: function () {
                return localStorage.getItem("isLoggedIn") === "true";
            },
            // ABU's own pages stop at these many lines. The store checks stock
            // at about a second a row, so its chunks stay under a minute.
            maxLines: buylist ? 750 : 1000,
            chunkSize: buylist ? 300 : 50,
            cartIDs: async function () {
                var resp = await fetch(cart, {headers: headers});
                if (resp.status === 401) {
                    throw new Error("ABU logged you out. Log in again, then click the BAN-to-Cart bookmark again.");
                }
                if (!resp.ok) {
                    throw new Error("ABU could not read your cart (" + resp.status + ").");
                }
                var body = await resp.json();
                var items = (body.data && body.data.relationships && body.data.relationships.items &&
                    body.data.relationships.items.data) || [];
                return items.map(function (item) {
                    return String(item.id);
                });
            },
            // false when ABU refused an id it does not know
            send: async function (chunk, qty) {
                var resp = await fetch(cart + "/item", {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(chunk.map(function (id) {
                        return {item_id: id, quantity: qty[id]};
                    }))
                });
                if (!resp.ok && resp.status !== 422) {
                    throw new Error("ABU refused the list (" + resp.status + ").");
                }
                return resp.ok;
            }
        };
    }

    // scgStore hands SCG the list as one CSV, the import its sell site offers,
    // and opens SCG's review of it, where the user adds the matches to the
    // cart. SCG matches a row on its SKU alone.
    function scgStore() {
        return {
            name: "SCG",
            loggedIn: function () {
                return true;
            },
            upload: async function (rows, qty) {
                var csv = "quantity,productid\n" + rows.map(function (id) {
                    return qty[id] + "," + id;
                }).join("\n") + "\n";
                var form = new FormData();
                form.append("file", new Blob([csv], {type: "text/csv"}), "ban_prices.csv");
                form.append("fileFormatId", "1");
                form.append("invalidFinishAction", "use_default");
                form.append("invalidFinishDefault", "N");
                form.append("invalidLanguageAction", "use_default");
                form.append("invalidLanguageDefault", "en");
                form.append("invalidQuantityAction", "skip_row");
                form.append("invalidQuantityDefault", "");
                form.append("manualColumnAssignments", "{}");
                var token = /(?:^|; )XSRF-TOKEN=([^;]*)/.exec(document.cookie);
                var resp = await fetch("/api/CSV2/upload", {
                    method: "POST",
                    headers: {
                        Accept: "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                        "X-XSRF-TOKEN": token ? decodeURIComponent(token[1]) : ""
                    },
                    body: form
                });
                if (resp.status === 401) {
                    throw new Error("Log in to SCG first, then click the BAN-to-Cart bookmark again.");
                }
                var body = await resp.json().catch(function () {
                    return {};
                });
                if (!resp.ok || !body.fileId) {
                    throw new Error("SCG refused the list (" + (body.errorMessage || resp.status) + ").");
                }
                location.href = "/mtg/uploads/" + body.fileId;
            }
        };
    }

    // csiStore loads CSI's sell cart, kept by the browser's cookies, the way
    // its sell list page adds a row. CSI skips an id it does not buy and adds
    // to a card already in the cart.
    function csiStore() {
        return {
            name: "CSI",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            chunkSize: 100,
            cartIDs: async function () {
                var resp = await fetch("/buylist_cart.php");
                if (!resp.ok) {
                    throw new Error("CSI could not read your sell cart (" + resp.status + ").");
                }
                var page = await resp.text();
                var found = [];
                var re = /name="bl_q\[(\d+)\]"/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    found.push(m[1]);
                }
                return found;
            },
            send: async function (chunk, qty) {
                var resp = await fetch("/ajax_buylist.php", {
                    method: "POST",
                    headers: {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
                    body: "ajaxtype=addtocart&ajaxdata=" + encodeURIComponent(chunk.map(function (id) {
                        return "uid_" + id + "qty_" + qty[id] + "||";
                    }).join(""))
                });
                if (!resp.ok) {
                    throw new Error("CSI refused the list (" + resp.status + ").");
                }
                return true;
            }
        };
    }

    // mintStore loads Mint's buylist cart, kept by its session cookie, one
    // card per call: the call its cart page's quantity picker makes, which
    // sets the quantity and quietly skips an id Mint does not buy.
    function mintStore() {
        return {
            name: "MTG Mint Card",
            // The header links to the login page only for a guest
            loggedIn: function () {
                return !document.querySelector('a[href$="/login"]');
            },
            maxLines: 0,
            chunkSize: 1,
            cartIDs: async function () {
                var resp = await fetch("/buylist-cart");
                if (!resp.ok) {
                    throw new Error("MTG Mint Card could not read your buylist cart (" + resp.status + ").");
                }
                var page = await resp.text();
                var found = [];
                var re = /name="multiple_quantity_(\d+)"/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    found.push(m[1]);
                }
                return found;
            },
            send: async function (chunk, qty) {
                for (var i = 0; i < chunk.length; i++) {
                    var resp = await fetch("/ajax_index.php?ajax_main_page=ajax_buylist_cart_detail" +
                        "&action=update_buy_list_product&buylist_cart_product_id=" + chunk[i] +
                        "&buylist_cart_product_qty=" + qty[chunk[i]]);
                    if (!resp.ok) {
                        throw new Error("MTG Mint Card refused the list (" + resp.status + ").");
                    }
                }
                return true;
            }
        };
    }

    // szStore loads Strike Zone's cart, kept by its cookies: the buylist, or
    // the store when the link says side=retail. Its CSV import takes the whole
    // list at once, keyed by the id go-mtgban computes for each row; a plain
    // 637-C code goes through its Sell to Us or Add to Cart link, one copy per
    // call, and the cart form.
    function szStore() {
        var retail = /[#&]side=retail(&|$)/.test(location.hash);
        var line = retail ? "S-" : "B-";
        // Whether the cart holds a row on either side, as last read
        var filled = false;
        // Strike Zone answers "too many requests" to the cart pages after
        // about 100 calls, for some minutes, so a long list waits it out
        async function call(url, opts) {
            for (;;) {
                var resp = await fetch(url, opts);
                if (!resp.ok) {
                    throw new Error("Strike Zone refused the list (" + resp.status + ").");
                }
                var page = await resp.text();
                if (!/too many requests/i.test(page)) {
                    return page;
                }
                for (var wait = 300; wait > 0; wait--) {
                    banner.textContent = "BAN: Strike Zone pauses its cart after about 100 cards. " +
                        "Keep this tab open, continuing in " + wait + " s.";
                    await new Promise(function (resolve) {
                        setTimeout(resolve, 1000);
                    });
                }
            }
        }
        function add(code) {
            return call("/TUser?MC=CUVC&" + (retail ? "Add=" : "Buy=") + code + "&MF=B&BUID=637");
        }
        // The cart page lists only its first 800 rows, so the cart is read
        // through its CSV export, where a buylist row's name starts "Sell to
        // us - "; an empty cart answers with its page instead
        async function readCart() {
            var page = await call("/TUser?MC=CUVC&MF=B", {
                method: "POST",
                body: new URLSearchParams({BUID: "637", STORE_ID: "637", CMD: "Tools ...", TOOL_SELECT: "XC", ACT: "Export"})
            });
            var found = [];
            filled = false;
            if (page.indexOf("#Usc Id,") !== 0) {
                if (!/no items in your cart/i.test(page)) {
                    throw new Error("Strike Zone's cart could not be read.");
                }
                return found;
            }
            page.split(/\r?\n/).slice(1).forEach(function (row) {
                var fields = row.split(",");
                if (!fields[0]) {
                    return;
                }
                filled = true;
                if ((fields[1].indexOf("Sell to us - ") === 0) !== retail) {
                    found.push(szCode(fields[0]));
                }
            });
            return found;
        }
        return {
            name: "Strike Zone",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            // Imports of 1,000 and 3,000 rows load whole too, in 7 and 44 s;
            // 300 keeps the banner moving every few seconds
            chunkSize: 300,
            // The cart names a row by its plain code
            key: szCode,
            cartIDs: readCart,
            // Both ways set a quantity, trimmed to what Strike Zone wants or
            // has, and skip an id it does not list
            send: async function (chunk, qty, present) {
                var csv = "#Usc Id,Inventory Name,Store Name,Buy #,Buy $,Sell #,Sell $\r\n";
                var imported = [];
                var linked = false;
                var update = new URLSearchParams({BUID: "637", STORE_ID: "637", CMD: "Update"});
                var rows = 0;
                for (var i = 0; i < chunk.length; i++) {
                    var id = chunk[i];
                    var code = szCode(id);
                    if (code !== id) {
                        csv += id + ",x,Strike Zone Online," +
                            (retail ? "NC,0," + qty[id] : qty[id] + ",0,NC") + ",0\r\n";
                        imported.push(code);
                        continue;
                    }
                    if (present.indexOf(code) < 0) {
                        await add(code);
                        linked = true;
                    }
                    if (present.indexOf(code) >= 0 || qty[id] !== 1) {
                        update.append(String(rows), line + code);
                        update.append(rows + "Q", String(qty[id]));
                        rows++;
                    }
                }
                if (rows > 0) {
                    await call("/TUser?MC=CUVC&MF=B", {method: "POST", body: update});
                }
                if (imported.length > 0) {
                    // The import does nothing to a cart with no row yet, and
                    // Strike Zone skips a card it no longer lists, so cards go
                    // in through their links until one stays
                    if (!filled && linked) {
                        await readCart();
                    }
                    for (var j = 0; !filled && j < imported.length; j++) {
                        await add(imported[j]);
                        await readCart();
                    }
                    if (!filled) {
                        return true;
                    }
                    var form = new FormData();
                    form.append("BUID", "637");
                    form.append("STORE_ID", "637");
                    form.append("CMD", "Tools ...");
                    form.append("TOOL_SELECT", "CI");
                    form.append("ACT", "Do import");
                    form.append("FILE", new Blob([csv], {type: "text/csv"}), "ban_prices.csv");
                    await call("/TUser?MC=CUVC&MF=B", {method: "POST", body: form});
                }
                return true;
            }
        };
    }

    // szCode is the plain 637-C code a Strike Zone import id was computed
    // from, by undoing the shift of its digits, or id itself when it is not
    // one. docs/store-carts.md has how the id is built.
    function szCode(id) {
        var m = /^USCIDU-637-F-(\d{5,6})-(\d{3})-[A-Z]{3}-[A-Z]{3}$/.exec(id);
        if (!m) {
            return id;
        }
        var shifts = [8, 9, 7, 2, 9, 1, 8, 9, 7];
        var digits = (m[1] + m[2]).split("").map(function (d, i) {
            return (Number(d) + 10 - shifts[i]) % 10;
        }).join("");
        return "637-C-" + digits.slice(0, m[1].length) + "-" + digits.slice(m[1].length);
    }
})();

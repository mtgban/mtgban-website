(async function () {
    // The BAN-to-Cart loader, installed as a bookmarklet. It runs on the
    // store cart page an upload page "Load at" button opens, reads the list
    // from the page's #ban= fragment, and loads it into the cart of the
    // user on that store. docs/store-carts.md has what each store accepts.
    var match = /[#&]ban=([^&]*)/.exec(location.hash);
    var store = null;
    if (location.hostname === "abugames.com") {
        store = abuStore();
    } else if (location.hostname === "www.coolstuffinc.com") {
        store = csiStore();
    }
    if (!store || !match) {
        alert("Drag this link to your bookmarks bar. Then click it after the store's page loads.");
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
        if (!/^\d+$/.test(parts[0]) || !(qty > 0)) {
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

    try {
        // A card already in the cart adds no line
        var present = await store.cartIDs();
        var room = store.maxLines > 0 ? store.maxLines - present.length : Infinity;
        var rows = [];
        var noRoom = 0;
        ids.forEach(function (id) {
            if (present.indexOf(id) >= 0) {
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
                if (await store.send(chunk, quantities)) {
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
                    if (now.indexOf(chunk[j]) < 0 && !(await store.send([chunk[j]], quantities))) {
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
            return after.indexOf(id) >= 0;
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
        history.replaceState(null, "", location.pathname);
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
})();

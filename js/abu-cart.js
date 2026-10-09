(async function () {
    // MTGBAN's ABU loader, installed as a bookmarklet. It runs on the ABU
    // cart page the upload page's "Load at ABU" buttons open, reads the list
    // from the page's #mtgban= fragment, and loads it into the cart of the
    // user logged in to ABU there. docs/abu-carts.md has what ABU accepts.
    var match = /[#&]mtgban=([^&]*)/.exec(location.hash);
    if (location.hostname !== "abugames.com" || !match) {
        alert("Drag this link to your bookmarks bar. Then click it after the page on ABU loads.");
        return;
    }
    // A guest cannot have a buylist cart, and a guest's store cart is lost
    // at login
    if (localStorage.getItem("isLoggedIn") !== "true") {
        alert("Log in to ABU first, then click the BAN-to-ABU bookmark again.");
        return;
    }

    var buylist = location.pathname.indexOf("/cartview/buylist") === 0;
    var cart = "https://api.abugames.com/" + (buylist ? "buy-list-cart" : "cart");
    // ABU's own pages stop at these many lines. The store checks stock at
    // about a second a row, so its chunks stay under a minute.
    var maxLines = buylist ? 750 : 1000;
    var chunkSize = buylist ? 300 : 50;
    var headers = {
        Authorization: "Bearer " + localStorage.getItem("accessToken-ABU"),
        "Content-Type": "application/json",
        Accept: "application/json"
    };

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

    async function cartIDs() {
        var resp = await fetch(cart, {headers: headers});
        if (resp.status === 401) {
            throw new Error("ABU logged you out. Log in again, then click the BAN-to-ABU bookmark again.");
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
    }

    async function send(chunk) {
        var resp = await fetch(cart + "/item", {
            method: "POST",
            headers: headers,
            body: JSON.stringify(chunk.map(function (id) {
                return {item_id: id, quantity: quantities[id]};
            }))
        });
        if (!resp.ok && resp.status !== 422) {
            throw new Error("ABU refused the list (" + resp.status + ").");
        }
        return resp.ok;
    }

    try {
        // A card already in the cart takes the list's quantity and adds no line
        var present = await cartIDs();
        var room = maxLines - present.length;
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
        for (var i = 0; i < rows.length; i += chunkSize) {
            var chunk = rows.slice(i, i + chunkSize);
            while (chunk.length > 0) {
                banner.textContent = "MTGBAN: loading cards into your ABU cart, " + done + " of " + rows.length + " done";
                if (await send(chunk)) {
                    done += chunk.length;
                    break;
                }
                // ABU stops at an id it does not know, keeping the rows before
                // it without naming it. The store also skips a row it has none
                // of, so each row missing from the cart is tried alone until
                // one is refused.
                var now = await cartIDs();
                var bad = -1;
                for (var j = 0; j < chunk.length && bad < 0; j++) {
                    if (now.indexOf(chunk[j]) < 0 && !(await send([chunk[j]]))) {
                        bad = j;
                    }
                }
                if (bad < 0) {
                    throw new Error("ABU refused part of the list (422).");
                }
                done += bad + 1;
                unknown++;
                chunk = chunk.slice(bad + 1);
            }
        }

        var after = await cartIDs();
        var loaded = rows.filter(function (id) {
            return after.indexOf(id) >= 0;
        }).length;
        var message = "Loaded " + loaded + " cards into your ABU cart.";
        if (unknown > 0) {
            message += " " + unknown + " that ABU no longer lists were left out.";
        }
        if (rows.length - unknown - loaded > 0) {
            message += " " + (rows.length - unknown - loaded) + " that ABU has none of were skipped.";
        }
        if (noRoom > 0) {
            message += " " + noRoom + " did not fit: ABU's cart holds " + maxLines + " lines.";
        }
        alert(message);
        history.replaceState(null, "", location.pathname);
        location.reload();
    } catch (err) {
        banner.remove();
        alert(err.message);
    }
})();

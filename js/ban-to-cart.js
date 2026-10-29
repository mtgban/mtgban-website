(async function () {
    // The BAN-to-Cart loader, installed as a bookmarklet. It runs on the
    // store cart page an upload page "Load at" button opens, reads the list
    // from the page's #ban= fragment, and loads it into the cart of the
    // user on that store. docs/store-carts.md has what each store accepts.
    var match = /[#&]ban=([^&]*)/.exec(location.hash);
    var version = /[#&]v=([^&]*)/.exec(location.hash);
    // Rows BAN found no item at this store for, left out before the link
    var skip = /[#&]skip=(\d+)/.exec(location.hash);
    var store = null;
    if (location.hostname === "abugames.com") {
        store = abuStore();
    } else if (location.hostname === "www.coolstuffinc.com") {
        store = location.pathname.indexOf("/main_view_cart.php") === 0 ? csiShop() : csiStore();
    } else if (location.hostname === "sellyourcards.starcitygames.com") {
        store = scgStore();
    } else if (location.hostname === "www.mtgmintcard.com") {
        store = mintStore();
    } else if (location.hostname === "manapool.com") {
        store = mpStore();
    } else if (location.hostname === "buylist.gamenerdz.com") {
        store = storePassStore("Game Nerdz");
    } else if (location.hostname === "buylist.vegas.singles") {
        store = storePassStore("Vegas Singles");
    } else if (location.hostname === "www.gamenerdz.com") {
        store = gnShop();
    } else if (location.hostname === "www.cardtrader.com") {
        store = ctStore();
    } else if (location.hostname === "www.manaleak.com") {
        store = mlStore();
    } else if (location.hostname === "shop.strikezoneonline.com") {
        store = szStore();
    } else if (location.hostname === "www.hareruyamtg.com") {
        store = haStore();
    } else if (location.hostname === "www.cardkingdom.com") {
        store = ckStore();
    } else if (location.hostname === "www.tcgplayer.com") {
        store = tcgStore();
    }
    // A store whose cart names a row other than the link does maps it
    var key = (store && store.key) || function (id) {
        return id;
    };
    if (!store) {
        alert("Drag this link to your bookmarks bar. Then click it after the store's page loads.");
        return;
    }
    // A store's login drops the fragment on its way back to the cart
    var again = "go back to BAN and press Load at " + store.name + " again.";
    if (!match) {
        alert("This page has no list from BAN. Log in to " + store.name + " if you aren't, then " + again);
        return;
    }
    // The site stamps this copy and every link with the loader's version, a
    // hash that cannot tell which is older, and a mismatch must not touch a cart
    if (!version || version[1] !== "__BAN_VERSION__") {
        alert("Your BAN-to-Cart bookmark or this BAN page is from a different version. Reload BAN, " +
            "press the ? next to the Load button, and drag BAN-to-Cart to your bookmarks bar again, replacing the old one.");
        return;
    }
    if (!store.loggedIn()) {
        alert("Log in to " + store.name + " first, then " + again);
        return;
    }

    // The page link percent-encodes the separators
    var list;
    try {
        list = decodeURIComponent(match[1]);
    } catch (err) {
        alert("The list from BAN could not be read: " + again);
        return;
    }
    var ids = [];
    var quantities = {};
    var unread = 0;
    list.split(",").forEach(function (pair) {
        var parts = pair.split(":");
        var qty = parseInt(parts[1], 10);
        if (!/^[\w-]+$/.test(parts[0]) || !(qty > 0)) {
            unread += pair ? 1 : 0;
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
    // Leaving the page mid-load stops it with the cart half filled, so the
    // browser asks first until the loader is done
    window.addEventListener("beforeunload", stay);

    // A store that matches the list itself takes it whole and shows its own
    // review of it
    if (store.upload) {
        banner.textContent = "BAN: handing your list to " + store.name + ". Keep this tab open until it finishes.";
        try {
            await store.upload(ids, quantities);
        } catch (err) {
            window.removeEventListener("beforeunload", stay);
            banner.remove();
            alert(err.message);
        }
        return;
    }

    var release = function () {};
    try {
        // A store that sends the difference from one read of the cart loads
        // one tab at a time, or two tabs would each add the same difference
        if (store.lock) {
            banner.textContent = "BAN: waiting for another tab to finish loading your " + store.name + " cart.";
            release = await hold(store.lock);
        }
        banner.textContent = "BAN: reading your " + store.name + " cart. Keep this tab open until it finishes.";
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
                    done + " of " + rows.length + " done. Keep this tab open until it finishes.";
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
        release();
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
        message += leftOut();
        window.removeEventListener("beforeunload", stay);
        alert(message);
        history.replaceState(null, "", location.pathname + location.search);
        location.reload();
    } catch (err) {
        release();
        window.removeEventListener("beforeunload", stay);
        banner.remove();
        alert(err.message);
    }

    function stay(event) {
        event.preventDefault();
        event.returnValue = "";
    }

    // leftOut tells the rows the store never saw: pairs that did not read,
    // and cards BAN found no item at this store for
    function leftOut() {
        var note = "";
        if (unread > 0) {
            note += " " + unread + " in the list from BAN could not be read and were left out.";
        }
        if (skip && parseInt(skip[1], 10) > 0) {
            note += " " + parseInt(skip[1], 10) + " on BAN have no " + store.name + " item and were left out.";
        }
        return note;
    }

    // hold takes the store origin's lock of that name, shared by its tabs,
    // and resolves to the function that lets it go. A browser with no locks,
    // or one that refuses the request, runs unlocked.
    function hold(name) {
        var locks = window.navigator && window.navigator.locks;
        if (!locks) {
            return Promise.resolve(function () {});
        }
        return new Promise(function (granted) {
            locks.request(name, function () {
                return new Promise(function (release) {
                    granted(release);
                });
            }).catch(function () {
                granted(function () {});
            });
        });
    }

    // listingsUpload is the upload of a store whose cart is filled from its
    // live listings at or under BAN's price: fill adds what it can of a
    // row's need, counting the copies added in progress.got. An add adds to
    // the cart, so two tabs would each add the same cards, and a second load
    // of the whole list would add again the cards a stopped one did: the
    // page then keeps only the rest, a card cut short at what it still lacks.
    function listingsUpload(name, lock, fill) {
        return async function (rows, qty) {
            var release = await hold("ban-to-cart-" + lock);
            var added = 0;
            var cut = 0;
            var none = 0;
            var progress = {};
            function report() {
                var message = "Added " + added + " cards to your " + name + " cart, on top of what it held.";
                if (cut > 0) {
                    message += " " + cut + " were cut to the copies " + name + " has at or under BAN's price.";
                }
                if (none > 0) {
                    message += " " + none + " that " + name + " has none of at or under BAN's price were left out.";
                }
                return message;
            }
            try {
                for (var i = 0; i < rows.length; i++) {
                    banner.textContent = "BAN: loading cards into your " + name + " cart, " + i + " of " +
                        rows.length + " done. Keep this tab open until it finishes.";
                    progress.got = 0;
                    await fill(rows[i], qty[rows[i]], progress);
                    if (progress.got <= 0) {
                        none++;
                        continue;
                    }
                    added++;
                    if (progress.got < qty[rows[i]]) {
                        cut++;
                    }
                }
            } catch (err) {
                if (progress.got > 0) {
                    added++;
                    qty[rows[i]] -= progress.got;
                }
                if (added === 0) {
                    throw err;
                }
                var rest = rows.slice(i);
                history.replaceState(null, "", location.pathname + location.search + location.hash.replace(/([#&]ban=)[^&]*/,
                    "$1" + encodeURIComponent(rest.map(function (id) {
                        return id + ":" + qty[id];
                    }).join(","))));
                throw new Error(err.message + " " + report() + " The other " + rest.length +
                    " were not added, and this page now holds only those: click BAN-to-Cart again to load them." + leftOut());
            } finally {
                release();
            }
            window.removeEventListener("beforeunload", stay);
            alert(report() + leftOut());
            history.replaceState(null, "", location.pathname + location.search);
            location.reload();
        };
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
                    throw new Error("ABU logged you out. Log in again, then " + again);
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
                    throw new Error("Log in to SCG first, then " + again);
                }
                var body = await resp.json().catch(function () {
                    return {};
                });
                if (!resp.ok || !body.fileId) {
                    throw new Error("SCG refused the list (" + (body.errorMessage || resp.status) + ").");
                }
                window.removeEventListener("beforeunload", stay);
                if (leftOut()) {
                    alert("Handed " + rows.length + " cards to SCG for review." + leftOut());
                }
                location.href = "/mtg/uploads/" + body.fileId;
            }
        };
    }

    // csiStore loads CSI's sell cart, kept by the browser's cookies, the way
    // its sell list page adds a row. CSI skips an id it does not buy and adds
    // to a card already in the cart, so such a card gets the difference.
    function csiStore() {
        var held = {};
        return {
            name: "CSI",
            lock: "ban-to-cart-csi",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            chunkSize: 100,
            cartIDs: async function () {
                if (/[#&]side=retail(&|$)/.test(location.hash)) {
                    throw new Error("This is CSI's sell cart, but the list is for its store. Go back to BAN and press its button again.");
                }
                var resp = await fetch("/buylist_cart.php");
                if (!resp.ok) {
                    throw new Error("CSI could not read your sell cart (" + resp.status + ").");
                }
                var page = await resp.text();
                held = {};
                var re = /<[^>]*name="bl_q\[(\d+)\]"[^>]*>/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    var value = /value="(\d+)"/.exec(m[0]);
                    held[m[1]] = value ? Number(value[1]) : 0;
                }
                return Object.keys(held);
            },
            send: async function (chunk, qty) {
                var add = "";
                for (var i = 0; i < chunk.length; i++) {
                    var more = qty[chunk[i]] - (held[chunk[i]] || 0);
                    if (more > 0) {
                        add += "uid_" + chunk[i] + "qty_" + more + "||";
                    }
                }
                if (!add) {
                    return true;
                }
                var resp = await fetch("/ajax_buylist.php", {
                    method: "POST",
                    headers: {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
                    body: "ajaxtype=addtocart&ajaxdata=" + encodeURIComponent(add)
                });
                if (!resp.ok) {
                    throw new Error("CSI refused the list (" + resp.status + ").");
                }
                return true;
            }
        };
    }

    // csiShop loads CSI's store cart, kept by the browser's cookies, keyed by
    // <product id>-<row id>, one row per condition and finish. Its add takes
    // many rows at once but adds to a row already in the cart, so such a row
    // gets the difference, or is deleted and added again when the list asks
    // for fewer. CSI trims a quantity to its stock and skips a row it does
    // not sell.
    function csiShop() {
        var held = {};
        return {
            name: "CSI",
            lock: "ban-to-cart-csi",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            // One add of 40 rows took 3.6 s
            chunkSize: 100,
            // The cart names a row by its row id alone
            key: function (id) {
                return id.split("-")[1];
            },
            cartIDs: async function () {
                if (!/[#&]side=retail(&|$)/.test(location.hash)) {
                    throw new Error("This is CSI's store cart, but the list is for its sell cart. Go back to BAN and press its button again.");
                }
                var resp = await fetch("/main_view_cart.php");
                if (!resp.ok) {
                    throw new Error("CSI could not read your cart (" + resp.status + ").");
                }
                var page = await resp.text();
                held = {};
                var re = /name="cartQty\[(\d+)\]"[^>]*value="(\d+)"/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    held[m[1]] = Number(m[2]);
                }
                return Object.keys(held);
            },
            send: async function (chunk, qty) {
                var add = [];
                for (var i = 0; i < chunk.length; i++) {
                    var parts = chunk[i].split("-");
                    var want = qty[chunk[i]];
                    var have = held[parts[1]] || 0;
                    if (want < have) {
                        var resp = await fetch("/main_view_cart.php?action=delete-" + parts[1]);
                        if (!resp.ok) {
                            throw new Error("CSI refused the list (" + resp.status + ").");
                        }
                        have = 0;
                    }
                    if (want > have) {
                        add.push("atc[" + parts[0] + "][" + parts[1] + "]=" + (want - have));
                    }
                }
                if (add.length > 0) {
                    var sent = await fetch("/ajax_cart_qty_add.php", {
                        method: "POST",
                        headers: {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
                        body: add.map(function (pair) {
                            return pair.replace(/\[/g, "%5B").replace(/\]/g, "%5D");
                        }).join("&") + "&referrer="
                    });
                    if (!sent.ok) {
                        throw new Error("CSI refused the list (" + sent.status + ").");
                    }
                }
                return true;
            }
        };
    }

    // mintStore loads Mint's buylist cart, or its store cart on that cart's
    // page, kept by its session cookie, one card per call: the call each
    // cart's quantity picker makes, which sets the quantity, trims it to what
    // Mint wants or has, and quietly skips an id Mint does not take there.
    function mintStore() {
        var buylist = location.pathname.indexOf("/shopping-cart") !== 0;
        var retail = /[#&]side=retail(&|$)/.test(location.hash);
        var cartPage = buylist ? "/buylist-cart" : "/shopping-cart";
        var call = buylist ?
            "ajax_buylist_cart_detail&action=update_buy_list_product" :
            "ajax_shopping_cart&action=update_product";
        var field = buylist ? "buylist_cart_product_" : "shopping_cart_product_";
        return {
            name: "MTG Mint Card",
            // The header links to the login page only for a guest
            loggedIn: function () {
                return !document.querySelector('a[href$="/login"]');
            },
            maxLines: 0,
            // A call takes 0.4 to 1 s
            chunkSize: 1,
            cartIDs: async function () {
                // A product id can be both a store row and a buylist one
                if (retail === buylist) {
                    throw new Error("This is not the MTG Mint Card cart the list is for. Go back to BAN and press its button again.");
                }
                var resp = await fetch(cartPage);
                if (!resp.ok) {
                    throw new Error("MTG Mint Card could not read your cart (" + resp.status + ").");
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
                    var resp = await fetch("/ajax_index.php?ajax_main_page=" + call +
                        "&" + field + "id=" + chunk[i] + "&" + field + "qty=" + qty[chunk[i]]);
                    if (!resp.ok) {
                        throw new Error("MTG Mint Card refused the list (" + resp.status + ").");
                    }
                }
                return true;
            }
        };
    }

    // mpStore loads Mana Pool's cart, which holds sellers' listings rather
    // than products and is kept in the browser's storage, from where Mana
    // Pool syncs a signed-in user's queued changes. Its public optimizer
    // picks the cheapest listings for each product id; a card it has fewer
    // of goes again at that many, and one it has none of is left out. The
    // optimizer is not told what the cart holds, so the picks add to it.
    function mpStore() {
        // An empty cart, as Mana Pool starts one
        var empty = {version: 5, revision: "00000000-0000-4000-8000-000000000000", cart: {entries: []}, changes: []};
        // answer reads the optimizer's answer, which streams one better
        // solution per line while it works, keeping the last, and shows
        // each in the banner as it comes
        async function answer(resp, cards) {
            var text = "";
            var last = {};
            function take(line) {
                var parsed;
                try {
                    parsed = JSON.parse(line);
                } catch (err) {
                    return;
                }
                // A line that is not a solution or an error leaves the last
                if (!parsed || typeof parsed !== "object") {
                    return;
                }
                last = parsed;
                if (last.totals && last.totals.total_cents > 0) {
                    banner.textContent = "BAN: Mana Pool is finding the cheapest listings for " + cards + " cards, best so far $" +
                        (last.totals.total_cents / 100).toFixed(2) + ". Keep this tab open until it finishes.";
                }
            }
            var reader = resp.body && resp.body.getReader ? resp.body.getReader() : null;
            if (!reader) {
                (await resp.text()).split("\n").forEach(take);
                return last;
            }
            var decoder = new TextDecoder();
            for (;;) {
                var part = await reader.read();
                // The end flushes whatever the decoder still holds
                text += part.done ? decoder.decode() : decoder.decode(part.value, {stream: true});
                var lines = text.split("\n");
                text = part.done ? "" : lines.pop();
                lines.forEach(take);
                if (part.done) {
                    return last;
                }
            }
        }
        function readCart() {
            var stored = JSON.parse(localStorage.getItem("manapool-cart") || "null") || empty;
            if (stored.version !== 5 || !stored.cart || !Array.isArray(stored.cart.entries) || !Array.isArray(stored.changes)) {
                throw new Error("Mana Pool keeps its cart in a way this BAN-to-Cart does not know. Nothing was loaded.");
            }
            return stored;
        }
        return {
            name: "Mana Pool",
            loggedIn: function () {
                return true;
            },
            upload: async function (rows, qty) {
                readCart();
                var lines = rows.map(function (id) {
                    return {id: id, qty: qty[id], want: qty[id]};
                });
                var picks = [];
                // cutSoFar counts the lines a 409 has cut or dropped so far
                function cutSoFar(all) {
                    return all.filter(function (line) {
                        return line.qty < line.want;
                    }).length;
                }
                // The optimizer takes up to 2,000 lines a call
                for (var i = 0; i < lines.length; i += 2000) {
                    var chunk = lines.slice(i, i + 2000);
                    while (chunk.length > 0) {
                        banner.textContent = "BAN: asking Mana Pool for " + chunk.length + " cards" +
                            (cutSoFar(lines) > 0 ? ", " + cutSoFar(lines) + " cut or left out so far" : "") +
                            ". Keep this tab open until it finishes.";
                        var resp = await fetch("/api/v1/buyer/optimizer", {
                            method: "POST",
                            headers: {"Content-Type": "application/json"},
                            body: JSON.stringify({model: "lowest_price", cart: chunk.map(function (line) {
                                return {type: "product", product_type: "mtg_single", product_ids: [line.id], quantity_requested: line.qty};
                            })})
                        });
                        var body = await answer(resp, chunk.length);
                        // Mana Pool refuses the whole call over the lines it
                        // cannot fill, naming each with what it has
                        if (resp.status === 409 && Array.isArray(body.details) && body.details.length > 0) {
                            var cut = 0;
                            body.details.forEach(function (detail) {
                                var line = chunk[detail.item && detail.item.index];
                                if (!line || line.qty === 0) {
                                    return;
                                }
                                cut++;
                                if (detail.total_available > 0 && detail.total_available < line.qty) {
                                    line.qty = detail.total_available;
                                } else {
                                    line.qty = 0;
                                }
                            });
                            if (cut === 0) {
                                throw new Error("Mana Pool refused the list (" + (body.message || resp.status) + ").");
                            }
                            chunk = chunk.filter(function (line) {
                                return line.qty > 0;
                            });
                            continue;
                        }
                        if (!resp.ok || !Array.isArray(body.cart)) {
                            throw new Error("Mana Pool refused the list (" + (body.message || resp.status) + ").");
                        }
                        picks = picks.concat(body.cart);
                        break;
                    }
                }
                // A line can be cut by one 409 and dropped by the next, so
                // each counts once, by what was last asked of it
                var trimmed = lines.filter(function (line) {
                    return line.qty > 0 && line.qty < line.want;
                }).length;
                var missing = lines.filter(function (line) {
                    return line.qty === 0;
                }).length;
                // Read again with no wait before the write, so a change made
                // meanwhile stays; added the way Mana Pool's own optimizer
                // adds a listing
                var stored = readCart();
                picks.forEach(function (pick) {
                    var entry = stored.cart.entries.find(function (e) {
                        return e.inventoryId === pick.inventory_id;
                    });
                    if (entry) {
                        entry.quantitySelected += pick.quantity_selected;
                    } else {
                        stored.cart.entries.push({inventoryId: pick.inventory_id, quantitySelected: pick.quantity_selected, source: "optimizer", optimizerTouched: true});
                    }
                    stored.changes.push([pick.inventory_id, pick.quantity_selected, "optimizer", true]);
                });
                localStorage.setItem("manapool-cart", JSON.stringify(stored));
                var message = "Added " + (rows.length - missing) + " cards to your Mana Pool cart, on top of what it held.";
                if (trimmed > 0) {
                    message += " " + trimmed + " were cut to the copies Mana Pool has.";
                }
                if (missing > 0) {
                    message += " " + missing + " that Mana Pool has none of were left out.";
                }
                window.removeEventListener("beforeunload", stay);
                alert(message + leftOut());
                history.replaceState(null, "", location.pathname + location.search);
                location.reload();
            }
        };
    }

    // storePassStore loads a StorePass buylist cart, which the buylist page
    // keeps in its own state and saves whole under the session its cookie
    // names. Each card goes through the page's own add, which prices it from
    // the store's settings and holds it to the store's limit; a row names
    // <product id>-<variant id>, the variant one per condition where the
    // store prices each.
    function storePassStore(name) {
        var page = null;
        var session = /(?:^|; )bga-buylist-cart-(\w+)=([^;]*)/.exec(document.cookie);
        // cart is the buylist page's own cart component
        function cart() {
            if (page) {
                return page;
            }
            var nodes = document.querySelectorAll("div, button");
            for (var i = 0; i < nodes.length; i++) {
                var fiber = nodes[i][Object.keys(nodes[i]).find(function (k) {
                    return k.indexOf("__reactFiber$") === 0;
                })];
                for (; fiber; fiber = fiber["return"]) {
                    if (fiber.stateNode && typeof fiber.stateNode.didAddToCart === "function") {
                        page = fiber.stateNode;
                        return page;
                    }
                }
            }
            throw new Error(name + "'s buylist page has changed, so BAN cannot fill its cart. Nothing was loaded.");
        }
        async function call(url, opts) {
            var resp = await fetch(url, opts);
            if (!resp.ok) {
                throw new Error(name + " refused the list (" + resp.status + ").");
            }
            return resp.json();
        }
        // settle resolves once the page has applied its pending changes
        function settle(change) {
            return new Promise(function (resolve) {
                cart().setState(change || {}, resolve);
            });
        }
        function storeID() {
            return cart().state.store.id;
        }
        // condition is the one the page's add takes for a variant
        function condition(product, variant) {
            if (cart().state.store.buylist_settings.condition_type === "per-product") {
                return variant.title;
            }
            return product.condition;
        }
        // lineID names a cart line as a row does
        function lineID(line) {
            var variants = line.store_pass_variant_info || [];
            var variant = variants.find(function (v) {
                return v.title === line.condition;
            }) || (variants.length === 1 ? variants[0] : null);
            return variant ? line.product_id + "-" + variant.id : String(line.product_id);
        }
        return {
            name: name,
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            chunkSize: 10,
            lock: "ban-to-cart-" + (session ? session[1] : "storepass"),
            // The cart as last saved, which another tab may have changed
            // since this page loaded
            cartIDs: async function () {
                if (/[#&]side=retail(&|$)/.test(location.hash)) {
                    throw new Error("This is " + name + "'s buylist, but the list is for its store. Go back to BAN and press its button again.");
                }
                if (!session) {
                    throw new Error("This page has no " + name + " buylist cart yet. Reload it, then " + again);
                }
                var saved = await call("/saas/buylist-session?session_id=" + encodeURIComponent(decodeURIComponent(session[2])) +
                    "&store_id=" + storeID(), {headers: {"Content-Type": "application/json"}});
                await settle({cartProducts: saved.cartProducts || []});
                return cart().state.cartProducts.map(lineID);
            },
            // A held card gets the difference to the list's quantity; the
            // page skips a card the store does not price, and the cart is
            // saved as the page saves it
            send: async function (chunk, qty) {
                for (var i = 0; i < chunk.length; i++) {
                    var ids = chunk[i].split("-");
                    var found = await call("/saas/search?mongo=true&store_id=" + storeID() + "&product_id=" + ids[0] + "&condition=NM");
                    var product = (found.products || [])[0];
                    var variant = product && (product.store_pass_variant_info || []).find(function (v) {
                        return String(v.id) === ids[1];
                    });
                    if (!variant) {
                        continue;
                    }
                    var cond = condition(product, variant);
                    var held = cart().state.cartProducts.find(function (line) {
                        return line.product_id == product.product_id && line.condition === cond;
                    });
                    var more = qty[chunk[i]] - (held ? held.quantity : 0);
                    if (more !== 0) {
                        cart().didAddToCart(product, more, cond);
                        await settle();
                    }
                }
                await call("/saas/buylist-session?store_id=" + storeID(), {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({sessionId: decodeURIComponent(session[2]), cartProducts: cart().state.cartProducts, posSessionId: cart().state.posSessionId})
                });
                return true;
            }
        };
    }

    // gnShop loads Game Nerdz's store cart, a BigCommerce one kept by its
    // cookies, guests included, keyed by the SKU go-mtgban stores for each
    // row. BigCommerce's cart link adds a SKU and refuses the whole add above
    // the stock, answering with the product's page, whose available_to_sell
    // the add then goes again at; a card already in the cart is set through
    // the storefront API.
    function gnShop() {
        var held = {};
        var cartID = "";
        // call makes a change to the cart, stopping the load on a refusal
        async function call(url, opts) {
            var resp = await fetch(url, opts);
            if (!resp.ok) {
                throw new Error("Game Nerdz refused the list (" + resp.status + ").");
            }
            return resp;
        }
        async function read() {
            var resp = await fetch("/api/storefront/carts?include=lineItems.physicalItems.options");
            if (!resp.ok) {
                throw new Error("Game Nerdz could not read your cart (" + resp.status + ").");
            }
            var carts = await resp.json();
            held = {};
            cartID = carts.length > 0 ? carts[0].id : "";
            ((carts[0] && carts[0].lineItems.physicalItems) || []).forEach(function (item) {
                held[item.sku] = item;
            });
            return Object.keys(held);
        }
        return {
            name: "Game Nerdz",
            lock: "ban-to-cart-gn-shop",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            chunkSize: 5,
            cartIDs: async function () {
                if (!/[#&]side=retail(&|$)/.test(location.hash)) {
                    throw new Error("This is Game Nerdz's store, but the list is for its buylist. Go back to BAN and press its button again.");
                }
                return read();
            },
            send: async function (chunk, qty) {
                for (var i = 0; i < chunk.length; i++) {
                    var sku = chunk[i];
                    var line = held[sku];
                    if (line && line.quantity !== qty[sku]) {
                        await call("/api/storefront/carts/" + cartID + "/items/" + line.id, {
                            method: "PUT",
                            headers: {"Content-Type": "application/json"},
                            body: JSON.stringify({lineItem: {productId: line.productId, quantity: qty[sku]}})
                        });
                        continue;
                    }
                    if (line) {
                        continue;
                    }
                    var page = await (await call("/cart.php?action=add&sku=" + encodeURIComponent(sku) + "&qty=" + qty[sku])).text();
                    await read();
                    var stock = /"available_to_sell":(\d+)/.exec(page);
                    if (!held[sku] && stock && Number(stock[1]) > 0 && Number(stock[1]) < qty[sku]) {
                        await call("/cart.php?action=add&sku=" + encodeURIComponent(sku) + "&qty=" + stock[1]);
                        await read();
                    }
                }
                return true;
            }
        };
    }

    // ctStore loads Card Trader's cart, kept by its session cookie, guests
    // included. A listing BAN saw may be sold by now, so each card's live
    // listings are read first, in the storefront BAN priced it in, and every
    // one at or under BAN's price goes to Card Trader's add, which fills the
    // quantity from them. Card Trader is not told what the cart holds, so a
    // load adds to it.
    function ctStore() {
        // Card Trader's grades as go-mtgban reads them
        var grades = {"": "NM", "Mint": "NM", "Near Mint": "NM", "Slightly Played": "SP", "Lightly Played": "SP",
            "Moderately Played": "MP", "Played": "HP", "Heavily Played": "HP", "Poor": "PO", "Damaged": "PO"};
        // The page's own locale; a listing's price in its own currency
        // reads the same in every one
        var locale = (/^\/([a-z]{2}-[A-Z]{2})\//.exec(location.pathname) || [null, "en-EU"])[1];
        // row reads a row's id: <blueprint>-<grade>-<price cents><currency>-
        // <split>-<base64url properties>, or null for one it cannot read
        function row(id) {
            var parts = id.split("-");
            var price = /^(\d+)([A-Z]{3})$/.exec(parts[2] || "");
            if (parts.length < 5 || !price) {
                return null;
            }
            var props;
            try {
                var b64 = parts.slice(4).join("-").replace(/-/g, "+").replace(/_/g, "/");
                props = new URLSearchParams(atob(b64 + "===".slice((b64.length + 3) % 4)));
            } catch (err) {
                return null;
            }
            return {blueprint: parts[0], grade: parts[1], cents: Number(price[1]), currency: price[2], split: parts[3], props: props};
        }
        function token() {
            var meta = document.querySelector('meta[name="csrf-token"]');
            return meta ? meta.content : "";
        }
        async function call(url, body) {
            var resp = await fetch(url, {
                method: "POST",
                headers: {"X-CSRF-Token": token(), Accept: "application/json", "X-Requested-With": "XMLHttpRequest"},
                body: body
            });
            if (!resp.ok) {
                throw new Error("Card Trader refused the list (" + resp.status + ").");
            }
            return resp.json();
        }
        // grade is a listing's grade as go-mtgban prices it, or "" for one
        // it leaves out
        function grade(p) {
            var props = p.properties_hash || {};
            var text = (p.description || "").toLowerCase();
            if (p.quantity < 1 || p.on_vacation || props.altered || p.graded || /ita|mix/.test(text)) {
                return "";
            }
            if (props.signed || /signed|inked|stamp|poor|water/.test(text)) {
                return "PO";
            }
            return grades[props.condition || ""] || "";
        }
        // listings are the live listings of one row, cheapest first, at or
        // under its price, with every property it names: a flag false or
        // missing reads as empty
        async function listings(id) {
            var want = row(id);
            if (!want) {
                return [];
            }
            // Card Trader answers 100 listings at most, cheapest first, so
            // what can be filtered goes along: each property set, a flag as
            // a term; and the grade's names, but for Poor, which go-mtgban
            // also reads off a description
            var body = new URLSearchParams();
            want.props.forEach(function (value, key) {
                if (value === "true") {
                    body.append("q[term][properties_hash." + key + "]", "true");
                } else if (value) {
                    body.append("q[terms][properties_hash." + key + ".keyword][]", value);
                }
            });
            if (want.grade !== "PO") {
                Object.keys(grades).forEach(function (name) {
                    if (name && grades[name] === want.grade) {
                        body.append("q[terms][properties_hash.condition.keyword][]", name);
                    }
                });
            }
            if (want.split !== "d") {
                body.append("q[term][user.can_sell_via_hub]", String(want.split === "z"));
            }
            var page = await call("/" + locale + "/cards/" + want.blueprint + "/filter.json", body);
            var found = want.split === "d" ? page.odr_product_groups : page.products;
            return (found || []).filter(function (p) {
                var props = p.properties_hash || {};
                var user = p.user || {};
                // The storefront without Zero leaves out the private sellers
                // whose shipping go-mtgban does not price
                if (want.split === "m" && user.user_type === "normal" && ["GB", "ES", "CH"].indexOf(user.country_code) >= 0) {
                    return false;
                }
                var same = true;
                want.props.forEach(function (value, key) {
                    same = same && (props[key] ? String(props[key]) : "") === value;
                });
                // The price a buyer is shown, in the listing's own currency,
                // whatever the page's
                return same && grade(p) === want.grade &&
                    p.price_currency === want.currency && p.layered_price_cents <= want.cents;
            });
        }
        return {
            name: "Card Trader",
            loggedIn: function () {
                return true;
            },
            upload: listingsUpload("Card Trader", "ct", async function (id, need, progress) {
                var ids = [];
                (await listings(id)).forEach(function (p) {
                    ids = ids.concat(p.all_ids || [p.id]);
                });
                if (ids.length === 0) {
                    return;
                }
                var query = "quantity=" + need + "&" + ids.map(function (listing) {
                    return "product_ids[]=" + listing;
                }).join("&") + "&future_order=1";
                var body = await call("/" + locale + "/cart/add.json?" + query);
                progress.got = Number(body.delta_changed_quantity) || 0;
            })
        };
    }

    // tcgStore loads TCGplayer's cart, kept under the StoreCart_PRODUCTION
    // cookie's key for a guest too, with the live listings of each row's sku
    // at or under BAN's price, cheapest first: a listing names its seller,
    // which the cart's add needs. A row is named <product>-<sku>-<price
    // cents>-<split>, m for every seller's listings, d for Direct's alone.
    function tcgStore() {
        function cartKey() {
            var cookie = /(?:^|; )StoreCart_PRODUCTION=([^;]*)/.exec(document.cookie);
            var key = cookie && /(?:^|&)CK=(\w+)/.exec(decodeURIComponent(cookie[1]));
            return key ? key[1] : "";
        }
        function call(url, body) {
            return fetch(url, {
                method: "POST",
                credentials: "include",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body)
            });
        }
        function add(sku, listing, take) {
            return call("https://mpgateway.tcgplayer.com/v1/cart/" + cartKey() + "/item/add", {
                sku: sku,
                sellerKey: listing.sellerKey,
                channelId: 0,
                requestedQuantity: take,
                isDirect: !!listing.directListing,
                countryCode: "US"
            });
        }
        // listings are one page of a row's live listings at or under its
        // price, cheapest first, 50 being the most TCGplayer answers
        async function listings(want, from) {
            var term = {sellerStatus: "Live", channelId: 0, productConditionId: [want.sku], listingType: ["standard"]};
            var range = {quantity: {gte: 1}, price: {lte: want.cents / 100}};
            if (want.direct) {
                term["direct-seller"] = true;
                term.directProduct = true;
                range.directInventory = {gte: 1};
            }
            var resp = await call("https://mp-search-api.tcgplayer.com/v1/product/" + want.product + "/listings", {
                filters: {term: term, range: range, exclude: {channelExclusion: 0}},
                context: {shippingCountry: "US", cart: {}},
                from: from,
                size: 50,
                sort: {field: "price", order: "asc"}
            });
            if (!resp.ok) {
                throw new Error("TCGplayer refused the list (" + resp.status + ").");
            }
            var body = await resp.json();
            return (body.results && body.results[0] && body.results[0].results) || [];
        }
        return {
            name: "TCGplayer",
            loggedIn: function () {
                return cartKey() !== "";
            },
            upload: listingsUpload("TCGplayer", "tcg", async function (id, need, progress) {
                var row = /^(\d+)-(\d+)-(\d+)-([md])$/.exec(id);
                var want = row && {product: row[1], sku: Number(row[2]), cents: Number(row[3]), direct: row[4] === "d"};
                for (var from = 0; want && progress.got < need; from += 50) {
                    var page = await listings(want, from);
                    for (var i = 0; i < page.length && progress.got < need; i++) {
                        if (Math.round(page[i].price * 100) > want.cents) {
                            continue;
                        }
                        var take = Math.min(need - progress.got, page[i].quantity);
                        var resp = await add(want.sku, page[i], take);
                        // A listing with fewer left than asked, sold since or
                        // partly held in the cart, adds none and says what it
                        // has left, which is asked for once; one with none is
                        // passed over
                        if (resp.status === 422) {
                            var left = ((await resp.json().catch(Object)).results || [])[0] || {};
                            take = Math.min(take, left.sellerQuantityAvailable - left.itemQuantityInCart);
                            resp = take > 0 ? await add(want.sku, page[i], take) : resp;
                        }
                        if (resp.status === 422) {
                            continue;
                        }
                        if (!resp.ok) {
                            throw new Error("TCGplayer refused the list (" + resp.status + ").");
                        }
                        progress.got += take;
                    }
                    if (page.length < 50) {
                        break;
                    }
                }
            })
        };
    }

    // mlStore loads Manaleak's store cart, or its buylist cart on that
    // cart's page, kept by its session cookie. A store row is named
    // <product id>-<grade>, a buylist row by the product alone, bought as
    // Near Mint. Each card's page names the option each grade goes by and,
    // in the store, how many it has; a card already in the cart gets the
    // list's quantity through the cart form, and a new one is added in the
    // store's own way.
    function mlStore() {
        var buylist = /[?&]route=buylist\//.test(location.search);
        var retail = /[#&]side=retail(&|$)/.test(location.hash);
        var route = buylist ? "buylist/cart" : "checkout/cart";
        // Manaleak's names for the grades go-mtgban reads off its pages
        var labels = {NM: "Mint/Near Mint", SP: "Light Play", MP: "Played", HP: "Heavy Play", PO: "Damaged"};
        // The cart's lines by key, <product id>:<base64 options>:
        var held = {};
        // Each product's condition field and grades once its page was read,
        // null for one with none
        var pages = {};
        async function post(url, body) {
            var resp = await fetch(url, {
                method: "POST",
                headers: {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest"},
                body: new URLSearchParams(body)
            });
            if (!resp.ok) {
                throw new Error("Manaleak refused the list (" + resp.status + ").");
            }
            return resp.text();
        }
        // row reads a list id as the product and the grade it is wanted in
        function row(id) {
            var parts = id.split("-");
            return {product: parts[0], grade: parts[1] || "NM"};
        }
        // listID names a product's grade as the list does
        function listID(product, grade) {
            return buylist ? product : product + "-" + grade;
        }
        // lineOptions is the options a cart line's key names, as Manaleak
        // serializes them: a:1:{i:<option>;s:5:"<value>";}
        function lineOptions(key) {
            try {
                return atob(key.split(":")[1] || "");
            } catch (err) {
                return "";
            }
        }
        // grades reads a card's page for its condition field and, by grade,
        // each option's value and the copies the store has, 0 when out of stock
        async function grades(product) {
            if (product in pages) {
                return pages[product];
            }
            pages[product] = null;
            var resp = await fetch("/index.php?route=product/product&product_id=" + product);
            if (!resp.ok) {
                return null;
            }
            var page = await resp.text();
            // Its HTML breaks lines inside a tag
            var select = /<select\s+name="(option\[\d+\])">([\s\S]*?)<\/select>/.exec(page);
            if (!select) {
                return null;
            }
            var found = {field: select[1], grades: {}};
            Object.keys(labels).forEach(function (grade) {
                var option = new RegExp('<option\\s+value="(\\d+)"[^>]*>\\s*' + labels[grade] + '(?![A-Za-z])[^<]*').exec(select[2]);
                if (option) {
                    var stock = /Qty:\s*(\d+)/.exec(option[0]);
                    found.grades[grade] = {value: option[1], stock: stock ? Number(stock[1]) : 0};
                }
            });
            pages[product] = found;
            return found;
        }
        // gradeOf is the grade a cart line holds, once its card's page was read
        function gradeOf(key) {
            var page = pages[key.split(":")[0]];
            var options = lineOptions(key);
            return page && Object.keys(page.grades).find(function (grade) {
                return options.indexOf('"' + page.grades[grade].value + '"') >= 0;
            });
        }
        return {
            name: "Manaleak",
            // An add adds to a line, so two tabs would each add the same cards
            lock: "ban-to-cart-ml",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            // A card takes a read of its page and one call, about 0.6 s
            chunkSize: 10,
            cartIDs: async function () {
                // A product is sold and bought under the same id
                if (retail === buylist) {
                    throw new Error("This is not the Manaleak cart the list is for. Go back to BAN and press its button again.");
                }
                var resp = await fetch("/index.php?route=" + route);
                if (!resp.ok) {
                    throw new Error("Manaleak could not read your cart (" + resp.status + ").");
                }
                var page = await resp.text();
                held = {};
                var found = [];
                var re = /name="quantity\[([^\]]+)\]"\s+value="(\d+)"/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    held[m[1]] = Number(m[2]);
                    // A buylist row is only ever loaded as Near Mint
                    var grade = gradeOf(m[1]);
                    if (grade && (!buylist || grade === "NM")) {
                        found.push(listID(m[1].split(":")[0], grade));
                    }
                }
                return found;
            },
            // Manaleak adds to a line rather than set it, and lets a store
            // line pass its stock, so the loader trims to what it has
            send: async function (chunk, qty) {
                var update = {};
                var updates = 0;
                for (var i = 0; i < chunk.length; i++) {
                    var id = chunk[i];
                    var want = row(id);
                    var page = await grades(want.product);
                    var option = page && page.grades[want.grade];
                    if (!option) {
                        continue;
                    }
                    var count = buylist ? qty[id] : Math.min(qty[id], option.stock);
                    if (count <= 0) {
                        continue;
                    }
                    var key = Object.keys(held).find(function (k) {
                        return k.split(":")[0] === want.product && gradeOf(k) === want.grade;
                    });
                    if (key) {
                        update["quantity[" + key + "]"] = String(count);
                        updates++;
                        continue;
                    }
                    var add = {product_id: want.product};
                    add[buylist ? "buylist_quantity" : "quantity"] = String(count);
                    add[page.field] = option.value;
                    await post("/index.php?route=" + route + "/add", add);
                }
                if (updates > 0) {
                    await post("/index.php?route=" + route, update);
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

    // haStore loads Hareruya's store cart, or its buylist cart on that cart's
    // page, kept by its session cookie and keyed by the product class
    // go-mtgban stores for each row. The store cart's form takes the whole
    // list at once, setting each quantity up to the stock; the buylist
    // cart adds one card per call, at most 20 of it, and only its form sets
    // a quantity, so it follows the adds.
    function haStore() {
        var buylist = location.pathname.indexOf("/purchase/cart") >= 0;
        var retail = /[#&]side=retail(&|$)/.test(location.hash);
        var cartPage = buylist ? "/ja/purchase/cart" : "/en/cart";
        async function post(url, body) {
            var resp = await fetch(url, {method: "POST", body: body});
            if (!resp.ok) {
                throw new Error("Hareruya refused the list (" + resp.status + ").");
            }
        }
        function most(n) {
            return buylist ? Math.min(n, 20) : n;
        }
        return {
            name: "Hareruya",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            // A store form of 600 cards took 7 s; a buylist add takes 0.3 s
            chunkSize: buylist ? 50 : 500,
            cartIDs: async function () {
                // A store list on the buylist cart, or the other way round,
                // would put one side's classes into the other's cart
                if (retail === buylist) {
                    throw new Error("This is not the Hareruya cart the list is for. Go back to BAN and press its button again.");
                }
                var resp = await fetch(cartPage);
                if (!resp.ok) {
                    throw new Error("Hareruya could not read your cart (" + resp.status + ").");
                }
                var page = await resp.text();
                var found = [];
                var re = /name="qty\[(\d+)\]"/g;
                var m;
                while ((m = re.exec(page)) !== null) {
                    found.push(m[1]);
                }
                return found;
            },
            // Hareruya skips a class it does not sell or buy. A buylist card
            // the cart page did not list is added on top of what is there,
            // and the form then sets it like the rest.
            send: async function (chunk, qty, present) {
                var update = new URLSearchParams();
                for (var i = 0; i < chunk.length; i++) {
                    var id = chunk[i];
                    if (buylist && present.indexOf(id) < 0) {
                        await post("/ja/purchase/add", new URLSearchParams({product_class_id: id, quantity: String(most(qty[id]))}));
                    }
                    update.append("qty[" + id + "]", String(most(qty[id])));
                }
                await post(buylist ? "/ja/purchase/update" : "/en/cart/update", update);
                return true;
            }
        };
    }

    // ckStore loads Card Kingdom's store cart, kept by its cookies, through
    // its deck builder's add, which sets every <product id>-<style> of a
    // chunk in one call. A card that add leaves out, above the stock, goes
    // again alone, and CK answers that one with how many it has.
    function ckStore() {
        async function lines() {
            var resp = await fetch("/api/cart?v=" + Date.now());
            if (!resp.ok) {
                throw new Error("Card Kingdom could not read your cart (" + resp.status + ").");
            }
            var body = await resp.json();
            var found = {};
            ((body.cart || body).lineitems || []).forEach(function (line) {
                found[line.product_id + "-" + line.style] = line.qty;
            });
            return found;
        }
        async function add(id, qty) {
            var parts = id.split("-");
            var resp = await fetch("/api/cart/add", {
                method: "POST",
                headers: {"Content-Type": "application/json;charset=UTF-8", Accept: "application/json;charset=UTF-8"},
                body: JSON.stringify({product_id: Number(parts[0]), style: parts[1], quantity: qty})
            });
            if (resp.status === 400) {
                var body = await resp.json().catch(function () {
                    return {};
                });
                if (body.exception === "MaxQuantityExceeded" && body.available > 0 && body.available < qty) {
                    await add(id, body.available);
                }
                return;
            }
            if (!resp.ok) {
                throw new Error("Card Kingdom refused the list (" + resp.status + ").");
            }
        }
        return {
            name: "Card Kingdom",
            loggedIn: function () {
                return true;
            },
            maxLines: 0,
            // The builder's add takes 300 cards in about 18 s
            chunkSize: 100,
            cartIDs: async function () {
                return Object.keys(await lines());
            },
            // The builder's add skips a card asked above the available count
            // sent with it, so the count is the quantity. It skips a product
            // CK does not have without a word too, and that card is reported
            // as not taken.
            send: async function (chunk, qty) {
                var body = new URLSearchParams({dest: "/cart"});
                chunk.forEach(function (id) {
                    var parts = id.split("-");
                    var card = "[" + parts[0] + "][" + parts[1] + "]";
                    body.append("qty" + card, String(qty[id]));
                    body.append("available" + card, String(qty[id]));
                });
                // It answers with a redirect to the cart page, not followed
                var resp = await fetch("/api/builder/addMultiple", {method: "POST", body: body, redirect: "manual"});
                if (resp.type !== "opaqueredirect" && !resp.ok) {
                    throw new Error("Card Kingdom refused the list (" + resp.status + ").");
                }
                var now = await lines();
                for (var i = 0; i < chunk.length; i++) {
                    if (now[chunk[i]] !== qty[chunk[i]]) {
                        await add(chunk[i], qty[chunk[i]]);
                    }
                }
                return true;
            }
        };
    }
})();

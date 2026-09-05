/*
 * The autocomplete function takes a form containing an input field.
 * It will load the names to be completed once and create div elemenents
 * containing possible suggestions.
 * If a user scrolls up and down, selects an entry and presses Enter, or
 * clicks on a field, they will be submitting the form automatically.
 */

/* Shared across all autocomplete instances on a page. */
var __acCardMetaCache = {};
var __acCardMetaInflight = {};

/* Mirrors the server's search option vocabulary (FilterOperations in
 * searchfilter.go): a token shaped like one of these is a search filter, not
 * part of a card name, so suggestions match on the remaining words only and
 * the completed value carries the filters along. */
var __acFilterToken = /^-?(format|legal|sm|skip|sort|edition|set|e|s|se|ee|number|cn|cns|cne|date|year|name|namee|r|t|f|c|color|unpack|contents|container|decklist|ci|identity|cond|condr|condb|id|is|not|on|price|buy_price|arb_price|rev_price|ratio|store|seller|vendor|region|quantity|qty)[:<>]\S/i;

function __acEsc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
}

/* Leading words a name may be found without. Nobody types "Secret Lair Drop"
 * to find a drop, and 762 of the 4,184 sealed names begin with it. */
var __acSkippablePrefixes = ["The ", "Secret Lair Drop "];

/* Names are compared with their case, diacritics and punctuation set aside,
 * so that "jaces ire" finds "Jace's Ire" and "jotun" finds "Jötun Grunt".
 *
 * Letters and digits are kept whatever the script: 357 of the names carry no
 * ASCII letter at all - Κλεοπάτρα, Воин Лакватуса, تهילה - and dropping
 * everything but A-Z would leave each of them folding to nothing, findable by
 * no one. */
function __acFold(name) {
    return name
        .normalize("NFD")
        .replace(/[̀-ͯ]/g, "")
        .replace(/[^\p{L}\p{N} ]/gu, "")
        .toUpperCase();
}

var __acSkippableFolded = __acSkippablePrefixes.map(__acFold);

/* The typed text, prepared once a keystroke rather than once a name. */
function __acQuery(typed) {
    return {
        raw: typed,
        upper: typed.toUpperCase(),
        folded: __acFold(typed),
    };
}

/* Where the typed text matches within a folded name, or -1: at the front, or
 * past a prefix the name may be found without. */
function __acMatchOffset(foldedName, foldedInput) {
    if (!foldedInput) {
        return -1;
    }
    if (foldedName.lastIndexOf(foldedInput, 0) === 0) {
        return 0;
    }
    for (var i = 0; i < __acSkippableFolded.length; i++) {
        var skip = __acSkippableFolded[i];
        if (foldedName.lastIndexOf(skip, 0) !== 0) {
            continue;
        }
        if (foldedName.lastIndexOf(foldedInput, skip.length) === skip.length) {
            return skip.length;
        }
    }
    return -1;
}

/* Where the typed text matches in a name, as a span of the name itself, or
 * null if it does not. */
function __acMatchSpan(name, foldedName, query) {
    if (!query.raw) {
        return null;
    }

    /* Punctuation and nothing else was typed, and it folds to nothing. One
     * card really is named "_____", so compare the characters themselves: an
     * empty fold compared against an empty fold matches every name there is,
     * which is what the rule this replaced used to do. */
    if (!query.folded.trim()) {
        if (name.slice(0, query.raw.length).toUpperCase() !== query.upper) {
            return null;
        }
        return { start: 0, end: query.raw.length };
    }

    var offset = __acMatchOffset(foldedName, query.folded);
    if (offset < 0) {
        return null;
    }
    return __acOriginalSpan(name, offset, query.folded.length);
}

/* Turn a span of the folded name back into a span of the name itself, which is
 * the one the reader sees and the only one worth emboldening.
 *
 * Folding drops characters, so the two run at different rates: five typed
 * characters can cover six of "Jace's", and a match that begins after "Secret
 * Lair Drop " begins seventeen characters into the name rather than at nought.
 * Walking the name and folding it a character at a time is what says where.
 */
function __acOriginalSpan(name, offset, length) {
    var start = -1;
    var seen = 0;
    for (var i = 0; i < name.length; i++) {
        var folded = __acFold(name[i]);
        if (!folded) {
            /* A character that folds away belongs to whatever follows it,
             * unless the span has already begun - "Jace's" ends after the s. */
            continue;
        }
        if (seen === offset && start < 0) {
            start = i;
        }
        seen += folded.length;
        if (start >= 0 && seen >= offset + length) {
            return { start: start, end: i + 1 };
        }
    }
    return { start: Math.max(start, 0), end: name.length };
}

/* Returns cached card meta, or null while a fetch is in flight. */
function __acFetchCardMeta(name, onReady) {
    if (!name) return null;
    if (__acCardMetaCache[name]) return __acCardMetaCache[name];
    if (__acCardMetaInflight[name]) return null;
    __acCardMetaInflight[name] = fetch('/api/palette/card/' + encodeURIComponent(name))
        .then(function (r) { return r.ok ? r.json() : { found: false }; })
        .then(function (data) {
            if (data && data.found) __acCardMetaCache[name] = data;
            delete __acCardMetaInflight[name];
            if (typeof onReady === 'function') onReady();
            return data;
        })
        .catch(function () { delete __acCardMetaInflight[name]; });
    return null;
}

async function autocomplete(form, inp, sealed) {
    var currentFocus;
    var minlen = 3;
    var providerMode = false;
    const arr = await fetchNames(sealed);
    /* Folded once, here, rather than per keystroke: the singles list is 37,000
     * names, and every one of them used to be normalized again on every letter
     * typed. */
    const folded = arr.map(__acFold);

    // Track viewport listeners so we can detach them when the dropdown closes
    var viewportListenersAttached = false;
    var currentItemsDiv = null;

    function fitToViewport() {
        if (!currentItemsDiv || !document.body.contains(currentItemsDiv)) return;
        var vv = window.visualViewport;
        var inputRect = inp.getBoundingClientRect();
        var bottom = vv ? vv.height : window.innerHeight;
        var available = Math.max(120, bottom - inputRect.bottom - 8);
        currentItemsDiv.style.maxHeight = available + 'px';
        currentItemsDiv.style.overflowY = 'auto';
    }

    function attachViewportListeners() {
        if (viewportListenersAttached) return;
        viewportListenersAttached = true;
        var vv = window.visualViewport;
        if (vv) {
            vv.addEventListener('resize', fitToViewport);
            vv.addEventListener('scroll', fitToViewport);
        } else {
            window.addEventListener('resize', fitToViewport);
        }
    }

    function detachViewportListeners() {
        if (!viewportListenersAttached) return;
        viewportListenersAttached = false;
        var vv = window.visualViewport;
        if (vv) {
            vv.removeEventListener('resize', fitToViewport);
            vv.removeEventListener('scroll', fitToViewport);
        } else {
            window.removeEventListener('resize', fitToViewport);
        }
    }

    /* Render the active token's provider candidates. Returns true if a known
     * prefix was detected (so the caller skips card-name suggestions). */
    function renderProviderDropdown() {
        var providers = window.__palette_providers;
        if (!providers) return false;

        var caret = inp.selectionStart;
        if (typeof caret !== 'number') caret = inp.value.length;
        var head = inp.value.slice(0, caret);
        var tokenStart = head.lastIndexOf(' ') + 1;
        var token = head.slice(tokenStart);

        var detected = providers.detectPrefix(token);
        if (!detected) return false;
        var provider = providers.getProvider(detected.prefix);
        if (!provider) return false;

        /* Split the remainder on the last comma for multi-value lists. */
        var remainder = detected.query;
        var lastComma = remainder.lastIndexOf(',');
        var committed = lastComma >= 0 ? remainder.slice(0, lastComma + 1) : '';
        var filterQuery = lastComma >= 0 ? remainder.slice(lastComma + 1) : remainder;

        /* Card-context narrowing from a quoted name before the active token. */
        var cardMeta = null;
        var match = inp.value.slice(0, tokenStart).match(/"([^"]+)"/);
        if (match) {
            /* On resolve the cache is populated, so the re-dispatch hits cache and stops. */
            cardMeta = __acFetchCardMeta(match[1], function () {
                if (currentItemsDiv && document.activeElement === inp) {
                    inp.dispatchEvent(new InputEvent('input'));
                }
            });
        }

        var candidates = (provider.getCandidates(filterQuery, { chips: [], cardMeta: cardMeta }) || []).slice(0, 30);

        currentFocus = -1;

        var valueBefore = inp.value.slice(0, tokenStart);
        var tail = inp.value.slice(caret);

        var list = document.createElement("DIV");
        list.setAttribute("id", inp.id + "autocomplete-list");
        list.setAttribute("class", "autocomplete-items ac-dropdown");

        for (var i = 0; i < candidates.length; i++) {
            list.appendChild(buildProviderRow(candidates[i], detected.prefix, committed, valueBefore, tail));
        }

        if (list.hasChildNodes()) {
            inp.parentNode.appendChild(list);
            currentItemsDiv = list;
            providerMode = true;
            fitToViewport();
            attachViewportListeners();
        }
        /* Return true even with no matches: a known prefix suppresses name suggestions. */
        return true;
    }

    function buildProviderRow(candidate, prefix, committed, valueBefore, tail) {
        var row = document.createElement("DIV");

        if (candidate.disabled) {
            row.className = "autocomplete-disabled";
            row.textContent = candidate.label || '';
            return row;
        }

        var iconInner = '';
        if (candidate.keyrune) {
            var kr = String(candidate.keyrune).toLowerCase().replace(/[^a-z0-9]/g, '');
            iconInner = '<i class="ss ss-fw ss-' + kr + '"></i>';
        } else if (candidate.iconColor) {
            /* Whitelist CSS color chars; HTML-escaping alone does not stop CSS injection. */
            var safeColor = /^[a-zA-Z0-9#(),%. +-]+$/.test(candidate.iconColor) ? candidate.iconColor : '';
            iconInner = '<span class="ac-swatch" style="background:' + safeColor + '"></span>';
        }

        /* Fixed-width icon column so labels left-align regardless of symbol width. */
        var label = candidate.label || candidate.value || '';
        var sub = candidate.sublabel ? '<span class="ac-sub">' + __acEsc(candidate.sublabel) + '</span>' : '';
        row.innerHTML = '<span class="ac-icon">' + iconInner + '</span><span class="ac-label">' + __acEsc(label) + '</span>' + sub;

        var newToken = prefix + committed + candidate.value;
        row.addEventListener("click", function () {
            inp.value = valueBefore + newToken + tail;
            var pos = (valueBefore + newToken).length;
            closeAllLists();
            inp.focus();
            try { inp.setSelectionRange(pos, pos); } catch (e) {}
        });
        return row;
    }

    /* Execute a function when someone writes in the text field: */
    inp.addEventListener("input", function(e) {
        var a, b, i, val = this.value;
        /* Close any already open lists of autocompleted values */
        closeAllLists();
        providerMode = false;
        if (!val) {
            return false;
        }

        /* Prefix-driven sub-option suggestions take precedence over names. */
        if (renderProviderDropdown()) {
            return;
        }

        /* Clean up input string */
        val = val.trim();

        /* Filter tokens (s:PLST, f:foil, price>10 ...) are not part of the
         * card name: pull them aside so suggestions match on the remaining
         * words, and completions reinsert them ("s:PLST naya" completes to
         * "s:PLST Naya Charm"). */
        var filterPrefix = '';
        if (/[:<>]/.test(val)) {
            var filters = [];
            /* Quoted option values may contain spaces, extract them first */
            var rest = val.replace(/-?[a-zA-Z_]+[:<>]"[^"]*"/g, function (m) {
                if (__acFilterToken.test(m)) {
                    filters.push(m);
                    return ' ';
                }
                return m;
            });
            var words = [];
            var tokens = rest.split(/\s+/);
            for (i = 0; i < tokens.length; i++) {
                if (__acFilterToken.test(tokens[i])) {
                    filters.push(tokens[i]);
                } else if (tokens[i]) {
                    words.push(tokens[i]);
                }
            }
            if (filters.length) {
                filterPrefix = filters.join(' ') + ' ';
                val = words.join(' ');
            }
        }

        /* Prompt suggestions only if input is longer than three characters */
        if (val.length < minlen) {
            return false;
        }
        currentFocus = -1;
        /* Create a DIV element that will contain the items (values) */
        a = document.createElement("DIV");
        a.setAttribute("id", this.id + "autocomplete-list");
        a.setAttribute("class", "autocomplete-items ac-dropdown");

        /* For each item in the array... */
        var query = __acQuery(val);
        for (i = 0; i < arr.length; i++) {
            /* Check whether the item is found by what was typed, at its front
             * or past a prefix nobody types */
            var span = __acMatchSpan(arr[i], folded[i], query);
            if (!span) {
                continue;
            }

            /* Create a DIV element for each matching element */
            b = document.createElement("DIV");

            /* Make the matching letters bold - the ones that matched, which
             * are not always the ones the name begins with */
            var strong = document.createElement("strong");
            strong.textContent = arr[i].slice(span.start, span.end);
            b.appendChild(document.createTextNode(arr[i].slice(0, span.start)));
            b.appendChild(strong);
            b.appendChild(document.createTextNode(arr[i].slice(span.end)));

            /* Insert a input field that will hold the current array item's
             * value, with any search filters the query carried kept in front */
            var hidden = document.createElement("input");
            hidden.type = "hidden";
            hidden.value = filterPrefix + arr[i];
            b.appendChild(hidden);
            /* Execute a function when someone clicks on the item value (DIV element) */
            b.addEventListener("click", function(e) {
                /* Insert the value for the autocomplete text field */
                inp.value = this.getElementsByTagName("input")[0].value;
                /* Close the list of autocompleted values,
                 * (or any other open lists of autocompleted values */
                closeAllLists();

                /* Submit the form (so that onSubmit may trigger) */
                /* We need to use this extended workaround due to Safari */
                const fakeButton = document.createElement('button');
                fakeButton.type = this.type;
                fakeButton.style.display = 'none';
                form.appendChild(fakeButton);
                fakeButton.click();
                fakeButton.remove();
            });
            a.appendChild(b);
        }

        /* Only append the dropdown if there are matching items */
        if (a.hasChildNodes()) {
            this.parentNode.appendChild(a);
            currentItemsDiv = a;
            fitToViewport();
            attachViewportListeners();
        }
    });

    /* Execute a function presses a key on the keyboard */
    inp.addEventListener("keydown", function(e) {
        var x = document.getElementById(this.id + "autocomplete-list");
        if (x) {
            x = x.getElementsByTagName("div");
        }
        if (e.keyCode == 40) { // DOWN key
            /* If the arrow DOWN key is pressed,
             * do not move input cursor */
            e.preventDefault();
            if (!x || x.length == 0) {
                /* ignore the minimum input length */
                minlen = 1;
                /* force the drop-down menu to appear */
                this.dispatchEvent(new InputEvent("input", e));
            } else {
                /* increase the currentFocus variable */
                currentFocus++;
                /* prevent overflowing */
                if (x && currentFocus > x.length - 1) {
                    currentFocus = 0;
                }
                /* and and make the current item more visible */
                addActive(x);
            }
        } else if (e.keyCode == 38) { // UP key
            /* If the arrow UP key is pressed,
             * do not move input cursor */
            e.preventDefault();
            /* decrease the currentFocus variable */
            currentFocus--;
            /* prevent overflowing */
            if (currentFocus < 0 ) {
                currentFocus = x ? x.length - 1 : 0;
            }
            /* and and make the current item more visible */
            addActive(x);
        } else if (e.keyCode == 13 && currentFocus > -1) {
            /* If the ENTER key is pressed and if the selector is open */
            if (x) {
                /* simulate a click on the "active" item */
                x[currentFocus].click();
            }
        } else if (e.keyCode == 27) {
            /* If the ESC key is pressed just close everything */
            closeAllLists();
        } else if ((e.keyCode == 9 || e.keyCode == 39) && currentFocus > -1) {
            /* If the TAB or RIGHT ARROW keys are pressed, and if the selector
             * is open, do not move focus */
            e.preventDefault();
            if (providerMode) {
                /* Provider rows splice a value, so select rather than copy text. */
                if (x) x[currentFocus].click();
            } else {
                /* initialize the input field with what is selected - the value
                 * the row stands for, which carries the query's filters, and
                 * not the name the row displays */
                var chosen = x[currentFocus].getElementsByTagName("input")[0];
                this.value = chosen ? chosen.value : x[currentFocus].textContent;
            }
        }
    });

    /* Classify an item as "active" */
    function addActive(x) {
        if (!x) {
            return false;
        }
        /* Start by removing the "active" class on all items */
        removeActive(x);
        if (currentFocus >= x.length) {
            currentFocus = 0;
        }
        if (currentFocus < 0) {
            currentFocus = (x.length - 1);
        }
        /* Add class "autocomplete-active" */
        x[currentFocus].classList.add("autocomplete-active");
    }

    /* Remove the "active" class from all autocomplete items */
    function removeActive(x) {
        for (var i = 0; i < x.length; i++) {
            x[i].classList.remove("autocomplete-active");
        }
    }

    /* Close all autocomplete lists in the document, except the one passed as an argument */
    function closeAllLists(elmnt) {
        // Only our own dropdowns; other widgets reuse the autocomplete-items class.
        // Snapshot the live HTMLCollection so removeChild iteration is robust
        var x = Array.from(document.getElementsByClassName("ac-dropdown"));
        var anyRemoved = false;
        for (var i = 0; i < x.length; i++) {
            if (elmnt != x[i] && elmnt != inp) {
                x[i].parentNode.removeChild(x[i]);
                anyRemoved = true;
            }
        }
        if (anyRemoved) {
            currentItemsDiv = null;
            detachViewportListeners();
        }
    }

    /* Execute a function (make the suggestions disaeppear)
     * when someone clicks in the document */
    document.addEventListener("click", function(e) {
        closeAllLists(e.target);
    });

    /* Refresh an open provider dropdown when sets/stores JSON finishes loading. */
    /* Guard against double-registering if autocomplete() runs twice for this input. */
    if (window.__palette_providers && typeof window.__palette_providers.setOnDataReady === 'function' && !inp._acDataReadyRegistered) {
        inp._acDataReadyRegistered = true;
        window.__palette_providers.setOnDataReady(function () {
            if (providerMode && currentItemsDiv && document.activeElement === inp) {
                inp.dispatchEvent(new InputEvent('input'));
            }
        });
    }
};

/* Exposed for the tests; the browser gets these from the script tag itself. */
if (typeof self !== "undefined") {
    self.AutocompleteMatch = {
        fold: __acFold,
        query: __acQuery,
        matchOffset: __acMatchOffset,
        originalSpan: __acOriginalSpan,
        matchSpan: __acMatchSpan,
    };
}

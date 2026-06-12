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

function __acEsc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
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
            cardMeta = __acFetchCardMeta(match[1], function () {
                if (currentItemsDiv && document.activeElement === inp) {
                    inp.dispatchEvent(new InputEvent('input'));
                }
            });
        }

        var candidates = (provider.getCandidates(filterQuery, { chips: [], cardMeta: cardMeta }) || []).slice(0, 30);

        providerMode = true;
        currentFocus = -1;

        var valueBefore = inp.value.slice(0, tokenStart);
        var tail = inp.value.slice(caret);

        var list = document.createElement("DIV");
        list.setAttribute("id", inp.id + "autocomplete-list");
        list.setAttribute("class", "autocomplete-items");

        for (var i = 0; i < candidates.length; i++) {
            list.appendChild(buildProviderRow(candidates[i], detected.prefix, committed, valueBefore, tail));
        }

        if (list.hasChildNodes()) {
            inp.parentNode.appendChild(list);
            currentItemsDiv = list;
            fitToViewport();
            attachViewportListeners();
        }
        return true;
    }

    function buildProviderRow(candidate, prefix, committed, valueBefore, tail) {
        var row = document.createElement("DIV");

        if (candidate.disabled) {
            row.className = "autocomplete-disabled";
            row.textContent = candidate.label || '';
            return row;
        }

        var iconHtml = '';
        if (candidate.keyrune) {
            var kr = String(candidate.keyrune).toLowerCase().replace(/[^a-z0-9]/g, '');
            iconHtml = '<i class="ss ss-' + kr + '"></i> ';
        } else if (candidate.iconColor) {
            iconHtml = '<span class="ac-swatch" style="background:' + __acEsc(candidate.iconColor) + '"></span> ';
        }

        var label = candidate.label || candidate.value || '';
        var sub = candidate.sublabel ? '<span class="ac-sub">' + __acEsc(candidate.sublabel) + '</span>' : '';
        row.innerHTML = iconHtml + '<span class="ac-label">' + __acEsc(label) + '</span> ' + sub;

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

        /* Prompt suggestions only if input is longer than three characters */
        if (val.length < minlen) {
            return false;
        }
        currentFocus = -1;
        /* Create a DIV element that will contain the items (values) */
        a = document.createElement("DIV");
        a.setAttribute("id", this.id + "autocomplete-list");
        a.setAttribute("class", "autocomplete-items");

        /* For each item in the array... */
        for (i = 0; i < arr.length; i++) {
            let inputText = val.toUpperCase();
            /* Check if the item starts with the same letters as the text field value */
            if (arr[i].substr(0, val.length).toUpperCase() == inputText ||
                arr[i].normalize("NFD").replace(/[\u0300-\u036f]/g, "").substr(0, val.length).toUpperCase() == inputText ||
                arr[i].replace(/^The /g, "").substr(0, val.length).toUpperCase() == inputText ||
                arr[i].replace(/^Secret Lair Drop /g, "").substr(0, val.length).toUpperCase() == inputText ||
                arr[i].replace(/[^A-Za-z0-9 ]/g, "").substr(0, val.replace(/[^A-Za-z0-9 ]/g, "").length).toUpperCase() == val.replace(/[^A-Za-z0-9 ]/g, "").toUpperCase()) {
                /* Create a DIV element for each matching element */
                b = document.createElement("DIV");

                /* Make the matching letters bold */
                b.innerHTML = "<strong>" + arr[i].substr(0, val.length) + "</strong>";
                b.innerHTML += arr[i].substr(val.length);

                /* Insert a input field that will hold the current array item's value */
                b.innerHTML += "<input type='hidden' value='" + arr[i].replace(/'/g, "&apos;").replace(/\"/g, "&quot;") + "'>";
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
                /* initialize the input field with what is selected */
                this.value = x[currentFocus].textContent;
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
        // Snapshot the live HTMLCollection so removeChild iteration is robust
        var x = Array.from(document.getElementsByClassName("autocomplete-items"));
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
    if (window.__palette_providers && typeof window.__palette_providers.setOnDataReady === 'function') {
        window.__palette_providers.setOnDataReady(function () {
            if (providerMode && currentItemsDiv && document.activeElement === inp) {
                inp.dispatchEvent(new InputEvent('input'));
            }
        });
    }
};

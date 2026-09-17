// The server emits this from NavElem.Link. Cookies not claimed by a NavElem
// are shared because their values are consumed by more than one route family.
const COOKIE_PATHS = Object.freeze(window.__BAN_COOKIE_PATHS || {});

function cookiePath(cname) {
    return COOKIE_PATHS[cname] || '/';
}

function writeCookie(cname, cvalue, exdays, path) {
    const d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));

    // Delete cookie if no data
    if (cvalue == '') {
        d.setTime(Date.now());
    }
    
    let expires = "expires="+ d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=" + path + ";SameSite=Strict";
}

function setCookie(cname, cvalue, exdays) {
    const path = cookiePath(cname);
    writeCookie(cname, cvalue, exdays, path);

    // Move legacy root-scoped copies out of the broad path whenever a
    // route-local preference is written. The startup migration below handles
    // preferences that have not been touched since this change.
    if (path !== '/') {
        writeCookie(cname, '', 0, '/');
    }
}

function getCookie(cname) {
    let name = cname + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for(let i = 0; i <ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

function migrateScopedCookies() {
    Object.keys(COOKIE_PATHS).forEach(function (cname) {
        const path = COOKIE_PATHS[cname];
        const migrationKey = 'mtgban-cookie-scope-v1:' + cname;
        let migrated = false;
        try {
            migrated = window.localStorage.getItem(migrationKey) === '1';
        } catch (e) {}

        // A Path=/ cookie is visible on every page, but the new scoped cookie
        // is not. Migrate only when visiting its owner so an unrelated page
        // cannot clear a legacy value before it has been copied.
        const pathname = window.location.pathname;
        if (migrated || (pathname !== path && !pathname.startsWith(path + '/'))) {
            return;
        }

        const value = getCookie(cname);
        if (value !== '') {
            // Preserve the preference when moving it from the old root path.
            writeCookie(cname, value, 3650, path);
            writeCookie(cname, '', 0, '/');
        }
        try {
            window.localStorage.setItem(migrationKey, '1');
        } catch (e) {}
    });
}

migrateScopedCookies();

function clearForm(containerName) {
    const container = document.querySelector('#' + containerName);
    var checkboxes = container.querySelectorAll('input')
    for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
            checkboxes[i].checked = false;
        }
    }
}

function selectAll(containerName) {
    const container = document.querySelector('#' + containerName);
    var checkboxes = container.querySelectorAll('input');
    for (var i = 0; i < checkboxes.length; i++) {
        checkboxes[i].checked = true;
    }
}

function saveForm(cookieName, containerName) {
    var list = "";
    const sellers = document.querySelector('#' + containerName);
    var checkboxes = sellers.querySelectorAll('input');
    for (var i = 0; i < checkboxes.length; i++) {
        if (checkboxes[i].checked) {
            list += checkboxes[i].name + ',';
        }
    }

    setCookie(cookieName, list, 1000);
}

function loadForm(cookieName, containerName) {
    var list = getCookie(cookieName);
    if (list == "") {
        return;
    }

    const sets = list.split(",");
    const container = document.querySelector('#' + containerName);
    var checkboxes = container.querySelectorAll('input');
    for (var i = 0; i < sets.length; i++) {
        for (var j = 0; j < checkboxes.length; j++) {
            if (checkboxes[j].name == sets[i]) {
                checkboxes[j].checked = true;
            }
        }
    }
}

function saveRadio(cookieName, containerName) {
    var out = "";
    const sellers = document.querySelector('#' + containerName);
    var radios = sellers.querySelectorAll('input');
    for (var i = 0; i < radios.length; i++) {
        if (radios[i].checked) {
            out = radios[i].value;
            break;
        }
    }

    setCookie(cookieName, out, 1000);
}

function loadRadio(cookieName, containerName) {
    var list = getCookie(cookieName);
    if (list == "") {
        return;
    }

    const container = document.querySelector('#' + containerName);
    var checkboxes = container.querySelectorAll('input');
    for (var j = 0; j < checkboxes.length; j++) {
        if (checkboxes[j].value == list) {
            checkboxes[j].checked = true;
            break;
        }
    }
}

function saveDropdown(cookieName, containerName) {
    var out = "";
    const drops = document.querySelector('#' + containerName);
    for (var i = 0; i < drops.length; i++) {
        if (drops.options[i].selected && !drops.options[i].disabled) {
            out = drops.options[i].value;
            break;
        }
    }

    setCookie(cookieName, out, 1000);
}

function loadDropdown(cookieName, containerName) {
    var list = getCookie(cookieName);
    if (list == "") {
        return;
    }

    const drops = document.querySelector('#' + containerName);
    for (var j = 0; j < drops.length; j++) {
        drops[j].selected = false;
        if (drops[j].value == list) {
            drops[j].selected = true;
        }
    }
}

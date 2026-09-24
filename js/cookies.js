// Search preferences are shared by /search and /sealed, and the custom
// buylist is set up on /upload but priced into /search too. Other browser
// preferences belong to the first path segment of the page that edits them.
function routePath() {
    const match = window.location.pathname.match(/^\/[^/]+/);
    return match ? match[0] : '/';
}

function cookiePath(cname) {
    if (cname.startsWith('Search') || cname.startsWith('MobileSearch') || cname.startsWith('UploadCustom')) {
        return '/';
    }
    return routePath();
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

    // Expire the copy at the other path, a legacy root one or a route one
    // left by an older build, so two values with one name are never sent.
    const other = path === '/' ? routePath() : '/';
    if (other !== path) {
        writeCookie(cname, '', 0, other);
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

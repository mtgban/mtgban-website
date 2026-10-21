// Search preferences are shared by /search and /sealed, and the custom
// buylist is set up on /upload but priced into /search too. Other browser
// preferences belong to owner, the path of the page that reads them, or
// the current page's first path segment when no owner is named.
function routePath() {
    const match = window.location.pathname.match(/^\/[^/]+/);
    return match ? match[0] : '/';
}

function cookiePath(cname, owner) {
    if (cname.startsWith('Search') || cname.startsWith('MobileSearch') || cname.startsWith('UploadCustom')) {
        return '/';
    }
    return owner || routePath();
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

function setCookie(cname, cvalue, exdays, owner) {
    const path = cookiePath(cname, owner);
    writeCookie(cname, cvalue, exdays, path);

    // Expire the copies at the other paths, a legacy root one or one an
    // older build left at the page it was saved on, so two values with one
    // name are never sent.
    ['/', routePath()].forEach(function (other, i, all) {
        if (other !== path && all.indexOf(other) === i) {
            writeCookie(cname, '', 0, other);
        }
    });
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

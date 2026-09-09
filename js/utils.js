// Shared HTML helpers — loaded first in base.html so any later script
// (favorites.js, recent-searches.js, chartopts.js, …) can call them as
// globals without redefining its own copy.

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
        return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
}

function escapeAttr(str) {
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function thumbHtml(src, foil, cw) {
    var cls = 'foil-wrap';
    if (cw) cls += ' content-warning';
    return '<div class="' + cls + '" data-foil="' + (foil ? 'true' : 'false') + '"' +
           (cw ? ' onclick="this.classList.add(\'cw-revealed\');event.preventDefault();event.stopPropagation()"' : '') +
           '><img src="' + escapeAttr(src) + '" loading="lazy" alt=""></div>';
}

/* A URL from the page - an attribute, a select's value, an href - resolved
 * against this document and handed back only if it is safe to follow.
 *
 * Parsing beats testing the string: "javascript:", "data:" and "vbscript:" are
 * each settled by asking the parser for the scheme, where a test naming one of
 * them lets the other two through. An unparseable value comes back empty, and
 * every caller reads empty as "do not follow".
 */
function httpURL(value) {
    if (typeof value !== 'string' || !value) return '';
    var url;
    try {
        url = new URL(value, window.location.href);
    } catch (e) {
        return '';
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
    return url.href;
}

/* httpURL, and on this site as well - which is what a navigation needs, since
 * a "//host" or "/\\host" that a leading-slash test reads as a path resolves
 * to somewhere else entirely.
 *
 * Only for navigation. Card art is served from Scryfall and TCGplayer, so an
 * image source asks httpURL alone or it would answer for none of it.
 */
function sameSiteURL(value) {
    var href = httpURL(value);
    if (!href) return '';
    if (new URL(href).origin !== window.location.origin) return '';
    return href;
}

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

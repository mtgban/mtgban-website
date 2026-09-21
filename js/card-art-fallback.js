// A card's own image is fetched from wherever the vendor data points -
// TCGplayer, tcgdex, Scryfall - and that address is not this site's to
// guarantee. The set-symbol partial learned this the hard way: tcgdex moved
// where a symbol lived out from under a URL this site had already been
// handed, and for nine days every one of them sat as a broken-image icon
// because nothing was watching for the load to fail. This is that same
// lesson generalized to every place a card's own art is shown: on a failed
// load, fall back to the game's card back rather than leave a hole.
//
// A capture-phase listener on document, not one per <img>, because the
// pages listed below build most of these elements dynamically - a search
// result row swaps #cardImage's src on hover, thumbHtml() stamps out a new
// <img> per favorite or recent search - and "error" does not bubble, so
// delegation needs the capture phase to see it at all. One listener here
// covers every image tagged below for the life of the page, including ones
// that do not exist yet when this script runs.
//
// SELECTOR names every place a card's own image is displayed, by the marker
// each page already gives it plus .card-art for the ones that carried none:
// desktop search's sidebar image and its click-to-zoom modal, the four
// hover-preview pages (arbit, news, screener, upload) that share
// .hoverImage, the mobile card drawer, mobile search's landscape thumbnail,
// the homepage's popular-searches strip, and .card-art itself on sleep.html,
// mobile/sleep.html, upload.html's per-row thumbnail and thumbHtml()'s
// generated markup (js/utils.js). A new page showing a card's own art opts
// in by adding .card-art to it - nothing else has to change here.
var CARD_ART_SELECTOR = '#cardImage, #cardImageModalImg, #m-drawer-img, .hoverImage, .m-card-img-landscape, .landing-popular-img, .card-art';
var CARD_ART_PLACEHOLDER = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
window.cardArtPlaceholder = CARD_ART_PLACEHOLDER;

// data-game is server-rendered - see the "game" template function, which
// hands back Config.Game verbatim - never user input. Validated against the
// slug shape every registered game actually uses anyway, so building a path
// from it can never carry a scheme, host, or traversal sequence, whatever
// reads the attribute next.
var GAME_SLUG_RE = /^[a-z0-9]+$/;
function cardBackForGame() {
    var game = document.body && document.body.getAttribute('data-game');
    return game && GAME_SLUG_RE.test(game) ? '/img/backs/' + game + '.webp' : null;
}

// Reused card-art elements need a fresh fallback guard whenever their source
// changes. Keeping this beside the error listener gives inline handlers one
// shared way to make that transition safely.
function setCardArtSource(img, src) {
    if (!img) return;
    var target = src || cardBackForGame();
    var hoverWrap = img.closest && img.closest('.hoverWrap');
    var showHover = function () {
        if (hoverWrap) {
            hoverWrap.classList.toggle('is-visible', target !== CARD_ART_PLACEHOLDER);
        }
    };
    var apply = function () {
        img.src = target;
        showHover();
    };

    delete img.dataset.cardArtFallback;
    // Keep the previous art visible while a different printing loads. This
    // matters on the price-heavy search pages, where moving between adjacent
    // results otherwise exposes the image's blank loading state in Firefox.
    // The token prevents a slow response for an older hover from winning.
    if (target !== CARD_ART_PLACEHOLDER && typeof Image !== 'undefined') {
        var request = new Image();
        var token = {};
        img.__cardArtRequest = token;
        request.onload = function () {
            if (img.__cardArtRequest === token) apply();
        };
        request.onerror = function () {
            if (img.__cardArtRequest === token) apply();
        };
        request.src = target;
        return;
    }
    apply();
}
window.setCardArtSource = setCardArtSource;

document.addEventListener('error', function (e) {
    var img = e.target;
    if (!(img instanceof HTMLImageElement) || !img.matches(CARD_ART_SELECTOR)) {
        return;
    }
    // Guards the fallback itself failing to load (a missing img/backs/ asset)
    // from re-firing this handler forever - flagged rather than compared by
    // URL, since img.src always reads back as the browser's resolved
    // absolute form and would never equal the relative path this writes.
    if (img.dataset.cardArtFallback) {
        return;
    }
    img.dataset.cardArtFallback = '1';
    // data-game is already on <body> for every deployment (base.html and
    // base-mobile.html both set it); mirrors what the card_back template
    // function computes server-side, so a page needs neither to call it nor
    // to thread the value through to script-generated images.
    var back = cardBackForGame();
    if (!back) {
        return;
    }
    img.src = back;
}, true);

// What had focus when the overlay opened, handed back when Back closes it.
var uploadProcessingOpener = null;

// The wait between posting a list and its results page arriving. Only the
// posts that navigate here call it: an export answers with a file and leaves
// this page on screen, so an overlay shown for one would never go away.
// Focus moves into the dialog so a screen reader announces it, and so
// Enter on the covered Upload button cannot post the list again.
window.showUploadProcessing = function() {
    var overlay = document.getElementById('upload-processing');
    if (!overlay) return;
    // A click leaves focus on <body> in Safari, which does not focus buttons.
    var active = document.activeElement;
    uploadProcessingOpener = active && active !== document.body ? active : document.getElementById('submit_default');
    overlay.classList.add('open');
    var dialog = overlay.querySelector('[role="alertdialog"]');
    if (dialog) dialog.focus();
};

// Back from the results restores this page from the cache as it was left,
// overlay and all.
window.addEventListener('pageshow', function(e) {
    if (!e.persisted) return;
    var overlay = document.getElementById('upload-processing');
    if (overlay) overlay.classList.remove('open');
    if (uploadProcessingOpener) uploadProcessingOpener.focus();
    uploadProcessingOpener = null;
});

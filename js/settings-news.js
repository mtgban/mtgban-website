(function () {
    'use strict';

    function pickerEl() { return document.getElementById('news-editions-picker'); }

    function load() {
        const p = pickerEl();
        if (p && window.EditionsPicker) {
            window.EditionsPicker.load(p, 'NewspaperList');
        }
    }
    function save() {
        const p = pickerEl();
        if (p && window.EditionsPicker) {
            window.EditionsPicker.save(p, 'NewspaperList');
        }
    }
    function serialize() {
        const p = pickerEl();
        return p && window.EditionsPicker ? window.EditionsPicker.serialize(p) : '';
    }

    document.addEventListener('DOMContentLoaded', function () {
        const p = pickerEl();
        if (p && window.EditionsPicker) window.EditionsPicker.init(p);
        if (window.SettingsModal) {
            window.SettingsModal.register({ load: load, save: save, serialize: serialize });
        }
    });
})();

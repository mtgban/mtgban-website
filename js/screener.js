// Counts the screener's filter controls; the listener is on document so it survives the results swap.
(function () {
    var CONTROLS = { provider: 'provider', window: 'window', kind: 'kind', move: 'move', size: 'size', edition: 'editions' };

    // control maps a filter field's name to its registry value, or '' for one not counted.
    function control(name) {
        return Object.prototype.hasOwnProperty.call(CONTROLS, name) ? CONTROLS[name] : '';
    }

    window.ScreenerTrack = { control: control };

    document.addEventListener('change', function (e) {
        var t = e.target;
        if (!t || !t.closest || !t.closest('form[action="/screener"]')) return;
        var value = control(t.name);
        if (value && window.BAN && window.BAN.track) window.BAN.track('ui.screener.control', value);
    });
})();

// One request per list: every search box on a page, and the command
// palette, share the same promise rather than each fetching 700 KB.
var __fetchNamesCache = {};
function fetchNames(sealed) {
    var key = String(sealed);
    if (!__fetchNamesCache[key]) {
        __fetchNamesCache[key] = fetch("/api/suggest?all=true&sealed=" + key)
            .then(function (response) {
                if (!response.ok) throw new Error("suggest " + response.status);
                return response.json();
            })
            .catch(function (err) {
                // A failed fetch should not poison every future retry.
                delete __fetchNamesCache[key];
                throw err;
            });
    }
    return __fetchNamesCache[key];
}

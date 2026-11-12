// What a settings save changed, sent only as registry words.
(function () {
    'use strict';

    // Packed cookies, one flag a box, and the flags an unset cookie means.
    var FLAGS = {
        SearchMiscOpts: [],
        UploadOptimizerOpts: ['lowval', 'lowvalabs', 'minmargin', 'customperc'],
        UploadCustomOpts: []
    };
    // Enum cookies, with the value an empty one means where there is one.
    var ENUMS = {
        SearchDefaultSort: 'chrono',
        SearchListingPriority: 'prices',
        SearchBuylistSecondary: 'priceRatio',
        SearchSealedContents: 'contents',
        UploadSorting: '',
        UploadPriceSource: '',
        UploadTiebreak: '',
        SearchDefaultTab: 'sellers',
        SearchDefaultView: 'NM',
        MobileSearchLayout: 'expanded'
    };
    // Each packed cookie's flags, closed; a token outside is never sent.
    var KNOWN_FLAGS = {
        SearchMiscOpts: ['noSussy', 'hidePrelPack', 'hidePromos', 'preferFlavor', 'hideBLconds', 'skipEmpty', 'noUpsell'],
        UploadOptimizerOpts: ['lowval', 'highval', 'lowvalabs', 'highvalabs', 'minmargin', 'nocond', 'noprice', 'customperc', 'unpack', 'noresults'],
        UploadCustomOpts: ['enabled']
    };
    // Each enum cookie's words, closed; any other value is sent as set.
    var ENUM_VALUES = {
        SearchDefaultSort: ['chrono', 'hybrid', 'alpha', 'number', 'retail', 'buylist'],
        SearchListingPriority: ['stores', 'prices', 'credit', 'market'],
        SearchBuylistSecondary: ['priceRatio', 'creditPrice', 'marketCredit'],
        SearchSealedContents: ['contents', 'decklist', 'variable'],
        UploadSorting: ['setchrono', 'setalpha', 'alphabetical', 'highprice', 'highspread', 'profitability'],
        UploadPriceSource: ['credit', 'marketCredit'],
        UploadTiebreak: ['credit', 'marketCredit', 'consolidate', 'custom'],
        SearchDefaultTab: ['sellers', 'buyers'],
        SearchDefaultView: ['NM', 'SP', 'MP', 'HP', 'PO', 'INDEX'],
        MobileSearchLayout: ['expanded', 'compact']
    };
    // The other settings a save can change, closed; each is only set or cleared.
    var OTHERS = [
        'SearchSellersList', 'SearchVendorsList', 'SearchSellersPriority', 'SearchVendorsPriority', 'SearchStoreFactors',
        'UploadAltPrice', 'UploadCustomBuyer', 'UploadCustomSealedBuyer', 'UploadCustomSinglesFallback', 'UploadCustomSealedFallback',
        'UploadPercSpread', 'UploadPercSpreadMax', 'UploadMinVal', 'UploadMaxVal', 'UploadMargin', 'UploadCustomPercMax',
        'UploadMultiplier', 'UploadMaxQty', 'UploadCustomMinPrice', 'UploadCustomRate', 'UploadTiebreakOrder',
        'SleepersSellersList', 'SleepersVendorsList', 'SleepersEditionList', 'NewspaperList',
        'ArbitVendorsList', 'GlobalVendorsList', 'ReverseVendorsList'
    ];
    // Binding names that serialize under another name than their cookie's.
    var RENAMED = { StoreFactors: 'SearchStoreFactors' };

    // The cookies the mobile drawer's save writes.
    var DRAWER = [
        'MobileSearchLayout', 'SearchDefaultTab', 'SearchDefaultView', 'SearchListingPriority',
        'SearchSealedContents', 'SearchSellersPriority', 'SearchVendorsPriority', 'SearchMiscOpts',
        'SearchSellersList', 'SearchVendorsList', 'SearchStoreFactors'
    ];

    function own(obj, key) { return Object.prototype.hasOwnProperty.call(obj, key); }

    function items(v) {
        return String(v || '').split(',').filter(function (s) { return s !== ''; });
    }

    // parse reads ["Name=value", ...] into {Name: value}, splitting at the first "=".
    function parse(serialized) {
        var out = {};
        (serialized || []).forEach(function (part) {
            var i = String(part).indexOf('=');
            if (i < 0) return;
            out[part.slice(0, i)] = part.slice(i + 1);
        });
        return out;
    }

    // snapshot reads every drawer cookie through read.
    function snapshot(read) {
        var out = {};
        DRAWER.forEach(function (name) { out[name] = read(name); });
        return out;
    }

    function rename(obj) {
        var out = {};
        Object.keys(obj || {}).forEach(function (k) { out[own(RENAMED, k) ? RENAMED[k] : k] = obj[k]; });
        return out;
    }

    // flagChanges walks the closed flag list, so only its own words name a scope.
    function flagChanges(name, before, after) {
        var was = (before === null || before === undefined || before === '') ? FLAGS[name] : items(before);
        var now = items(after);
        var out = [];
        KNOWN_FLAGS[name].slice().sort().forEach(function (f) {
            var on = now.indexOf(f) >= 0;
            if (on !== (was.indexOf(f) >= 0)) out.push({ name: name + '.' + f, value: on ? 'on' : 'off' });
        });
        return out;
    }

    function enumChange(name, before, after) {
        var was = String(before || '') || ENUMS[name];
        var now = String(after || '') || ENUMS[name];
        if (was === now) return [];
        var words = ENUM_VALUES[name];
        var i = words.indexOf(now);
        return [{ name: name, value: i >= 0 ? words[i] : (now ? 'set' : 'cleared') }];
    }

    // A value with commas is a set: order and empties are not a change; an empty blob is empty.
    function plain(v) {
        v = String(v || '');
        if (v === '{}' || v === '[]') return '';
        return v.indexOf(',') < 0 ? v : items(v).sort().join(',');
    }

    function otherChange(name, before, after) {
        if (plain(before) === plain(after)) return [];
        return [{ name: name, value: plain(after) ? 'set' : 'cleared' }];
    }

    // diff lists what changed between two {Name: value} maps, by name.
    function diff(before, after) {
        before = rename(before);
        after = rename(after);
        var names = Object.keys(before).concat(Object.keys(after))
            .filter(function (n, i, all) { return all.indexOf(n) === i; }).sort();
        var out = [];
        names.forEach(function (name) {
            var was = own(before, name) ? before[name] : '';
            var now = own(after, name) ? after[name] : '';
            if (own(KNOWN_FLAGS, name)) out = out.concat(flagChanges(name, was, now));
            else if (own(ENUM_VALUES, name)) out = out.concat(enumChange(name, was, now));
            else if (OTHERS.indexOf(name) >= 0) out = out.concat(otherChange(name, was, now));
        });
        return out;
    }

    // report tracks each change, then the save itself, by surface.
    function report(before, after, surface) {
        if (!(window.BAN && window.BAN.track)) return;
        diff(before, after).forEach(function (c) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.settings.change', c.value, c.name);
        });
        if (window.BAN && window.BAN.track) window.BAN.track('ui.settings.save', surface);
    }

    window.SettingsChanges = { parse: parse, snapshot: snapshot, diff: diff, report: report, DRAWER: DRAWER };
})();

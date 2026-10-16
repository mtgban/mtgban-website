import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/settings.js', import.meta.url), 'utf8');

test('autoWire registers the store adjustments binding when its container is in the body', () => {
    expect(source).toContain("bindStoreFactors('settings-store-factors')");
    expect(source).toMatch(/function bindStoreFactors\(elementId\)[\s\S]*?window\.StoreFactors\.binding\(el\)/);
});

test('the desktop and mobile templates give the editor its stores', () => {
    const desktop = readFileSync(new URL('../templates/settings/search.html', import.meta.url), 'utf8');
    const mobile = readFileSync(new URL('../templates/mobile/search.html', import.meta.url), 'utf8');
    expect(desktop).toContain('id="settings-store-factors" data-stores="{{store_factor_options .SellerKeys .VendorKeys}}"');
    expect(mobile).toContain('id="m-set-store-factors" data-stores="{{store_factor_options .SellerKeys .VendorKeys}}"');
    expect(mobile).toContain("window.StoreFactors.render(factors, window.StoreFactors.read())");
    expect(mobile).toContain("window.StoreFactors.saveEditor(factors)");
});

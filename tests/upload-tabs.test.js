import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// At 640px and under the Results/Optimizer tabs span the page; their padding
// and border count inside that width, or the bar runs 10px past the page.
test('the result tabs fit the page width on phones', () => {
    const css = read('css/upload.css');
    const rule = css.match(/\.res-tabs \{ flex-direction: row; width: 100%;[^}]*\}/);
    expect(rule, 'expected the phone .res-tabs rule').toBeTruthy();
    expect(rule[0]).toContain('box-sizing: border-box;');
});

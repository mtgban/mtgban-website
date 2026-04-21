/* Guide Data — Shared Content Registry
 * Single source of truth for the command palette and /guide page.
 */
window.__BAN_GUIDE = {
    sections: [

        // ─── Command Palette ──────────────────────────────────────────────

        {
            id: 'palette-overview',
            category: 'Command Palette',
            title: 'What the Palette Can Do',
            icon: 'sparkles',
            summary: 'A tour of what the command palette can do — cards, filters, navigation, and saved commands.',
            snippets: [],
            keywords: ['overview', 'capabilities', 'features', 'tour', 'what can', 'palette can', 'guide', 'introduction'],
            content: {
                description: '<p>The command palette is a single keyboard-driven surface for everything on the site. Open it with <kbd>Ctrl+K</kbd> / <kbd>Cmd+K</kbd>, or press <kbd>/</kbd> anywhere no input is focused. Nothing requires memorizing — the palette surfaces what\'s possible as you type.</p><p><strong>Core capabilities:</strong></p><ul><li><strong>Card search</strong> — type a card name, <kbd>Enter</kbd> to search.</li><li><strong>Filter building with chips</strong> — type a prefix like <code>s:</code> or <code>r:</code> and Tab-lock the selection; chain chips to compose complex queries.</li><li><strong>Card-aware narrowing</strong> — lock a card chip first and subsequent filter dropdowns narrow to what exists for that card.</li><li><strong>Multi-stage navigation</strong> — <code>&gt;</code> to find a page, <kbd>Tab</kbd> to reveal sub-views like Newspaper spike scores or Arbitrage filter presets.</li><li><strong>Inline syntax help</strong> — <code>?</code> followed by a keyword returns a syntax snippet you can copy.</li><li><strong>Recent searches and saved commands</strong> — your recent queries and named shortcuts are one keystroke away.</li><li><strong>Round-trip editing</strong> — saved commands can be loaded back as chips (<kbd>Shift+Enter</kbd>) so you can tweak and re-run.</li></ul>',
                table: [],
                examples: [
                    { query: 'Lightning Bolt', desc: 'Simple card search — Enter to execute' },
                    { query: '"Birds of Paradise" + Tab + s: + Tab', desc: 'Narrow sets dropdown to BoP printings, pick one' },
                    { query: '>newspaper + Tab + "Archive"', desc: 'Jump directly to Newspaper → Archive view' },
                    { query: '>arbit + Tab + "only Yield+" + Tab + "sort: Spread"', desc: 'Compose multi-filter arbitrage URL' },
                    { query: '? rarity', desc: 'Inline rarity syntax help — Enter to copy' },
                    { query: 'saved:', desc: 'Browse all saved commands' }
                ]
            }
        },

        {
            id: 'palette',
            category: 'Command Palette',
            title: 'Getting Started',
            icon: 'terminal',
            summary: 'Open the command palette with Ctrl+K / Cmd+K or / when no input is focused',
            snippets: ['Ctrl+K', 'Cmd+K', '?', '>'],
            keywords: ['palette', 'keyboard', 'shortcut', 'command', 'help', 'search', 'open', 'ctrl k', 'cmd k', 'slash', 'modes', 'chips', 'filter builder'],
            content: {
                description: '<p>The command palette provides fast keyboard-driven access to search syntax help, site navigation, and smart filter composition. Open it with <code>Ctrl+K</code> (Windows/Linux) or <code>Cmd+K</code> (Mac), or press <code>/</code> when no input field is focused.</p><p><strong>Modes</strong> (typed as prefixes into the palette input):</p><ul><li><code>?</code> — inline syntax help</li><li><code>&gt;</code> — navigate to a page or page view</li><li><code>saved:</code> — recall a saved search command</li></ul><p>For filter composition with guided autocomplete, see <strong>Filter Builder</strong>. For the full keyboard reference, see <strong>Cheatsheet</strong>.</p>',
                table: [],
                examples: [
                    { query: '? rarity', desc: 'Look up rarity syntax' },
                    { query: '>newspaper', desc: 'Jump to Newspaper (Tab for sub-views)' }
                ]
            }
        },

        {
            id: 'filter-builder',
            category: 'Command Palette',
            title: 'Filter Builder',
            icon: 'sliders-horizontal',
            summary: 'Compose search queries with guided, context-aware dropdowns',
            snippets: ['Tab to lock', 's:', 'r:', 'c:', 'f:'],
            keywords: ['filter', 'chip', 'builder', 'tab', 'autocomplete', 'narrow', 'guided', 'compose'],
            content: {
                description: 'The palette supports all search syntax prefixes as guided filter builders. Type a prefix and the dropdown shows matching options. For prefixes that accept multiple values (sets, rarities, colors, types, stores), locking a second chip of the same prefix merges with the existing one — e.g., <code>s:MKM</code> then <code>s:LEA</code> becomes <code>s:MKM,LEA</code>.<br><br><strong>Card-aware narrowing:</strong> When a card chip is present, subsequent filter dropdowns narrow their options to what\'s actually available for that card. For example, with a "Birds of Paradise" chip, <code>s:</code> only shows sets the card was printed in, and <code>c:</code> only shows green color combinations.',
                table: [
                    { value: 's: / e:', short: 'Set / edition codes' },
                    { value: 'r:', short: 'Rarity (mythic, rare, uncommon, common, special, token, oversize)' },
                    { value: 'c: / ci:', short: 'Color / color identity (WUBRG, guilds, shards, wedges, colleges)' },
                    { value: 'f:', short: 'Finish (foil, nonfoil, etched)' },
                    { value: 't:', short: 'Card type' },
                    { value: 'cond: / condr: / condb:', short: 'Condition filter (NM, SP, MP, HP, PO)' },
                    { value: 'is: / not:', short: 'Card properties and tags' },
                    { value: 'store: / seller: / vendor:', short: 'Store shorthand' },
                    { value: 'region:', short: 'us / eu / jp' },
                    { value: 'skip:', short: 'Skip categories (retail, buylist, empty, index)' },
                    { value: 'sort:', short: 'Sort order' },
                    { value: 'sm:', short: 'Search mode' },
                    { value: 'on:', short: 'Special lists (hotlist, tcgsyp, newspaper)' }
                ],
                examples: [
                    { query: 'Birds of Paradise + Tab + s:', desc: 'Sets dropdown narrows to BoP printings' },
                    { query: 'r:mythic + Tab + r: (pick rare)', desc: 'Merges to r:mythic,rare' },
                    { query: 's:MKM + Tab + f:foil + Enter', desc: 'All foils in MKM' }
                ]
            }
        },

        {
            id: 'nav-sub-views',
            category: 'Command Palette',
            title: 'Multi-Stage Navigation',
            icon: 'list-tree',
            summary: 'Navigate directly to specific page views without touching the mouse',
            snippets: ['>newspaper', '>arbit', '>sleepers'],
            keywords: ['navigate', 'sub-view', 'multi-stage', 'newspaper view', 'sleepers mode', 'arbit filter'],
            content: {
                description: 'The <code>&gt;</code> navigation mode supports page sub-views. After typing <code>&gt;</code> and a page name, press <kbd>Tab</kbd> to lock that page as a chip — the dropdown then shows that page\'s specific views (Newspaper: Spike Score, Buylist Levels, Archive; Sleepers: Bulk, Reprint, Mismatch, Gap, Hotlist; Arbitrage: filter presets and sort orders).<br><br>For Arbitrage pages, you can lock multiple filter chips in sequence — each Tab adds another filter to the composed URL. Press Enter on a sub-view to navigate, or Enter with only a parent chip to go to the page\'s base URL.',
                table: [
                    { value: '>newspaper + Tab', short: 'Shows all Newspaper views' },
                    { value: '>sleepers + Tab', short: 'Shows the 5 analysis modes' },
                    { value: '>arbit + Tab', short: 'Shows sort options + filter presets' },
                    { value: 'Enter on parent chip only', short: 'Navigates to base URL' }
                ],
                examples: [
                    { query: '>newspaper + Tab + "Archive"', desc: 'Goes to /newspaper?page=old' },
                    { query: '>arbit + Tab + "Yield+" + Tab + "Bucks+" + Enter', desc: '/arbit?nolow=true&nopenny=true' }
                ]
            }
        },

        {
            id: 'saved-commands',
            category: 'Command Palette',
            title: 'Saved Commands',
            icon: 'bookmark',
            summary: 'Save and reuse your frequent searches, with chip round-trip editing',
            snippets: ['saved:'],
            keywords: ['saved', 'bookmark', 'favorite', 'command', 'recall', 'reuse', 'store', 'manage', 'delete', 'edit'],
            content: {
                description: 'Any search query can be saved as a named command for quick reuse. On a search results page, open the palette and select <strong>Save Current Search</strong>, or press <code>Ctrl+S</code> / <code>Cmd+S</code> while the palette is open. You will be prompted to name the command.<br><br><strong>Chip round-trip:</strong> Saved commands remember their chip structure. Press <kbd>Enter</kbd> on a saved command to execute it directly, or <kbd>Shift+Enter</kbd> to restore its chips into the palette input for editing before running.<br><br>Saved commands appear in the palette by default and can be filtered with the <code>saved:</code> prefix. Hover over a saved command to reveal a delete button.',
                table: [
                    { value: 'Save Current Search', short: 'Palette command (appears on search results pages)' },
                    { value: 'Ctrl+S / Cmd+S', short: 'Save the current page search as a command (while palette is open)' },
                    { value: 'saved:', short: 'Browse saved commands in palette' },
                    { value: 'Enter on saved', short: 'Execute immediately' },
                    { value: 'Shift+Enter on saved', short: 'Restore chips for editing' }
                ],
                examples: [
                    { query: 'saved:fetchlands', desc: 'Run the "fetchlands" saved search' },
                    { query: 'saved:', desc: 'Browse all saved commands' }
                ]
            }
        },

        {
            id: 'palette-walkthroughs',
            category: 'Command Palette',
            title: 'Walkthroughs',
            icon: 'footprints',
            summary: 'Common workflows with exact keystrokes — follow along to get comfortable',
            snippets: [],
            keywords: ['walkthrough', 'tutorial', 'example', 'workflow', 'how to', 'scenario', 'step by step'],
            content: {
                description: '<p>End-to-end keystroke sequences. Follow along in a live palette to build muscle memory.</p><div class="guide-walkthrough"><h4>1. Find all foil printings of a card</h4><ol><li><kbd>Ctrl+K</kbd> to open the palette.</li><li>Type <code>Birds of Paradise</code>. The card name appears in the dropdown.</li><li><kbd>Tab</kbd> — Birds of Paradise becomes a chip.</li><li>Type <code>f:foil</code>. The Finish dropdown appears with foil highlighted.</li><li><kbd>Tab</kbd> — <code>f:foil</code> becomes a chip.</li><li><kbd>Enter</kbd> — navigates to search with the composed query.</li></ol></div><div class="guide-walkthrough"><h4>2. Jump to Arbitrage with profit filters</h4><ol><li><kbd>Ctrl+K</kbd>.</li><li>Type <code>&gt;arb</code>. Arbitrage appears.</li><li><kbd>Tab</kbd> — Arbitrage chip locks; the dropdown now shows filter presets and sort options.</li><li>Type <code>yield</code> to narrow to "only Yield+".</li><li><kbd>Tab</kbd> — filter chip added.</li><li>Type <code>bucks</code>, <kbd>Tab</kbd> — second filter added.</li><li>Type <code>sort</code>, <kbd>Tab</kbd> on "Spread %" — sort chip added.</li><li><kbd>Enter</kbd> — navigates to <code>/arbit?nolow=true&amp;nopenny=true&amp;sort=spread</code>.</li></ol></div><div class="guide-walkthrough"><h4>3. Save a complex query for later</h4><ol><li>Build a query with chips: a card plus filters (as in walkthrough 1).</li><li>Press <kbd>Ctrl+S</kbd> while the palette is open.</li><li>Enter a short name and <kbd>Enter</kbd> — the command is saved.</li><li>Later, open the palette and type <code>saved:</code> to find your command.</li><li><kbd>Enter</kbd> runs it; <kbd>Shift+Enter</kbd> restores its chips for editing.</li></ol></div><div class="guide-walkthrough"><h4>4. Narrow a search with card-aware filters</h4><ol><li><kbd>Ctrl+K</kbd>.</li><li>Type <code>Lightning Bolt</code>, <kbd>Tab</kbd> — Lightning Bolt chip locks.</li><li>Type <code>s:</code> — the sets dropdown shows only sets Lightning Bolt has been printed in.</li><li>Type <code>Alpha</code>, <kbd>Tab</kbd> — picks Limited Edition Alpha, chip locks as <code>s:Alpha</code>.</li><li>Type <code>f:foil</code>, <kbd>Tab</kbd>, <kbd>Enter</kbd> — composes the final query.</li></ol></div><div class="guide-walkthrough"><h4>5. Look up syntax while building a query</h4><ol><li>In any context, type <code>?</code> followed by a keyword — e.g. <code>?rarity</code> or <code>? foil</code>.</li><li>The dropdown shows a syntax snippet — <kbd>Enter</kbd> copies it to your clipboard.</li><li><kbd>Shift+Enter</kbd> jumps to the full section of this guide.</li></ol></div>',
                table: [],
                examples: []
            }
        },

        {
            id: 'palette-cheatsheet',
            category: 'Command Palette',
            title: 'Cheatsheet',
            icon: 'keyboard',
            summary: 'All palette keyboard shortcuts, mode prefixes, and filter prefixes at a glance',
            snippets: ['Ctrl+K', '?', '>', 'saved:', 'Tab'],
            keywords: ['cheatsheet', 'reference', 'shortcuts', 'keys', 'prefixes', 'all', 'list'],
            content: {
                description: '<strong>Opening / closing</strong>',
                table: [
                    { value: 'Ctrl+K / Cmd+K', short: 'Toggle palette from anywhere' },
                    { value: '/', short: 'Open when no input is focused' },
                    { value: 'Escape', short: 'Close palette' },
                    { value: '—', short: '—' },
                    { value: 'Tab (on dropdown result)', short: 'Lock as chip' },
                    { value: 'Tab (on active chip)', short: 'Edit — re-opens dropdown' },
                    { value: '←  /  →', short: 'Navigate between chips' },
                    { value: 'Backspace / Delete', short: 'Remove active chip' },
                    { value: '↑  /  ↓', short: 'Navigate dropdown' },
                    { value: 'Enter', short: 'Execute composed query / navigate / copy snippet' },
                    { value: 'Shift+Enter', short: 'Alt action (see context)' },
                    { value: 'Ctrl+S / Cmd+S', short: 'Save current query as a named command' },
                    { value: '—', short: '—' },
                    { value: '?  (or help: / syntax:)', short: 'Help mode — inline syntax lookup' },
                    { value: '>', short: 'Navigation mode — pages and sub-views' },
                    { value: 'saved:', short: 'Saved mode — browse saved commands' },
                    { value: '—', short: '—' },
                    { value: 's:  e:', short: 'Set / edition (accepts list, narrows to card printings)' },
                    { value: 'r:', short: 'Rarity (accepts list, narrows to card rarities)' },
                    { value: 'c:  ci:', short: 'Color / color identity (WUBRG + guild/shard/wedge/college/four-color)' },
                    { value: 'f:', short: 'Finish (foil / nonfoil / etched)' },
                    { value: 't:', short: 'Card type' },
                    { value: 'cond:  condr:  condb:', short: 'Condition (singleton)' },
                    { value: 'is:  not:', short: 'Property tags' },
                    { value: 'store:  seller:  vendor:', short: 'Store shorthand' },
                    { value: 'region:', short: 'us / eu / jp (singleton)' },
                    { value: 'skip:', short: 'Skip categories' },
                    { value: 'sort:', short: 'Sort order (singleton)' },
                    { value: 'sm:', short: 'Search mode (singleton)' },
                    { value: 'on:', short: 'Special lists (hotlist, tcgsyp, newspaper)' }
                ],
                examples: []
            }
        },

        // ─── Search Syntax ────────────────────────────────────────────────

        {
            id: 'basic-syntax',
            category: 'Search Syntax',
            title: 'Basic Syntax',
            icon: 'text-cursor-input',
            summary: 'Card names, Pricefall bot notation, suffix shortcuts (* foil, & nonfoil, ~ etched).',
            snippets: ['name|set|number|finish', 'Sol Ring*', 'Sheoldred (Showcase)', 'r:rare,mythic'],
            keywords: ['basic', 'name', 'pricefall', 'notation', 'suffix', 'foil', 'nonfoil', 'etched', 'altfoil', 'finish', 'comma', 'multiple', 'syntax', 'search'],
            content: {
                description: 'Start typing a card name and an autocomplete dropdown will appear. You can also use the Pricefall bot notation: <code>name[|code[|number[|finish]]]</code>.<br><br>Human-readable tags are also supported — for example, appending <code>(Extended Art)</code> or <code>(Showcase)</code> to a card name will filter to those versions (does not work in regexp mode).<br><br>Use commas to supply multiple values for any filter. Finish suffixes can be appended directly to any search term:',
                table: [
                    { value: '&', short: 'Non-foil only' },
                    { value: '*', short: 'Foil only' },
                    { value: '~', short: 'Etched only' },
                    { value: '`', short: 'Alt-foil (surge, ripple, galaxy, etc.)' }
                ],
                examples: [
                    { query: 'Lightning Bolt|LEA', desc: 'Lightning Bolt from Alpha' },
                    { query: 'Sol Ring*', desc: 'Foil Sol Rings only' },
                    { query: 'Sheoldred (Showcase)', desc: 'Showcase versions of Sheoldred' },
                    { query: 'r:rare,mythic', desc: 'Rare OR mythic cards' }
                ]
            }
        },

        {
            id: 'editions',
            category: 'Search Syntax',
            title: 'Editions & Sets',
            icon: 'library',
            summary: 'Filter by set code (s:MKM), full name (s:"Aether Revolt"), or regexp (se:^MH).',
            snippets: ['s:CODE', 's:"Set Name"', 'se:REGEXP', 'e:CODE'],
            keywords: ['edition', 'set', 'expansion', 'code', 'name', 'scryfall', 'e:', 's:', 'se:', 'regex', 'regexp', 'filter'],
            content: {
                description: 'Filter cards by edition using the Scryfall notation <code>s:CODE</code> or the full edition name in quotes: <code>s:"Aether Revolt"</code>.<br><br>Regular expressions are supported with <code>se:REGEXP</code>. For compatibility, <code>e:CODE</code> (exact match) and <code>ee:REGEXP</code> (regexp) are also accepted.',
                table: [
                    { value: 's:CODE', short: 'Set by code (e.g. s:MKM)' },
                    { value: 's:"Name"', short: 'Set by full name' },
                    { value: 'se:REGEXP', short: 'Set code by regular expression' },
                    { value: 'e:CODE', short: 'Compatibility alias for s:CODE' }
                ],
                examples: [
                    { query: 's:MKM', desc: 'Cards from Murders at Karlov Manor' },
                    { query: 's:"Aether Revolt"', desc: 'Using full set name' },
                    { query: 'se:^MH', desc: 'Sets starting with "MH" (regex)' },
                    { query: 'e:LEA', desc: 'Compatibility syntax for Alpha' }
                ]
            }
        },

        {
            id: 'collector-numbers',
            category: 'Search Syntax',
            title: 'Collector Numbers',
            icon: 'hash',
            summary: 'Filter by number (cn:123), range (cn:1-50), comparison (cn>300), or per-set (cn:MKM:42).',
            snippets: ['cn:123', 'cn:1-50', 'cn>300', 'cn:CODE:42', 'cne:REGEXP'],
            keywords: ['collector', 'number', 'cn', 'cne', 'range', 'comparison', 'regex', 'regexp', '#', 'card number'],
            content: {
                description: 'Filter by collector number using <code>cn:NUMBER</code>. For plain numbers you can use comparison operators <code>cn&gt;NUMBER</code> and <code>cn&lt;NUMBER</code>, or a range <code>cn:NUMBER-NUMBER</code>.<br><br>Regular expressions are supported via <code>cne:REGEXP</code>.<br><br>To target a specific set while leaving other results untouched, prepend the set code: <code>cn:CODE:NUMBER</code>.',
                table: [
                    { value: 'cn:NUMBER', short: 'Exact collector number' },
                    { value: 'cn:N-N', short: 'Range of collector numbers' },
                    { value: 'cn>N / cn<N', short: 'Comparison operators' },
                    { value: 'cn:CODE:N', short: 'Number within a specific set' },
                    { value: 'cne:REGEXP', short: 'Collector number by regexp' }
                ],
                examples: [
                    { query: 'cn:123', desc: 'Cards numbered 123' },
                    { query: 'cn:1-50', desc: 'Cards numbered 1–50' },
                    { query: 'cn>300', desc: 'Cards above #300' },
                    { query: 'cn:MKM:42', desc: '#42 from MKM only' }
                ]
            }
        },

        {
            id: 'finish',
            category: 'Search Syntax',
            title: 'Finish & Foils',
            icon: 'sparkles',
            summary: 'Filter foil treatments: f:foil, f:etched, f:nonfoil, is:altfoil.',
            snippets: ['f:foil', 'f:etched', 'f:nonfoil', 'is:altfoil', 'Lightning Bolt*'],
            keywords: ['finish', 'foil', 'etched', 'nonfoil', 'altfoil', 'surge', 'ripple', 'galaxy', 'treatment', 'f:', 'is:altfoil'],
            content: {
                description: 'Filter by finish with <code>f:VALUE</code>. Accepted values are <code>nonfoil</code>, <code>foil</code>, and <code>etched</code>, with shorthand <code>nf</code>, <code>f</code>, and <code>e</code>.<br><br>For special foil variants (Galaxy, Surge, Ripple, etc.) use <code>is:altfoil</code> as an additional filter.<br><br>Alternatively, use suffix notation directly on any query:',
                table: [
                    { value: '&', short: 'Non-foil only' },
                    { value: '*', short: 'Foil only' },
                    { value: '~', short: 'Etched only' },
                    { value: '`', short: 'Alt-foil (surge, ripple, galaxy)' }
                ],
                examples: [
                    { query: 'f:foil', desc: 'Foil versions only' },
                    { query: 'f:e', desc: 'Etched foils (short form)' },
                    { query: 'Lightning Bolt*', desc: 'Foil Lightning Bolts' },
                    { query: 'Sol Ring&', desc: 'Non-foil Sol Rings' }
                ]
            }
        },

        {
            id: 'colors',
            category: 'Search Syntax',
            title: 'Colors & Identity',
            icon: 'palette',
            summary: 'Filter by color (c:RG) or identity (ci:esper); supports guild, shard, and college names.',
            snippets: ['c:WUBRG', 'ci:esper', 'c:azorius', 'c:colorless', 'c:multicolor'],
            keywords: ['color', 'colour', 'identity', 'ci', 'c:', 'WUBRG', 'white', 'blue', 'black', 'red', 'green', 'colorless', 'multicolor', 'guild', 'shard', 'wedge', 'college', 'azorius', 'dimir', 'rakdos', 'gruul', 'selesnya', 'orzhov', 'izzet', 'golgari', 'boros', 'simic', 'bant', 'esper', 'grixis', 'jund', 'naya', 'abzan', 'jeskai', 'sultai', 'mardu', 'temur'],
            content: {
                description: 'Filter by color with <code>c:COLOR</code> and color identity with <code>ci:COLOR</code>. Use standard WUBRG letters, full color names, <code>C</code> for colorless, or <code>M</code> for multicolor.<br><br>Named groups are also supported:<br><strong>Guilds (2-color):</strong> azorius, dimir, rakdos, gruul, selesnya, orzhov, izzet, golgari, boros, simic<br><strong>Shards/Wedges (3-color):</strong> bant, esper, grixis, jund, naya, abzan, jeskai, sultai, mardu, temur<br><strong>Colleges (Strixhaven):</strong> silverquill, prismari, witherbloom, lorehold, quandrix<br><strong>Four-color:</strong> chaos, aggression, altruism, growth, artifice',
                table: [
                    { value: 'c:COLOR', short: 'Filter by card color' },
                    { value: 'ci:COLOR', short: 'Filter by color identity' },
                    { value: 'c:colorless', short: 'Colorless cards' },
                    { value: 'c:M', short: 'Multicolor cards' }
                ],
                examples: [
                    { query: 'c:rg', desc: 'Red and green cards' },
                    { query: 'ci:esper', desc: 'Esper color identity (WUB)' },
                    { query: 'c:quandrix', desc: 'Green/Blue (Strixhaven college)' },
                    { query: 'c:colorless', desc: 'Colorless cards' }
                ]
            }
        },

        {
            id: 'rarity',
            category: 'Search Syntax',
            title: 'Rarity',
            icon: 'diamond',
            summary: 'Filter by rarity (r:mythic, r:m) or use comparisons (r>=rare).',
            snippets: ['r:mythic', 'r:m', 'r:rare', 'r>=rare', 'r<uncommon'],
            keywords: ['rarity', 'r:', 'mythic', 'rare', 'uncommon', 'common', 'special', 'token', 'oversize', 'shorthand', 'comparison'],
            content: {
                description: 'Filter by rarity with <code>r:RARITY</code>. The first letter can be used as shorthand. Comparison operators <code>r&gt;RARITY</code> and <code>r&lt;RARITY</code> are also supported.',
                table: [
                    { value: 'mythic', short: 'm' },
                    { value: 'rare', short: 'r' },
                    { value: 'uncommon', short: 'u' },
                    { value: 'common', short: 'c' },
                    { value: 'special', short: 's' },
                    { value: 'token', short: 't' },
                    { value: 'oversize', short: 'o' }
                ],
                examples: [
                    { query: 'r:mythic', desc: 'Mythic rares only' },
                    { query: 'r:m', desc: 'Same using shorthand' },
                    { query: 'r>=rare', desc: 'Rare and mythic' },
                    { query: 'r:rare,mythic s:MKM', desc: 'Rares and mythics from MKM' }
                ]
            }
        },

        {
            id: 'conditions',
            category: 'Search Syntax',
            title: 'Conditions',
            icon: 'shield-check',
            summary: 'Filter by card condition: cond:NM, condr: for retail, condb: for buylist.',
            snippets: ['cond:NM', 'cond:SP', 'condr:MP', 'condb:NM', 'cond>SP'],
            keywords: ['condition', 'cond', 'NM', 'SP', 'MP', 'HP', 'PO', 'near mint', 'slightly played', 'moderately played', 'heavily played', 'poor', 'retail', 'buylist', 'condr', 'condb'],
            content: {
                description: 'Filter by condition with <code>cond:COND</code>. Use <code>condr:</code> to apply the filter to retail prices only, or <code>condb:</code> for buylist prices only. Comparison operators are supported.',
                table: [
                    { value: 'NM', short: 'Near Mint' },
                    { value: 'SP', short: 'Slightly Played' },
                    { value: 'MP', short: 'Moderately Played' },
                    { value: 'HP', short: 'Heavily Played' },
                    { value: 'PO', short: 'Poor' }
                ],
                examples: [
                    { query: 'cond:NM', desc: 'Near Mint only' },
                    { query: 'condr:SP', desc: 'SP retail prices only' },
                    { query: 'condb:MP', desc: 'MP buylist prices only' },
                    { query: 'cond>SP', desc: 'Worse than SP (MP, HP, PO)' }
                ]
            }
        },

        {
            id: 'types',
            category: 'Search Syntax',
            title: 'Card & Product Types',
            icon: 'swords',
            summary: 'Filter by type, subtype, or supertype (t:creature, t:goblin, t:booster).',
            snippets: ['t:creature', 't:legendary', 't:goblin', 't:booster', 't:planeswalker'],
            keywords: ['type', 'supertype', 'subtype', 'creature', 'instant', 'sorcery', 'enchantment', 'artifact', 'planeswalker', 'land', 'legendary', 'goblin', 'elf', 'wizard', 'booster', 'box', 'deck', 'sealed', 'product', 'redemption'],
            content: {
                description: 'Filter by card type with <code>t:VALUE</code>, accepting any valid supertype, type, or subtype. The same option also works for sealed products — you can search by category (booster, box, deck) or subtype (draft, collector, intro), or any fragment of the product name.',
                table: [],
                examples: [
                    { query: 't:creature', desc: 'All creatures' },
                    { query: 't:legendary', desc: 'Legendary permanents' },
                    { query: 't:goblin', desc: 'Goblin creatures' },
                    { query: 't:booster s:blb', desc: 'All booster products in BLB' },
                    { query: 't:redemption', desc: 'All MTGO redemption products' }
                ]
            }
        },

        {
            id: 'dates',
            category: 'Search Syntax',
            title: 'Release Dates',
            icon: 'calendar',
            summary: 'Filter by release date (date:2024, date>2023-01-01, year<2004, date:now).',
            snippets: ['date:2024', 'date>2023-01-01', 'year<2004', 'date:now', 'date:MKM'],
            keywords: ['date', 'year', 'release', 'when', 'old', 'new', 'vintage', 'modern', 'today', 'now', 'iso', 'format'],
            content: {
                description: 'Filter by release date with <code>date:VALUE</code>, <code>date&gt;VALUE</code>, or <code>date&lt;VALUE</code>. Use <code>year:VALUE</code> for year-only filtering. The value formats accepted are:',
                table: [
                    { value: 'YYYY-MM-DD', short: 'ISO date format' },
                    { value: 'YYYY-MM', short: 'Year and month' },
                    { value: 'YYYY', short: 'Year only' },
                    { value: 'Set code', short: 'Same date as that set' },
                    { value: 'now / today', short: 'Current date' }
                ],
                examples: [
                    { query: 'date:2024', desc: 'Cards released in 2024' },
                    { query: 'date>2023-01-01', desc: 'Released after Jan 1, 2023' },
                    { query: 'date:MKM', desc: 'Same release date as MKM' },
                    { query: 'year<2004', desc: 'Released before 2004' }
                ]
            }
        },

        {
            id: 'properties',
            category: 'Search Syntax',
            title: 'Card Properties',
            icon: 'tag',
            summary: 'Filter by frame, language, or game properties (is:reserved, is:ea, not:foil).',
            snippets: ['is:reserved', 'is:extendedart', 'is:showcase', 'is:borderless', 'not:foil', 'is:ea', 'is:sc'],
            keywords: ['properties', 'is:', 'not:', 'reserved', 'token', 'oversize', 'fullart', 'extendedart', 'extended art', 'showcase', 'reskin', 'borderless', 'gold', 'retro', 'future', 'altfoil', 'japanese', 'phyrexian', 'wcd', 'commander', 'funny', 'gamechanger', 'ea', 'sc', 'bd', 'gc', 'jp', 'jpn', 'ph'],
            content: {
                description: 'Filter by card properties with <code>is:VALUE</code> or exclude with <code>not:VALUE</code> (equivalent to <code>-is:VALUE</code>).<br><br><strong>Generic:</strong> reserved, token, oversize, funny, wcd, commander, productless, gamechanger<br><strong>Frame:</strong> fullart, extendedart, showcase, reskin, borderless, gold, retro, future, foil, nonfoil, altfoil<br><strong>Language:</strong> japanese, phyrexian<br><br>Some values have shorthand aliases:',
                table: [
                    { value: 'ea', short: 'fullart / extended art' },
                    { value: 'sc', short: 'showcase' },
                    { value: 'bd', short: 'borderless' },
                    { value: 'gc', short: 'gamechanger' },
                    { value: 'jp / jpn', short: 'japanese' },
                    { value: 'ph', short: 'phyrexian' }
                ],
                examples: [
                    { query: 'is:reserved', desc: 'Reserved List cards' },
                    { query: 'is:extendedart', desc: 'Extended art versions' },
                    { query: 'is:showcase is:foil', desc: 'Foil showcase cards' },
                    { query: 'not:foil', desc: 'Non-foil only' },
                    { query: 'is:ea r:mythic', desc: 'Extended art mythics' }
                ]
            }
        },

        {
            id: 'promos',
            category: 'Search Syntax',
            title: 'Promos & Variants',
            icon: 'gift',
            summary: 'Filter promos: is:promo, is:prerelease, is:buyabox, is:serialized.',
            snippets: ['is:promo', 'is:prerelease', 'is:buyabox', 'is:serialized'],
            keywords: ['promo', 'prerelease', 'buyabox', 'buy a box', 'serialized', 'variant', 'stamped', 'convention', 'fnm', 'wpn', 'gameday', 'judge', 'brawl', 'planeswalker deck'],
            content: {
                description: 'Filter promo cards with <code>is:VALUE</code>. Use <code>is:promo</code> to match any promo type, or a specific tag for targeted filtering. Multiple promo tags are available depending on the product.',
                table: [],
                examples: [
                    { query: 'is:prerelease', desc: 'Prerelease promos' },
                    { query: 'is:buyabox', desc: 'Buy-a-Box promos' },
                    { query: 'is:serialized', desc: 'Serialized numbered cards' },
                    { query: 'is:promo r:mythic', desc: 'Any mythic promo' }
                ]
            }
        },

        {
            id: 'lands',
            category: 'Search Syntax',
            title: 'Land & Set Cycles',
            icon: 'mountain',
            summary: 'Filter land cycles (is:fetchland, is:dual) and special sets (is:power9, is:abu4h).',
            snippets: ['is:fetchland', 'is:dual', 'is:shockland', 'is:power9', 'is:abu4h'],
            keywords: ['land', 'cycle', 'fetchland', 'fetch', 'dual', 'shockland', 'shock', 'painland', 'pain', 'checkland', 'check', 'fastland', 'fast', 'filterland', 'surveilland', 'vergeland', 'power9', 'p9', 'abu4h', 'alpha', 'beta', 'unlimited'],
            content: {
                description: 'Filter by well-known land cycles and set groupings using <code>is:VALUE</code>:',
                table: [
                    { value: 'is:dual', short: 'Original dual lands' },
                    { value: 'is:fetchland', short: 'Fetch lands' },
                    { value: 'is:shockland', short: 'Shock lands' },
                    { value: 'is:painland', short: 'Pain lands' },
                    { value: 'is:checkland', short: 'Check lands' },
                    { value: 'is:fastland', short: 'Fast lands' },
                    { value: 'is:filterland', short: 'Filter lands' },
                    { value: 'is:surveilland', short: 'Surveil lands' },
                    { value: 'is:vergeland', short: 'Verge lands' },
                    { value: 'is:power9 / is:p9', short: 'The Power Nine' },
                    { value: 'is:abu4h', short: 'Alpha/Beta/Unlimited + first 4 expansions' }
                ],
                examples: [
                    { query: 'is:fetchland', desc: 'All fetchlands' },
                    { query: 'is:dual', desc: 'Original dual lands' },
                    { query: 'is:power9', desc: 'The Power Nine cards' },
                    { query: 'is:shockland f:foil', desc: 'Foil shocklands' }
                ]
            }
        },

        {
            id: 'prices',
            category: 'Search Syntax',
            title: 'Price Filters',
            icon: 'dollar-sign',
            summary: 'Filter by price (price>10), buylist (buy_price>5), ratio (ratio>50), or cross-store (price>TCGLow).',
            snippets: ['price>10', 'price<5', 'buy_price>5', 'ratio>50', 'price>TCGLow', 'arb_price', 'rev_price'],
            keywords: ['price', 'buy_price', 'arb_price', 'rev_price', 'ratio', 'cost', 'value', 'retail', 'buylist', 'TCGLow', 'filter', 'comparison', 'desirability'],
            content: {
                description: 'Filter by retail price with <code>price&gt;VALUE</code> or <code>price&lt;VALUE</code>. Use <code>buy_price</code> to filter buylist prices. Filters can also reference a store\'s price — <code>price&gt;TCGLow</code> returns stores charging more than the TCG Low index for that card.<br><br>For cross-category comparisons: <code>arb_price</code> uses buylist price as a reference for retail results, and <code>rev_price</code> uses retail price as a reference for buylist results.<br><br><code>ratio&gt;VALUE</code> filters by buylist desirability percentage (max 64).',
                table: [
                    { value: 'price', short: 'Retail price filter' },
                    { value: 'buy_price', short: 'Buylist price filter' },
                    { value: 'arb_price', short: 'Retail results filtered by buylist price' },
                    { value: 'rev_price', short: 'Buylist results filtered by retail price' },
                    { value: 'ratio', short: 'Buylist desirability ratio (0–64)' }
                ],
                examples: [
                    { query: 'price<10', desc: 'Cards selling under $10 retail' },
                    { query: 'price>TCGLow', desc: 'Stores above TCG Low price' },
                    { query: 'buy_price>5', desc: 'Buylists paying over $5' },
                    { query: 'ratio>50', desc: 'High buylist demand cards' }
                ]
            }
        },

        {
            id: 'stores',
            category: 'Search Syntax',
            title: 'Stores & Regions',
            icon: 'store',
            summary: 'Filter by store (store:TCG), region (region:eu), or skip categories (skip:index).',
            snippets: ['store:TCG', 'store:only:CK', 'vendor:CK', 'seller:SCG', 'region:eu', 'skip:index', 'skip:retail'],
            keywords: ['store', 'vendor', 'seller', 'region', 'skip', 'only', 'CK', 'TCG', 'SCG', 'MKM', 'us', 'eu', 'jp', 'index', 'retail', 'buylist', 'empty', 'filter'],
            content: {
                description: 'Filter by seller or vendor with <code>store:shorthand</code>, <code>seller:shorthand</code> (retail), or <code>vendor:shorthand</code> (buylist). These drop results where the store is absent. To show only that store, use <code>store:only:shorthand</code>.<br><br>Filter by region with <code>region:us</code>, <code>region:eu</code>, or <code>region:jp</code>.<br><br>The <code>skip:</code> filter hides entire result categories. Note: store filters leave index results visible — use <code>skip:index</code> to hide them.',
                table: [
                    { value: 'store:X', short: 'Include results from store X' },
                    { value: 'store:only:X', short: 'Show only results from store X' },
                    { value: 'seller:X', short: 'Retail-only store filter' },
                    { value: 'vendor:X', short: 'Buylist-only store filter' },
                    { value: 'region:us/eu/jp', short: 'Filter by store region' },
                    { value: 'skip:retail', short: 'Hide all retail prices' },
                    { value: 'skip:buylist', short: 'Hide all buylist prices' },
                    { value: 'skip:index', short: 'Hide index/aggregate prices' },
                    { value: 'skip:empty', short: 'Hide cards with no prices' }
                ],
                examples: [
                    { query: 'store:TCG', desc: 'TCGplayer listings' },
                    { query: 'store:only:CK', desc: 'Card Kingdom results only' },
                    { query: 'vendor:CK', desc: 'Card Kingdom buylist' },
                    { query: 'region:eu', desc: 'European stores only' },
                    { query: 'skip:index', desc: 'Hide index/aggregate prices' }
                ]
            }
        },

        {
            id: 'modes',
            category: 'Search Syntax',
            title: 'Search Modes',
            icon: 'scan-search',
            summary: 'Change matching behavior: sm:exact (default), sm:prefix, sm:any, sm:regexp, sm:scryfall.',
            snippets: ['sm:exact', 'sm:prefix', 'sm:any', 'sm:regexp', 'sm:scryfall'],
            keywords: ['mode', 'sm:', 'exact', 'prefix', 'any', 'regexp', 'regex', 'scryfall', 'match', 'contains', 'starts', 'pattern', 'forward'],
            content: {
                description: 'Change search matching behavior with <code>sm:VALUE</code>. The default mode is <code>exact</code> — only cards with that precise name are returned.<br><br>In <code>scryfall</code> mode, the query is forwarded to Scryfall. BAN card filters are disabled to avoid conflicts, but store and price filters still apply.',
                table: [
                    { value: 'exact', short: 'Exact name match (default)' },
                    { value: 'prefix', short: 'Names starting with search term' },
                    { value: 'any', short: 'Names containing search term' },
                    { value: 'regexp', short: 'Regular expression (case sensitive)' },
                    { value: 'scryfall', short: 'Forward query to Scryfall' }
                ],
                examples: [
                    { query: 'Vesuva', desc: 'exact: only "Vesuva", not Vesuvan cards' },
                    { query: 'sm:prefix Dragonlord', desc: 'prefix: cards starting with "Dragonlord"' },
                    { query: 'sm:any Draco', desc: 'any: Draco and all cards containing "draco"' },
                    { query: 'sm:regexp Cluestone$', desc: 'regexp: cards ending in "Cluestone"' },
                    { query: 'sm:scryfall art:loot f:f', desc: 'scryfall: foil cards tagged "loot"' }
                ]
            }
        },

        {
            id: 'sorting',
            category: 'Search Syntax',
            title: 'Sorting',
            icon: 'arrow-up-down',
            summary: 'Sort results by date (default), price, name, or collector number.',
            snippets: ['sort:chrono', 'sort:retail', 'sort:buylist', 'sort:alpha', 'sort:number', 'sort:hybrid'],
            keywords: ['sort', 'order', 'chrono', 'hybrid', 'alpha', 'alphabetical', 'number', 'retail', 'buylist', 'price', 'date', 'print', 'collector'],
            content: {
                description: 'Change the sort order of results with <code>sort:VALUE</code>. Note: when a sort is set via query, the sort UI dropdown is disabled.',
                table: [
                    { value: 'chrono', short: 'By print date (default)' },
                    { value: 'hybrid', short: 'Alphabetical with sets grouped' },
                    { value: 'alpha', short: 'Alphabetical order' },
                    { value: 'number', short: 'By collector number' },
                    { value: 'retail', short: 'By TCGplayer price' },
                    { value: 'buylist', short: 'By Card Kingdom buylist price' }
                ],
                examples: [
                    { query: 'sort:retail', desc: 'Highest TCG price first' },
                    { query: 'r:mythic sort:retail', desc: 'Most expensive mythics first' },
                    { query: 'is:fetchland sort:buylist', desc: 'Fetchlands by buylist value' }
                ]
            }
        },

        {
            id: 'lists',
            category: 'Search Syntax',
            title: 'Special Lists',
            icon: 'list-checks',
            summary: 'Filter cards on curated lists: on:hotlist, on:tcgsyp, on:newspaper.',
            snippets: ['on:hotlist', 'on:tcgsyp', 'on:newspaper'],
            keywords: ['list', 'on:', 'hotlist', 'tcgsyp', 'syp', 'newspaper', 'spike', 'hot', 'curated', 'special', 'TCGplayer'],
            content: {
                description: 'Check if a card belongs to a curated list using <code>on:VALUE</code>:',
                table: [
                    { value: 'hotlist', short: 'Highest buylist prices over 3 months' },
                    { value: 'tcgsyp', short: 'Present on the TCGplayer SYP list' },
                    { value: 'newspaper', short: 'Found in a Newspaper Spike score' }
                ],
                examples: [
                    { query: 'on:hotlist', desc: 'Cards on the buylist hot list' },
                    { query: 'on:tcgsyp', desc: 'Cards available on TCGplayer SYP' },
                    { query: 'on:newspaper r:mythic', desc: 'Newspaper spike mythics' }
                ]
            }
        },

        {
            id: 'names',
            category: 'Search Syntax',
            title: 'Name Filters',
            icon: 'type',
            summary: 'Include or exclude cards by name (name:"X", -name:"Y") or filter by ID.',
            snippets: ['name:"Lightning Bolt"', '-name:"Sol Ring"', 'namee:^The', 'id:12345'],
            keywords: ['name', 'namee', 'id', 'include', 'exclude', 'filter', 'specific', 'regex', 'regexp', 'MTGBAN', 'MTGJSON', 'scryfall', 'TCGplayer', 'product ID'],
            content: {
                description: 'Filter by card name to include or exclude specific cards from a query using <code>name:NAME</code>. Enclose names with spaces in quotes or parentheses. Prefix with <code>-</code> to exclude.<br><br>Regular expressions are supported with <code>namee:REGEXP</code>.<br><br>Filter by internal card ID with <code>id:VALUE</code>, supporting MTGBAN, MTGJSON, Scryfall, and TCGplayer product IDs.',
                table: [
                    { value: 'name:"X"', short: 'Include only cards named X' },
                    { value: '-name:"X"', short: 'Exclude cards named X' },
                    { value: 'namee:REGEXP', short: 'Name filter using regular expression' },
                    { value: 'id:VALUE', short: 'Filter by MTGBAN/MTGJSON/Scryfall/TCG ID' }
                ],
                examples: [
                    { query: 'name:"Lightning Bolt"', desc: 'Exact name match' },
                    { query: '-name:"Sol Ring"', desc: 'Exclude Sol Ring from results' },
                    { query: 'namee:^The', desc: 'Names starting with "The"' },
                    { query: 'id:12345', desc: 'By TCGplayer product ID' }
                ]
            }
        },

        // ─── Features ─────────────────────────────────────────────────────

        {
            id: 'feature-search',
            category: 'Features',
            title: 'Card & Sealed Search',
            icon: 'search',
            summary: 'Search prices across all stores, view historical charts, and follow affiliate links.',
            snippets: [],
            keywords: ['search', 'price', 'retail', 'buylist', 'chart', 'history', 'affiliate', 'store', 'sealed', 'product', 'condition', 'index'],
            content: {
                description: 'The main search page lets you find prices across all tracked stores and vendors for both single cards and sealed products. Results are split by retail and buylist, with condition breakdowns and index prices from aggregators like TCGplayer.<br><br>Click the chart icon (📊) on any card to load historical price data from major vendors. Use affiliate links in results to support BAN while making purchases.',
                table: [],
                examples: [
                    { query: 'Lightning Bolt s:lea', desc: 'Alpha Lightning Bolt prices' },
                    { query: 'r:mythic sort:retail skip:index', desc: 'Mythics by price, no index' },
                    { query: 't:booster s:blb', desc: 'Bloomburrow booster products' }
                ]
            }
        },

        {
            id: 'feature-newspaper',
            category: 'Features',
            requiresNav: 'Newspaper',
            title: 'Newspaper',
            icon: 'newspaper',
            summary: 'Daily Spike scores, buylist changes, seller count trends, SYP list, and archive.',
            snippets: [],
            keywords: ['newspaper', 'spike', 'score', 'buylist', 'change', 'trend', 'seller', 'count', 'SYP', 'archive', 'daily', 'movement', 'price change'],
            content: {
                description: 'The Newspaper page tracks daily market movements. It shows Spike scores (sudden price increases), buylist changes (vendors adjusting what they pay), and seller count trends (supply going up or down).<br><br>The SYP (Save Your Points) section lists TCGplayer store credit opportunities. An archive lets you browse historical issues.',
                table: [],
                examples: [
                    { query: 'on:newspaper', desc: 'Cards currently in a Newspaper spike' },
                    { query: 'on:newspaper r:mythic', desc: 'Spiking mythics' }
                ]
            }
        },

        {
            id: 'feature-sleepers',
            category: 'Features',
            requiresNav: 'Sleepers',
            title: 'Sleepers',
            icon: 'moon',
            summary: 'Discover undervalued cards with bulk, reprint, mismatch, and gap analysis across tiers.',
            snippets: [],
            keywords: ['sleepers', 'bulk', 'reprint', 'mismatch', 'gap', 'hotlist', 'analysis', 'tier', 'rank', 'S', 'F', 'undervalued', 'opportunity', 'arbitrage'],
            content: {
                description: 'The Sleepers page surfaces cards that may be undervalued or overlooked. Analysis modes include:<br><br><strong>Bulk:</strong> Cards available for low prices across vendors<br><strong>Reprint:</strong> Cards with upcoming or recent reprints affecting price<br><strong>Mismatch:</strong> Cards priced inconsistently across stores<br><strong>Gap:</strong> Cards where buylist and retail prices diverge significantly<br><strong>Hotlist:</strong> High-demand cards based on sustained buylist interest<br><br>Cards are tiered S through F based on opportunity score.',
                table: [],
                examples: []
            }
        },

        {
            id: 'feature-upload',
            category: 'Features',
            requiresNav: 'Upload',
            title: 'Upload & Optimize',
            icon: 'upload',
            summary: 'Upload a collection (CSV, Excel, Moxfield, Deckbox) and optimize across buylist vendors.',
            snippets: [],
            keywords: ['upload', 'collection', 'CSV', 'excel', 'google sheets', 'moxfield', 'deckbox', 'buylist', 'optimize', 'export', 'CK', 'SCG', 'TCG', 'MKM', 'card kingdom', 'cardmarket'],
            content: {
                description: 'Upload your collection in CSV, Excel, Google Sheets, Moxfield, or Deckbox format. BAN will match your cards against all active buylists and calculate the optimal split across vendors to maximize return.<br><br>Export results in formats compatible with Card Kingdom, StarCityGames, TCGplayer, and Cardmarket.',
                table: [],
                examples: []
            }
        },

        {
            id: 'feature-arbitrage',
            category: 'Features',
            requiresNav: 'Arbitrage',
            title: 'Arbitrage',
            icon: 'trending-up',
            summary: 'Find price gaps between retail and buylist; filter by condition, foil, rarity, and more.',
            snippets: [],
            keywords: ['arbitrage', 'arb', 'gap', 'price difference', 'retail', 'buylist', 'profit', 'flip', 'reverse', 'global', 'condition', 'foil', 'rarity', 'filter'],
            content: {
                description: 'The Arbitrage page identifies cards where there is a meaningful gap between what stores are selling for and what other vendors are buying at — potential flip opportunities.<br><br><strong>Standard mode:</strong> Compare retail prices to buylist prices across all vendors<br><strong>Reverse mode:</strong> Find buylists paying more than retail prices<br><strong>Global mode:</strong> Cross-store arbitrage including international vendors<br><br>Filter results by condition, foil treatment, rarity, and price thresholds.',
                table: [],
                examples: []
            }
        },

        // ─── Tips & Tricks ────────────────────────────────────────────────

        {
            id: 'tips',
            category: 'Tips & Tricks',
            title: 'Power User Tips',
            icon: 'lightbulb',
            summary: 'Price refresh timing, historical charts, reprint finder, buylist ratios, and trade credit tooltips.',
            snippets: [],
            keywords: ['tips', 'tricks', 'power user', 'refresh', 'timing', 'history', 'chart', 'reprint', 'ratio', 'trade credit', 'tooltip', 'flavor name', 'condition', 'index', 'feedback'],
            content: {
                description: 'A few things to know to get the most out of BAN:<br><br><strong>Price refresh:</strong> Data is updated periodically throughout the day. The exact delay is randomized to prevent sniping.<br><br><strong>Historical data:</strong> Click the 📊 chart icon on any card to view price history from major vendors.<br><br><strong>Reprint finder:</strong> Click 📖 on a card to see every product containing any reprint of that card. Source products are also accessible via "Found in * products" links.<br><br><strong>Buylist ratios:</strong> The percentage shown on buylist results reflects vendor desirability — higher means they want it more. Only shown when the vendor also has retail stock at matching conditions.<br><br><strong>Trade credit:</strong> Hover over a buylist price to see the corresponding trade credit value, if available.<br><br><strong>Conditions:</strong> Inventory prices reflect stated conditions (accuracy depends on provider). Buylist prices are always NM. Sealed products are always in sealed/unopened condition. The Index condition is for trend data only — no quantities are tracked.<br><br><strong>Flavor names:</strong> Searching a flavor name returns only those specific art versions (unless disabled in preferences). This does not work for complex multi-filter queries.<br><br><strong>Feedback:</strong> Report issues in the #feedback channel on the BAN Discord with a URL or screenshot. Some errors originate from upstream providers.',
                table: [],
                examples: [
                    { query: 'ratio>50 r:rare', desc: 'High-demand rares on buylists' },
                    { query: 'is:reserved price>50', desc: 'Expensive reserved list cards' },
                    { query: 'on:hotlist sort:buylist', desc: 'Hot list sorted by buylist value' }
                ]
            }
        }

    ]
};

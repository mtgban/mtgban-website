/* Guide Data - Shared Content Registry for the command palette and /guide page. */
window.__BAN_GUIDE = {
    sections: [

        // Overview
        {
            id: 'welcome',
            category: 'Overview',
            title: 'Welcome',
            icon: 'sparkles',
            summary: 'What MTGBAN is and where to find things',
            snippets: [],
            keywords: ['welcome', 'intro', 'overview', 'start', 'getting started', 'about', 'mtgban', 'ban'],
            content: {
                description: '<p>MTG<span class="ban">BAN</span> aggregates retail and buylist prices for Magic: The Gathering singles and sealed products across dozens of vendors. Everything on the site is built around two things: a flexible search syntax, and a keyboard-driven command palette that composes that syntax for you.</p><p>The three things you can reach from anywhere:</p><ul><li><strong>Search</strong> - find prices for a card or sealed product, filter by set, rarity, finish, condition, store, region, or price thresholds. Results split into retail and buylist, with condition breakdowns and index references from aggregators like TCGplayer.</li><li><strong>The Command Palette</strong> - <kbd>Ctrl+K</kbd> / <kbd>Cmd+K</kbd> from any page (or <kbd>/</kbd> when no input is focused) opens a single surface for searching cards, composing filter queries with guided chips, jumping to pages, recalling saved commands, browsing sealed products, and uploading collections.</li><li><strong>Tools</strong> - Newspaper for daily market movement, Sleepers for undervalued cards, Arbitrage for retail/buylist gaps, and Upload &amp; Optimize for splitting a collection across buylists.</li></ul><p>The rest of this guide is organized by tab:</p><ul><li><strong>Overview</strong> (you are here) - the palette at a glance, then a tour of the tools available on your account, then power-user tips.</li><li><strong>Command Palette</strong> - chips, modes, multi-stage navigation, saved commands, walkthroughs, and the full keyboard cheatsheet.</li><li><strong>Syntax</strong> - reference for every search prefix.</li><li><strong>F.A.Q.</strong> - common questions.</li></ul>',
                table: [],
                examples: []
            }
        },

        {
            id: 'palette-modes',
            category: 'Overview',
            title: 'The Command Palette at a Glance',
            icon: 'layout-grid',
            summary: 'Six modes for navigating, searching, and acting without leaving the keyboard',
            snippets: ['Ctrl+K', '>', '?', '*', '<', '$', '+'],
            keywords: ['palette', 'modes', 'shortcuts', 'overview', 'pages', 'help', 'saved', 'recent', 'sealed', 'upload', 'tiles'],
            content: {
                description: '<p>Press <kbd>Ctrl+K</kbd> / <kbd>Cmd+K</kbd> from any page (or <kbd>/</kbd> when no input is focused) to open the palette. The default view shows six shortcut tiles, each backed by a single-character prefix you can type directly into the input. Type a card name with no prefix to search; everything else is one keystroke away.</p><p>The palette also supports guided filter chips - type a prefix like <code>s:</code> or <code>r:</code> and the dropdown shows matching options. <kbd>Tab</kbd> locks the highlighted option as a chip; chain chips to compose complex queries. When a card chip is locked first, subsequent filter dropdowns narrow to what exists for that card. For the full reference, see the <strong>Command Palette</strong> tab.</p>',
                table: [
                    { value: '>',  short: 'Pages - navigate to a page or a specific sub-view (Newspaper Archive, Sleepers Bulk, Arbitrage with filter presets, etc.)' },
                    { value: '?',  short: 'Help & syntax - look up a syntax prefix; Enter copies the snippet, Shift+Enter opens the guide section' },
                    { value: '*',  short: 'Saved - browse and run your saved searches; Shift+Enter restores chips for editing' },
                    { value: '<',  short: 'Recent - recall your recent searches' },
                    { value: '$',  short: 'Sealed - search sealed products; Enter for prices, Shift+Enter for contents, Ctrl+Enter to simulate a pack pull' },
                    { value: '+',  short: 'Upload - submit a Sheets/Moxfield/TCG URL, pick a CSV/XLS file, or push current page results to the Uploader' }
                ],
                examples: [
                    { query: 'Lightning Bolt', desc: 'Just type a card name - Enter to search' },
                    { query: 'Birds of Paradise + Tab + s: + Tab', desc: 'Lock the card as a chip; the set dropdown narrows to its printings', palette: true },
                    { query: '>arbit + Tab + "Yield+" + Tab', desc: 'Compose an Arbitrage URL with filter presets', palette: true },
                    { query: '? rarity', desc: 'Inline syntax help - Enter copies the snippet', palette: true },
                    { query: '$Modern Horizons 3 Bundle + Shift+Enter', desc: 'Jump straight to the contents of a sealed product', palette: true },
                    { query: '+https://docs.google.com/spreadsheets/d/...', desc: 'Submit a Google Sheets collection to the Uploader', palette: true }
                ]
            }
        },
        // Command Palette
        {
            id: 'palette',
            category: 'Command Palette',
            title: 'Getting Started',
            icon: 'terminal',
            summary: 'Open the command palette with Ctrl+K / Cmd+K or / when no input is focused',
            snippets: ['Ctrl+K', 'Cmd+K', '?', '>'],
            keywords: ['palette', 'keyboard', 'shortcut', 'command', 'help', 'search', 'open', 'ctrl k', 'cmd k', 'slash', 'modes', 'chips', 'filter builder'],
            content: {
                description: '<p>The command palette provides fast keyboard-driven access to search syntax help, site navigation, and smart filter composition. Open it with <code>Ctrl+K</code> (Windows/Linux) or <code>Cmd+K</code> (Mac), or press <code>/</code> when no input field is focused.</p><p><strong>Modes</strong> (typed as prefixes into the palette input):</p><ul><li><code>?</code> - inline syntax help</li><li><code>&gt;</code> - navigate to a page or page view</li><li><code>saved:</code> - recall a saved search command</li><li><code>$</code> - sealed product mode (search + actions on a picked product)</li><li><code>+</code> - upload mode (URL, file picker, or current results) - when permitted</li></ul><p>Press <kbd>Shift+Delete</kbd> on a highlighted recent search or saved command to remove it instantly.</p><p>For filter composition with guided autocomplete, see <strong>Filter Builder</strong>. For the full keyboard reference, see <strong>Cheatsheet</strong>.</p>',
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
                description: '<p>The palette supports all search syntax prefixes as guided filter builders. Type a prefix and the dropdown shows matching options.</p><p>Locking a second chip with the same prefix merges it into the first: <code>s:MKM</code> followed by <code>s:LEA</code> becomes <code>s:MKM,LEA</code>. This applies to prefixes that accept multiple values - sets, rarities, colors, types, stores, tags.</p><p><strong>Card-aware narrowing:</strong> when a card chip is present, subsequent filter dropdowns narrow their options to what exists for that card. With a "Birds of Paradise" chip, <code>s:</code> only shows sets that card was printed in, and <code>c:</code> only shows green color combinations.</p>',
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
                    { value: 'on:', short: 'Special lists (hotlist, ckp90, tcgsyp, newspaper)' }
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
                description: '<p>The <code>&gt;</code> navigation mode supports page sub-views. After typing <code>&gt;</code> and a page name, press <kbd>Tab</kbd> to lock that page as a chip - the dropdown then shows that page\'s specific views (Newspaper: Spike Score, Buylist Levels, Archive; Sleepers: Bulk, Reprint, Mismatch, Gap, Hotlist; Arbitrage: filter presets and sort orders).</p><p>For Arbitrage pages, you can lock multiple filter chips in sequence - each Tab adds another filter to the composed URL. Press Enter on a sub-view to navigate, or Enter with only a parent chip to go to the page\'s base URL.</p>',
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
                description: '<p>Any search query can be saved as a named command. Press <kbd>Ctrl+S</kbd> / <kbd>Cmd+S</kbd> while the palette is open, or select <strong>Save Current Search</strong> from the palette on a search results page. You\'ll be prompted to name the command.</p><p>Saved commands appear in the palette default view and can be filtered with the <code>saved:</code> prefix.</p><p><strong>Editing:</strong> <kbd>Enter</kbd> runs a saved command directly. <kbd>Shift+Enter</kbd> restores its chips into the palette input so you can modify and re-run.</p><p><strong>Deleting:</strong> highlight a saved command and press <kbd>Shift+Delete</kbd> to remove it instantly (no confirmation). You can also hover and click the trash icon for a confirmed deletion.</p>',
                table: [
                    { value: 'Save Current Search', short: 'Palette command (appears on search results pages)' },
                    { value: 'Ctrl+S / Cmd+S', short: 'Save the current page search as a command (while palette is open)' },
                    { value: 'saved:', short: 'Browse saved commands in palette' },
                    { value: 'Enter on saved', short: 'Execute immediately' },
                    { value: 'Shift+Enter on saved', short: 'Restore chips for editing' },
                    { value: 'Shift+Delete on saved', short: 'Delete without confirmation' }
                ],
                examples: [
                    { query: 'saved:fetchlands', desc: 'Run the "fetchlands" saved search' },
                    { query: 'saved:', desc: 'Browse all saved commands' }
                ]
            }
        },

        {
            id: 'sealed-mode',
            category: 'Command Palette',
            title: 'Sealed Mode',
            icon: 'package',
            summary: 'Search sealed products and open their contents, prices, or simulated pack pulls.',
            snippets: ['$', '$Booster Box', 'Shift+Enter contents', 'Ctrl+Enter unpack'],
            keywords: ['sealed', 'product', 'booster', 'pack', 'contents', 'unpack', 'pack pull', 'sealed mode', 'box', 'bundle'],
            content: {
                description: '<p>Type <code>$</code> as the first character to enter <strong>Sealed mode</strong>. The autocomplete dropdown switches to the sealed-product dataset (booster boxes, bundles, packs, decks, cases, displays). Matching is <strong>prefix-only on the full product name</strong> - type the start of the actual name (e.g. <code>$Modern Horizons 3</code>), not a set code (<code>$MH3</code> will not match).</p><p>For any highlighted product the palette offers three actions:</p><ul><li><kbd>Enter</kbd> - search the sealed page for that product (price grid).</li><li><kbd>Shift+Enter</kbd> - <strong>View Contents</strong> - displays the cards inside the product.</li><li><kbd>Ctrl+Enter</kbd> - <strong>Pack Pull</strong> - simulates opening the product (when supported by the data).</li></ul><p><strong>Tab</strong> locks the highlighted product as a chip; the dropdown then morphs into a 3-row action menu where the same actions are reachable via arrow keys + Enter for users who prefer the menu over the modifier keys. Pack Pull is hidden if the product has no picks data.</p><p>If your typed query matches no products, <kbd>Enter</kbd> falls back to a generic <code>/sealed?q=&lt;text&gt;</code> search.</p>',
                table: [
                    { value: '$',                  short: 'Enter sealed mode (autocomplete switches to sealed products)' },
                    { value: 'Enter',              short: 'Search prices for the highlighted product' },
                    { value: 'Shift+Enter',        short: 'View contents (cards inside)' },
                    { value: 'Ctrl+Enter',         short: 'Pack Pull (simulated open) - hidden when unsupported' },
                    { value: 'Tab',                short: 'Lock product as chip and show the action menu' },
                    { value: 'Enter on no match',  short: 'Falls back to generic sealed search of typed text' }
                ],
                examples: [
                    { query: '$Phyrexia All Will Be One Prerelease Pack',  desc: 'Find a specific product by full-name prefix', palette: true },
                    { query: '$Modern Horizons 3 + arrow + Tab',           desc: 'Browse MH3 products, Tab to lock, then pick an action', palette: true },
                    { query: '$Murders at Karlov Manor Bundle + Shift+Enter', desc: 'Jump straight to the cards inside the bundle', palette: true },
                    { query: '$Phyrexia All Will Be One Prerelease Pack + Ctrl+Enter', desc: 'Simulate opening a prerelease pack', palette: true }
                ]
            }
        },

        {
            id: 'upload-mode',
            category: 'Command Palette',
            title: 'Upload Mode',
            icon: 'upload',
            summary: 'Send URLs, files, or current results to the Uploader without leaving the palette.',
            snippets: ['+', '+https://docs.google.com/...', '+ Browse for file...', '+ Send results'],
            keywords: ['upload', 'uploader', 'url', 'file', 'csv', 'xls', 'xlsx', 'sheets', 'moxfield', 'tcgplayer', 'send', 'hashes', 'collection'],
            requiresNav: 'Upload',
            content: {
                description: '<p>Type <code>+</code> as the first character to enter <strong>Upload mode</strong> (available when your tier includes the Uploader). The dropdown adapts to what is available:</p><ul><li><strong>Pasted URL</strong> - any input matching <code>store.tcgplayer.com</code>, <code>moxfield.com</code>, or <code>docs.google.com</code> shows an "Upload from..." row identifying the source.</li><li><strong>Browse for file...</strong> - always present; opens the native file picker for CSV / XLS / XLSX.</li><li><strong>Send N results to Uploader</strong> - shown on any page with row hashes (search and contents results); posts the visible hashes to the Uploader.</li></ul><p>All paths submit to <code>/upload</code> as a POST. Your saved upload preferences (mode, store list, optimizer settings) ride along automatically as cookies, so the result page reflects whatever you last configured at <code>/upload</code>.</p><p>Unsupported URL hosts render an error row that ignores Enter; pick one of the supported sources or use the file picker.</p>',
                table: [
                    { value: '+',                                    short: 'Enter upload mode (when tier permits)' },
                    { value: '+<URL>',                               short: 'Submit a Sheets / Moxfield / TCGplayer URL' },
                    { value: 'Browse for file...',                   short: 'Open native file picker (CSV/XLS/XLSX)' },
                    { value: 'Send N results to Uploader',           short: 'Shown on results pages; posts row hashes to /upload' },
                    { value: 'Cookies (mode, stores, optimizer)',    short: 'Honored from your last /upload session' }
                ],
                examples: [
                    { query: '+https://docs.google.com/spreadsheets/d/...',         desc: 'Submit a Google Sheets collection', palette: true },
                    { query: '+https://www.moxfield.com/decks/abc',                  desc: 'Submit a Moxfield deck', palette: true },
                    { query: 'On /search?q=lightning bolt -> + -> Send results',     desc: 'Push current results to Uploader', palette: true },
                    { query: '+ -> Browse for file... -> pick collection.csv',       desc: 'Local file path', palette: true }
                ]
            }
        },

        {
            id: 'palette-walkthroughs',
            category: 'Command Palette',
            title: 'Walkthroughs',
            icon: 'footprints',
            summary: 'Common workflows with exact keystrokes - follow along to get comfortable',
            snippets: [],
            keywords: ['walkthrough', 'tutorial', 'example', 'workflow', 'how to', 'scenario', 'step by step'],
            content: {
                description: '<p>End-to-end keystroke sequences. Follow along in a live palette to build muscle memory.</p><div class="guide-walkthrough"><h4>1. Find all foil printings of a card</h4><ol><li><kbd>Ctrl+K</kbd> to open the palette.</li><li>Type <code>Birds of Paradise</code>. The card name appears in the dropdown.</li><li><kbd>Tab</kbd> - Birds of Paradise becomes a chip.</li><li>Type <code>f:foil</code>. The Finish dropdown appears with foil highlighted.</li><li><kbd>Tab</kbd> - <code>f:foil</code> becomes a chip.</li><li><kbd>Enter</kbd> - navigates to search with the composed query.</li></ol></div><div class="guide-walkthrough"><h4>2. Jump to Arbitrage with profit filters</h4><ol><li><kbd>Ctrl+K</kbd>.</li><li>Type <code>&gt;arb</code>. Arbitrage appears.</li><li><kbd>Tab</kbd> - Arbitrage chip locks; the dropdown now shows filter presets and sort options.</li><li>Type <code>yield</code> to narrow to "only Yield+".</li><li><kbd>Tab</kbd> - filter chip added.</li><li>Type <code>bucks</code>, <kbd>Tab</kbd> - second filter added.</li><li>Type <code>sort</code>, <kbd>Tab</kbd> on "Spread %" - sort chip added.</li><li><kbd>Enter</kbd> - navigates to <code>/arbit?nolow=true&amp;nopenny=true&amp;sort=spread</code>.</li></ol></div><div class="guide-walkthrough"><h4>3. Save a complex query for later</h4><ol><li>Build a query with chips: a card plus filters (as in walkthrough 1).</li><li>Press <kbd>Ctrl+S</kbd> while the palette is open.</li><li>Enter a short name and <kbd>Enter</kbd> - the command is saved.</li><li>Later, open the palette and type <code>saved:</code> to find your command.</li><li><kbd>Enter</kbd> runs it; <kbd>Shift+Enter</kbd> restores its chips for editing.</li></ol></div><div class="guide-walkthrough"><h4>4. Narrow a search with card-aware filters</h4><ol><li><kbd>Ctrl+K</kbd>.</li><li>Type <code>Lightning Bolt</code>, <kbd>Tab</kbd> - Lightning Bolt chip locks.</li><li>Type <code>s:</code> - the sets dropdown shows only sets Lightning Bolt has been printed in.</li><li>Type <code>Alpha</code>, <kbd>Tab</kbd> - picks Limited Edition Alpha, chip locks as <code>s:Alpha</code>.</li><li>Type <code>f:foil</code>, <kbd>Tab</kbd>, <kbd>Enter</kbd> - composes the final query.</li></ol></div><div class="guide-walkthrough"><h4>5. Look up syntax while building a query</h4><ol><li>In any context, type <code>?</code> followed by a keyword - e.g. <code>?rarity</code> or <code>? foil</code>.</li><li>The dropdown shows a syntax snippet - <kbd>Enter</kbd> copies it to your clipboard.</li><li><kbd>Shift+Enter</kbd> jumps to the full section of this guide.</li></ol></div><div class="guide-walkthrough"><h4>6. Browse the contents of a booster box</h4><ol><li><kbd>Ctrl+K</kbd> to open the palette.</li><li>Type <code>$bundle lci</code>. Sealed product matches appear under a "Sealed" header.</li><li>Arrow to the desired product.</li><li><kbd>Shift+Enter</kbd> - navigates to <code>/sealed?q=contents:Bundle...</code> showing the cards inside.</li></ol></div><div class="guide-walkthrough"><h4>7. Push a search result set to Upload</h4><ol><li>On any search results page (e.g. <code>/search?q=lightning bolt</code>), <kbd>Ctrl+K</kbd>.</li><li>Type <code>+</code>. The dropdown shows "Send N results to Uploader" alongside file picker and URL options.</li><li>Arrow to the "Send N results" row.</li><li><kbd>Enter</kbd> - the page POSTs to <code>/upload</code> with the row hashes; you land on the upload results page using your saved store and mode preferences.</li></ol></div>',
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
                    { value: 'Tab (on dropdown result)', short: 'Lock as chip' },
                    { value: 'Tab (on active chip)', short: 'Edit - re-opens dropdown' },
                    { value: '←  /  →', short: 'Navigate between chips' },
                    { value: 'Backspace / Delete', short: 'Remove active chip' },
                    { value: '↑  /  ↓', short: 'Navigate dropdown' },
                    { value: 'Enter', short: 'Execute composed query / navigate / copy snippet' },
                    { value: 'Shift+Enter', short: 'Alt action (see context)' },
                    { value: 'Shift+Delete', short: 'Remove active recent search or saved command' },
                    { value: 'Ctrl+S / Cmd+S', short: 'Save current query as a named command' },
                    { value: '?  (or help: / syntax:)', short: 'Help mode - inline syntax lookup' },
                    { value: '>', short: 'Navigation mode - pages and sub-views' },
                    { value: 'saved:', short: 'Saved mode - browse saved commands' },
                    { value: '$',                        short: 'Sealed mode - product search + actions' },
                    { value: '+',                        short: 'Upload mode - URL / file / page results (when permitted)' },
                    { value: 'Enter on sealed result',   short: 'Search prices' },
                    { value: 'Shift+Enter on sealed',    short: 'View contents (cards inside)' },
                    { value: 'Ctrl+Enter on sealed',     short: 'Pack Pull (when available)' },
                    { value: 'Tab on sealed result',     short: 'Lock as chip; show action menu' },
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
                    { value: 'on:', short: 'Special lists (hotlist, ckp90, tcgsyp, newspaper)' }
                ],
                examples: []
            }
        },

        // Search Syntax
        {
            id: 'basic-syntax',
            category: 'Search Syntax',
            title: 'Basic Syntax',
            icon: 'text-cursor-input',
            summary: 'Card names, Pricefall bot notation, suffix shortcuts (* foil, & nonfoil, ~ etched).',
            snippets: ['name|set|number|finish', 'Sol Ring*', 'Sheoldred (Showcase)', 'r:rare,mythic'],
            keywords: ['basic', 'name', 'pricefall', 'notation', 'suffix', 'foil', 'nonfoil', 'etched', 'altfoil', 'finish', 'comma', 'multiple', 'syntax', 'search'],
            content: {
                description: '<p>Start typing a card name and an autocomplete dropdown will appear. You can also use the Pricefall bot notation: <code>name[|code[|number[|finish]]]</code>.</p><p>Human-readable tags are also supported - for example, appending <code>(Extended Art)</code> or <code>(Showcase)</code> to a card name will filter to those versions (does not work in regexp mode).</p><p>Use commas to supply multiple values for any filter. Finish suffixes can be appended directly to any search term:</p>',
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
                description: '<p>Filter cards by edition using the Scryfall notation <code>s:CODE</code> or the full edition name in quotes: <code>s:"Aether Revolt"</code>.</p><p>Regular expressions are supported with <code>se:REGEXP</code>. For compatibility, <code>e:CODE</code> (exact match) and <code>ee:REGEXP</code> (regexp) are also accepted.</p>',
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
                description: '<p>Filter by collector number using <code>cn:NUMBER</code>. For plain numbers you can use comparison operators <code>cn&gt;NUMBER</code> and <code>cn&lt;NUMBER</code>, or a range <code>cn:NUMBER-NUMBER</code>.</p><p>Regular expressions are supported via <code>cne:REGEXP</code>.</p><p>To target a specific set while leaving other results untouched, prepend the set code: <code>cn:CODE:NUMBER</code>.</p>',
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
                description: '<p>Filter by finish with <code>f:VALUE</code> using the values below, or append a suffix character directly to any search term.</p>',
                table: [
                    { value: 'foil / f', short: 'Foil' },
                    { value: 'nonfoil / nf / r', short: 'Non-foil' },
                    { value: 'etched / e', short: 'Etched foil' },
                    { value: 'is:altfoil', short: 'Any special foil variant (Galaxy, Surge, Ripple, etc.)' },
                    { value: '*', short: 'Foil only (query suffix)' },
                    { value: '&', short: 'Non-foil only (query suffix)' },
                    { value: '~', short: 'Etched only (query suffix)' },
                    { value: '`', short: 'Alt-foil only, e.g. surge/ripple/galaxy (query suffix)' }
                ],
                examples: [
                    { query: 'f:foil', desc: 'Foil versions only' },
                    { query: 'Forest is:altfoil', desc: 'Special-foil Forests (a separate filter, not f:altfoil)' },
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
            keywords: ['color', 'colour', 'identity', 'ci', 'c:', 'WUBRG', 'white', 'blue', 'black', 'red', 'green', 'colorless', 'multicolor', 'guild', 'shard', 'wedge', 'college', 'azorius', 'dimir', 'rakdos', 'gruul', 'selesnya', 'orzhov', 'izzet', 'golgari', 'boros', 'simic', 'bant', 'esper', 'grixis', 'jund', 'naya', 'abzan', 'jeskai', 'sultai', 'mardu', 'temur', 'silverquill', 'prismari', 'witherbloom', 'lorehold', 'quandrix', 'chaos', 'aggression', 'altruism', 'growth', 'artifice'],
            content: {
                description: '<p>Filter by card color with <code>c:COLOR</code> or by color identity with <code>ci:COLOR</code> (alias <code>identity:</code>). Combine WUBRG letters directly (<code>c:rg</code>), or use any color name or named group below. Options with more than one accepted spelling list every alias together.</p>',
                table: [
                    { value: 'white / w', short: 'White (W)' },
                    { value: 'blue / u', short: 'Blue (U)' },
                    { value: 'black / b', short: 'Black (B)' },
                    { value: 'red / r', short: 'Red (R)' },
                    { value: 'green / g', short: 'Green (G)' },
                    { value: 'colorless / c', short: 'No colors' },
                    { value: 'multicolor / multi / m', short: 'Two or more colors (WUBRG)' },
                    { value: 'azorius', short: 'White-Blue (WU)' },
                    { value: 'dimir', short: 'Blue-Black (UB)' },
                    { value: 'rakdos', short: 'Black-Red (BR)' },
                    { value: 'gruul', short: 'Red-Green (RG)' },
                    { value: 'selesnya', short: 'Green-White (GW)' },
                    { value: 'orzhov', short: 'White-Black (WB)' },
                    { value: 'izzet', short: 'Blue-Red (UR)' },
                    { value: 'golgari', short: 'Black-Green (BG)' },
                    { value: 'boros', short: 'Red-White (RW)' },
                    { value: 'simic', short: 'Green-Blue (GU)' },
                    { value: 'lorehold', short: 'Red-White (RW), Strixhaven' },
                    { value: 'prismari', short: 'Blue-Red (UR), Strixhaven' },
                    { value: 'quandrix', short: 'Green-Blue (GU), Strixhaven' },
                    { value: 'silverquill', short: 'White-Black (WB), Strixhaven' },
                    { value: 'witherbloom', short: 'Black-Green (BG), Strixhaven' },
                    { value: 'bant', short: 'Green-White-Blue (GWU)' },
                    { value: 'esper', short: 'White-Blue-Black (WUB)' },
                    { value: 'grixis', short: 'Blue-Black-Red (UBR)' },
                    { value: 'jund', short: 'Black-Red-Green (BRG)' },
                    { value: 'naya', short: 'Red-Green-White (RGW)' },
                    { value: 'abzan', short: 'White-Black-Green (WBG)' },
                    { value: 'jeskai', short: 'Blue-Red-White (URW)' },
                    { value: 'sultai', short: 'Black-Green-Blue (BGU)' },
                    { value: 'mardu', short: 'Red-White-Black (RWB)' },
                    { value: 'temur', short: 'Green-Blue-Red (GUR)' },
                    { value: 'chaos', short: 'Four-color, no white (UBRG)' },
                    { value: 'aggression', short: 'Four-color, no blue (WBRG)' },
                    { value: 'altruism', short: 'Four-color, no black (WURG)' },
                    { value: 'growth', short: 'Four-color, no red (WUBG)' },
                    { value: 'artifice', short: 'Four-color, no green (WUBR)' }
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
            id: 'format',
            category: 'Search Syntax',
            title: 'Format',
            icon: 'gavel',
            summary: 'Filter by format legality (format:standard, format:modern).',
            snippets: ['format:standard', 'format:modern', 'format:commander'],
            keywords: ['format', 'legal', 'legality', 'banned', 'restricted', 'standard', 'pioneer', 'modern', 'legacy', 'vintage', 'pauper', 'commander', 'edh', 'brawl', 'oathbreaker', 'pdh'],
            content: {
                description: 'Filter to cards that are legal (or restricted) in a given format with <code>format:NAME</code> (alias <code>legal:NAME</code>). Banned and not-legal cards are excluded; negate with <code>-format:NAME</code>. Combine formats with commas to match any of them.',
                table: [
                    { value: 'standard', short: 'Standard' },
                    { value: 'pioneer', short: 'Pioneer' },
                    { value: 'modern', short: 'Modern' },
                    { value: 'legacy', short: 'Legacy' },
                    { value: 'vintage', short: 'Vintage' },
                    { value: 'pauper', short: 'Pauper' },
                    { value: 'commander', short: 'Commander (alias: edh)' },
                    { value: 'oathbreaker', short: 'Oathbreaker' },
                    { value: 'brawl', short: 'Brawl' },
                    { value: 'standardbrawl', short: 'Standard Brawl' },
                    { value: 'historic', short: 'Historic' },
                    { value: 'timeless', short: 'Timeless' },
                    { value: 'alchemy', short: 'Alchemy' },
                    { value: 'explorer', short: 'Explorer' },
                    { value: 'gladiator', short: 'Gladiator' },
                    { value: 'penny', short: 'Penny Dreadful' },
                    { value: 'duel', short: 'Duel Commander' },
                    { value: 'premodern', short: 'Premodern' },
                    { value: 'oldschool', short: 'Old School' },
                    { value: 'predh', short: 'PreDH' },
                    { value: 'paupercommander', short: 'Pauper Commander (alias: pdh)' },
                    { value: 'future', short: 'Future Standard' }
                ],
                examples: [
                    { query: 'format:standard', desc: 'Cards legal in Standard' },
                    { query: 'format:modern r:mythic', desc: 'Modern-legal mythics' },
                    { query: 'format:commander', desc: 'Commander-legal cards (alias: format:edh)' },
                    { query: 'format:legacy,vintage', desc: 'Legal in Legacy or Vintage' }
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
                description: 'Filter by rarity with <code>r:RARITY</code>. The first letter works as shorthand. Comparison operators <code>r&gt;RARITY</code> and <code>r&lt;RARITY</code> are also supported.',
                table: [
                    { value: 'mythic / m', short: 'Mythic rarity' },
                    { value: 'rare / r', short: 'Rare rarity' },
                    { value: 'uncommon / u', short: 'Uncommon rarity' },
                    { value: 'common / c', short: 'Common rarity' },
                    { value: 'special / s', short: 'Special rarity' },
                    { value: 'token / t', short: 'Token rarity' },
                    { value: 'oversize / o', short: 'Oversized rarity' }
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
                description: 'Filter by card type with <code>t:VALUE</code>, accepting any valid supertype, type, or subtype. The same option also works for sealed products - you can search by category (booster, box, deck) or subtype (draft, collector, intro), or any fragment of the product name.',
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
                description: '<p>Filter by card properties with <code>is:VALUE</code> or exclude with <code>not:VALUE</code> (equivalent to <code>-is:VALUE</code>). Options with more than one accepted spelling list every alias together.</p>',
                table: [
                    { value: 'reserved', short: 'On the Reserved List' },
                    { value: 'token', short: 'Token card' },
                    { value: 'oversize / oversized', short: 'Oversized card' },
                    { value: 'funny', short: 'Un-set / funny card' },
                    { value: 'wcd / gold', short: 'Gold-bordered World Championship card' },
                    { value: 'commander', short: 'Commander deck card (from a sealed product)' },
                    { value: 'productless', short: 'Not found in any tracked product' },
                    { value: 'gamechanger / gc', short: 'Game Changer (Commander bracket)' },
                    { value: 'ampersand', short: 'Forgotten Realms ampersand (&) treatment' },
                    { value: 'fullart / fa', short: 'Full-art card' },
                    { value: 'extendedart / ea', short: 'Extended-art frame' },
                    { value: 'showcase / sc / sh', short: 'Showcase frame' },
                    { value: 'borderless / bd / bl', short: 'Borderless frame' },
                    { value: 'reskin', short: 'Reskinned card (has a flavor name)' },
                    { value: 'retro / old', short: 'Retro frame (1993 or 1997)' },
                    { value: 'future', short: 'Future frame' },
                    { value: 'foil', short: 'Foil (includes etched)' },
                    { value: 'nonfoil', short: 'Non-foil' },
                    { value: 'altfoil', short: 'Any special foil treatment (see Promos & Variants)' },
                    { value: 'japanese / jpn / jp / ja', short: 'Japanese printing' },
                    { value: 'phyrexian / ph', short: 'Phyrexian printing' }
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
            summary: 'Filter promos and special foil treatments: is:promo, is:prerelease, is:buyabox, is:surge, is:serialized.',
            snippets: ['is:promo', 'is:prerelease', 'is:buyabox', 'is:serialized', 'is:altfoil', 'is:surge'],
            keywords: ['promo', 'prerelease', 'buyabox', 'buy a box', 'serialized', 'variant', 'stamped', 'convention', 'fnm', 'wpn', 'gameday', 'judge', 'arena', 'release', 'bundle', 'altfoil', 'foil', 'surge', 'galaxy', 'ripple', 'rainbow', 'halo', 'mana', 'neon', 'gilded', 'textured', 'oilslick', 'confetti', 'fracture', 'embossed', 'godzilla', 'dracula', 'concept', 'poster', 'glossy', 'storechampionship', 'draftweekend', 'intropack', 'starterdeck'],
            content: {
                description: '<p>Filter promo cards and special foil treatments with <code>is:VALUE</code>. Use <code>is:promo</code> to match any promo type, or one of the specific tags below for targeted filtering. Options with more than one accepted spelling list every alias together.</p><p><code>is:altfoil</code> is a convenience union that matches <em>any</em> special foil treatment (surge, ripple, galaxy, etc.). The list tracks the live card data, so newer treatments work as soon as the data includes them even if not listed here.</p>',
                table: [
                    { value: 'promo', short: 'Any promo (matches every type below)' },
                    { value: 'altfoil', short: 'Any special foil treatment (union of the foil tags)' },
                    { value: 'prerelease / pre', short: 'Prerelease-stamped promo' },
                    { value: 'promopack / pp', short: 'Promo Pack stamped' },
                    { value: 'buyabox / bab / buy-a-box', short: 'Buy-a-Box promo' },
                    { value: 'bundle', short: 'Bundle promo' },
                    { value: 'release', short: 'Release / launch party promo' },
                    { value: 'draftweekend', short: 'Draft Weekend promo' },
                    { value: 'gameday', short: 'Game Day promo' },
                    { value: 'fnm', short: 'Friday Night Magic promo' },
                    { value: 'judgegift / judge', short: 'Judge Gift program' },
                    { value: 'arenaleague / arena', short: 'Arena League promo' },
                    { value: 'playerrewards / rewards / mpr', short: 'Magic Player Rewards' },
                    { value: 'wizardsplaynetwork / wpn', short: 'WPN / gateway promo' },
                    { value: 'storechampionship', short: 'Store Championship promo' },
                    { value: 'convention', short: 'Convention promo' },
                    { value: 'tourney', short: 'Tournament promo' },
                    { value: 'intropack', short: 'Intro Pack promo' },
                    { value: 'starterdeck', short: 'Starter deck promo' },
                    { value: 'glossy', short: 'Glossy promo' },
                    { value: 'serialized', short: 'Serialized numbered card' },
                    { value: 'concept', short: 'Concept-art card' },
                    { value: 'poster', short: 'Poster-art treatment' },
                    { value: 'scroll', short: 'Scroll treatment' },
                    { value: 'schinesealtart', short: 'Simplified Chinese alternate art' },
                    { value: 'draculaseries', short: 'Dracula series (Crimson Vow)' },
                    { value: 'godzillaseries', short: 'Godzilla series (Ikoria)' },
                    { value: 'ruderiders', short: 'Rude Riders series' },
                    { value: 'boosterfun / bf / v', short: 'Booster Fun alternate treatment' },
                    { value: 'surgefoil / surge', short: 'Surge foil' },
                    { value: 'galaxyfoil / galaxy', short: 'Galaxy foil' },
                    { value: 'ripplefoil / ripple', short: 'Ripple foil' },
                    { value: 'rainbowfoil / rainbow', short: 'Rainbow foil' },
                    { value: 'raisedfoil / raised', short: 'Raised foil' },
                    { value: 'halofoil / halo', short: 'Halo foil' },
                    { value: 'manafoil / mana', short: 'Mana foil' },
                    { value: 'silverfoil / silver', short: 'Silver foil' },
                    { value: 'fracturefoil / fracture', short: 'Fracture foil' },
                    { value: 'confettifoil / confetti', short: 'Confetti foil' },
                    { value: 'neonink / neon', short: 'Neon Ink foil' },
                    { value: 'gilded', short: 'Gilded foil' },
                    { value: 'textured', short: 'Textured foil' },
                    { value: 'oilslick', short: 'Oil Slick foil' },
                    { value: 'invisibleink', short: 'Invisible Ink foil' },
                    { value: 'doubleexposure', short: 'Double Exposure foil' },
                    { value: 'doublerainbow', short: 'Double Rainbow foil' },
                    { value: 'stepandcompleat', short: 'Step-and-Compleat foil' },
                    { value: 'embossed', short: 'Embossed foil (Forgotten Realms ampersand)' },
                    { value: 'thick / thicc / display', short: 'Thick display card' }
                ],
                examples: [
                    { query: 'is:prerelease', desc: 'Prerelease promos' },
                    { query: 'is:buyabox', desc: 'Buy-a-Box promos' },
                    { query: 'is:serialized', desc: 'Serialized numbered cards' },
                    { query: 'is:surge r:mythic', desc: 'Surge foil mythics' }
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
                description: '<p>Filter by retail price with <code>price&gt;VALUE</code> or <code>price&lt;VALUE</code>. Use <code>buy_price</code> to filter buylist prices. Filters can also reference a store\'s price - <code>price&gt;TCGLow</code> returns stores charging more than the TCG Low index for that card.</p><p>For cross-category comparisons: <code>arb_price</code> uses buylist price as a reference for retail results, and <code>rev_price</code> uses retail price as a reference for buylist results.</p><p><code>ratio&gt;VALUE</code> filters by buylist desirability percentage (max 64).</p>',
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
                description: '<p>Filter by seller or vendor with <code>store:shorthand</code>, <code>seller:shorthand</code> (retail), or <code>vendor:shorthand</code> (buylist). You can pass either a store\'s full name in quotes or its shorthand. These drop results where the store is absent. To show only that store, use <code>store:only:shorthand</code>. The complete, always-current list of every store shorthand is shown at the bottom of this section.</p><p>The <code>skip:</code> filter hides entire result categories. Note: store filters leave index results visible - use <code>skip:index</code> to hide them.</p>',
                table: [
                    { value: 'store:X', short: 'Include results from store X' },
                    { value: 'store:only:X', short: 'Show only results from store X' },
                    { value: 'seller:X', short: 'Retail-only store filter' },
                    { value: 'vendor:X', short: 'Buylist-only store filter' },
                    { value: 'region:us', short: 'US-based stores only' },
                    { value: 'region:eu', short: 'European stores only' },
                    { value: 'region:jp', short: 'Japanese stores only' },
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
                description: '<p>Change search matching behavior with <code>sm:VALUE</code>. The default mode is <code>exact</code> - only cards with that precise name are returned.</p><p>In <code>scryfall</code> mode, the query is forwarded to Scryfall. BAN card filters are disabled to avoid conflicts, but store and price filters still apply.</p>',
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
            snippets: ['on:hotlist', 'on:ckp90', 'on:tcgsyp', 'on:newspaper', 'on:mtgstocks'],
            keywords: ['list', 'on:', 'hotlist', 'ckp90', 'p90', 'card kingdom', 'tcgsyp', 'syp', 'newspaper', 'mtgstocks', 'stocks', 'spike', 'hot', 'curated', 'special', 'TCGplayer'],
            content: {
                description: 'Check if a card belongs to a curated list using <code>on:VALUE</code>:',
                table: [
                    { value: 'hotlist', short: 'Highest buylist prices over 3 months' },
                    { value: 'ckp90', short: "Card Kingdom's buylist is at or above its 90-day P90" },
                    { value: 'tcgsyp / syp', short: 'Present on the TCGplayer SYP list' },
                    { value: 'newspaper', short: 'Found in a Newspaper Spike score' },
                    { value: 'mtgstocks', short: 'Tracked by MTGStocks' }
                ],
                examples: [
                    { query: 'on:hotlist', desc: 'Cards on the buylist hot list' },
                    { query: 'on:ckp90', desc: 'Cards where CK pays at/above its P90 (the 👍 badge)' },
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
                description: '<p>Filter by card name to include or exclude specific cards from a query using <code>name:NAME</code>. Enclose names with spaces in quotes or parentheses. Prefix with <code>-</code> to exclude.</p><p>Regular expressions are supported with <code>namee:REGEXP</code>.</p><p>Filter by internal card ID with <code>id:VALUE</code>, supporting MTGBAN, MTGJSON, Scryfall, and TCGplayer product IDs.</p>',
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

        // Tools
        {
            id: 'feature-search',
            category: 'Tools',
            title: 'Search',
            icon: 'search',
            summary: 'Search prices across all stores for singles and sealed; historical charts, condition breakdowns, reprint finder.',
            snippets: [],
            keywords: ['search', 'price', 'retail', 'buylist', 'chart', 'history', 'affiliate', 'store', 'sealed', 'product', 'condition', 'index', 'reprint', 'finder'],
            content: {
                description: '<p>The main search page is the entry point for finding prices across every tracked store and vendor. It handles both single cards and sealed products, and accepts the full filter syntax documented in the Syntax tab.</p><p><strong>Results layout:</strong> retail prices and buylist offers are split into separate tables. Each card has condition breakdowns (NM/SP/MP/HP/PO), and index prices from aggregators like TCGplayer Market, TCG Low, and Card Kingdom appear alongside individual vendor prices for reference.</p><p><strong>Per-card actions:</strong></p><ul><li><strong>📊 chart icon</strong> - opens historical price data from major vendors</li><li><strong>📖 book icon</strong> - opens the reprint finder, listing every product containing any reprint of that card</li><li><strong>Buy links</strong> - vendor affiliate links that support BAN at no extra cost</li></ul><p>The command palette\'s default behavior (type a card name, press Enter) lands you here.</p>',
                table: [],
                examples: [
                    { query: 'Lightning Bolt s:lea', desc: 'Alpha Lightning Bolt prices' },
                    { query: 'r:mythic sort:retail skip:index', desc: 'Mythics by price, no index' },
                    { query: 't:booster s:blb', desc: 'Bloomburrow booster products' }
                ]
            }
        },

        {
            id: 'feature-sealed',
            category: 'Tools',
            requiresNav: 'Sealed',
            title: 'Sealed Products',
            icon: 'package',
            summary: 'Browse sealed products by category, search by name, or open contents and simulated pack pulls.',
            snippets: [],
            keywords: ['sealed', 'product', 'booster', 'bundle', 'box', 'deck', 'commander deck', 'expansion', 'reprint', 'draft', 'core set', 'boxed set', 'commander supplement', 'from the vault', 'starter', 'browse', 'category', 'surprise me'],
            content: {
                description: '<p>The Sealed page is a structured directory of every sealed product BAN tracks. The left sidebar groups products by category; the main area shows the selected category as a clickable grid with set symbols for orientation.</p><p>Three ways to find a product:</p><ul><li><strong>Browse by category</strong> - pick a category in the sidebar (Commander Decks, Expansions, Boxed Sets, etc.)</li><li><strong>Search</strong> - type into the product search input to filter by name across all categories</li><li><strong>Surprise Me</strong> - opens a random product</li></ul><p>Clicking a product takes you to its price grid (every vendor selling it, plus index references). From the command palette, <code>$&lt;product name&gt;</code> reaches the same destination and adds two shortcuts the page itself doesn\'t expose: <kbd>Shift+Enter</kbd> for the product\'s contents, <kbd>Ctrl+Enter</kbd> for a pack-pull simulation.</p>',
                table: [
                    { value: 'Commander Decks',       short: 'Preconstructed Commander products by set' },
                    { value: 'Expansions',            short: 'Standard-legal set boosters, bundles, and cases' },
                    { value: 'Reprint Sets',          short: 'Masters, Remastered, and other reprint releases' },
                    { value: 'Eternal',               short: 'Eternal-format-targeted products' },
                    { value: 'Draft Experiments',     short: 'Draft-focused experimental products' },
                    { value: 'Core Sets',             short: 'Core set boosters and ancillary products' },
                    { value: 'Boxed Sets',            short: 'Premium boxed releases' },
                    { value: 'Funny Sets',            short: 'Un-sets and Unfinity-style products' },
                    { value: 'Commander Supplements', short: 'Commander-format anthologies and supplements' },
                    { value: 'Deck Series',           short: 'Themed deck series releases' },
                    { value: 'From the Vault Sets',   short: 'From the Vault premium releases' },
                    { value: 'Standalone Game',       short: 'Self-contained game products' },
                    { value: 'Starter Sets',          short: 'New-player starter products' }
                ],
                examples: [
                    { query: '$Modern Horizons 3 Bundle', desc: 'Find a sealed product from the palette', palette: true },
                    { query: '$Phyrexia All Will Be One Prerelease Pack + Ctrl+Enter', desc: 'Simulate opening a prerelease pack', palette: true },
                    { query: 't:booster s:blb', desc: 'All booster products from Bloomburrow' }
                ]
            }
        },

        {
            id: 'feature-newspaper',
            category: 'Tools',
            requiresNav: 'Newspaper',
            title: 'Newspaper',
            icon: 'newspaper',
            summary: 'Daily snapshot of market movement - spike scores, vendor listings, and buylist offers.',
            snippets: [],
            keywords: ['newspaper', 'spike', 'score', 'buylist', 'change', 'trend', 'seller', 'count', 'SYP', 'archive', 'daily', 'movement', 'price change', 'vendor', 'listings', 'supply', 'demand', 'edition'],
            content: {
                description: '<p>The Newspaper is BAN\'s daily snapshot of meaningful market movement. Each issue is an "edition" - the Early Edition is the in-progress view of the current day, with the previous full day available on a delay.</p><p><strong>Six metric cards make up an issue:</strong></p><p><strong>Spike scores</strong> - cards whose prices have jumped recently:</p><ul><li><em>Top Singles by Combined Spike Score</em> - blends TCGplayer sales velocity with Card Kingdom buylist movement. The strongest signal of "something is happening" because two independent data sources agree.</li><li><em>Top Singles by Spike Score</em> - TCGplayer-only sales-velocity spikes. Useful for catching moves before they propagate.</li></ul><p><strong>Vendor listings (supply signals)</strong> - tracks how many sellers have a card in stock:</p><ul><li><em>Greatest Increase</em> - stock is piling up faster than it sells. <strong>Avoid these</strong> as buys.</li><li><em>Greatest Decrease</em> - stock is drying up. <strong>Seek these out</strong> as buys.</li></ul><p><strong>Buylist offers (demand signals)</strong> - tracks what vendors are willing to pay:</p><ul><li><em>Greatest Increase</em> - higher offers indicate higher sales rates for the vendor. Can be fleeting; not a sole-source signal unless you\'re dropshipping.</li><li><em>Greatest Decrease</em> - declining offers indicate the vendor is moving fewer copies. Same caveat applies.</li></ul><p>The <strong>Archive</strong> view (palette: <code>&gt;newspaper + Tab + Archive</code>) browses historical issues by date.</p>',
                table: [
                    { value: 'Early Edition',                           short: 'In-progress view of today\'s data' },
                    { value: 'Standard Edition',                        short: 'Previous full day' },
                    { value: 'Top Singles by Combined Spike Score',     short: 'TCG sales + CK buylist movement (strongest signal)' },
                    { value: 'Top Singles by Spike Score',              short: 'TCG sales velocity only (catches early moves)' },
                    { value: 'Greatest Increase in Vendor Listings',    short: 'Supply piling up - avoid as buys' },
                    { value: 'Greatest Decrease in Vendor Listings',    short: 'Supply drying up - seek out as buys' },
                    { value: 'Greatest Increase in Buylist Offer',      short: 'Demand rising - may be fleeting' },
                    { value: 'Greatest Decrease in Buylist Offer',      short: 'Demand falling - may be fleeting' },
                    { value: 'Archive',                                 short: 'Browse historical issues' }
                ],
                examples: [
                    { query: 'on:newspaper', desc: 'Cards currently in a Newspaper spike' },
                    { query: 'on:newspaper r:mythic', desc: 'Spiking mythics' },
                    { query: '>newspaper + Tab + "Archive"', desc: 'Jump to the Archive view', palette: true }
                ]
            }
        },

        {
            id: 'feature-screener',
            category: 'Tools',
            requiresNav: 'Screener',
            title: 'Screener',
            icon: 'sliders-horizontal',
            summary: 'Find cards whose price moved by a threshold you set - every filter is editable.',
            snippets: [],
            keywords: ['screener', 'movers', 'price change', 'percent', 'threshold', 'gainers', 'losers', 'trending', 'filter', 'tcglow', 'tcg low', 'window', 'floor', 'was', 'now', 'up', 'down', 'sealed', 'edition', 'per page'],
            content: {
                description: '<p>The Screener finds cards whose price has moved by a threshold you choose. Where the Newspaper is a fixed daily snapshot, every filter here is editable - so you can ask arbitrary questions like "TCGplayer Low $50 or more, up 20% or more over the last 30 days."</p><p><strong>How it works:</strong> pick a price <strong>metric</strong> and a <strong>window</strong>, choose whether you want cards moving <strong>up</strong>, <strong>down</strong>, or <strong>either</strong>, then set your floors and percent threshold. Results are every card matching all of it, sortable by current price, prior price, percent change, or dollar change.</p><p><strong>Two price floors:</strong> <em>Now $</em> filters on the current price; <em>Was $</em> filters on the price at the start of the window. They combine, so you can screen for cards that <em>were</em> $100+ and have since moved, regardless of where they sit now.</p><p>The <strong>Type</strong> toggle switches between singles, sealed products, or both. The <strong>Editions</strong> dropdown narrows to specific sets (checkboxes populated from the current results). Set <strong>Per page</strong> and press <strong>Apply</strong>; <strong>Reset</strong> returns everything to defaults.</p>',
                table: [
                    { value: 'Metric',                short: 'Which price to track (TCG Low/Market, CK/SCG/ABU/CSI buylist, Cardmarket, Sealed EV)' },
                    { value: 'Window',                short: 'Lookback period: 1, 7, 14, 30, or 90 days' },
                    { value: 'Type',                  short: 'Singles, Sealed, or Both' },
                    { value: 'Move',                  short: 'Up, Down, or Either direction' },
                    { value: 'Now $ / Was $',         short: 'Floor on the current price and/or the price at the start of the window' },
                    { value: 'Change (Min / Max %)',  short: 'Minimum move to qualify; optional cap to hide outliers' },
                    { value: 'Editions',              short: 'Restrict to specific sets (checkboxes from the current results)' },
                    { value: 'Per page',              short: '25, 50, or 100 rows per page' }
                ],
                examples: [
                    { query: 'TCG Low, +20%, 30d, Now $50', desc: 'Cards $50+ that rose 20% or more in the last month', palette: true },
                    { query: 'Was $100, up, 7d', desc: 'Cards that were $100+ and have climbed over the last week', palette: true },
                    { query: 'CK Buylist, down, 14d', desc: 'Buylist offers that fell over the last two weeks', palette: true }
                ]
            }
        },

        {
            id: 'feature-sleepers',
            category: 'Tools',
            requiresNav: 'Sleepers',
            title: 'Sleepers',
            icon: 'moon',
            summary: 'Find cards the market hasn\'t caught up on - bulk gems, no-reprint plays, mismatches, and seller gaps.',
            snippets: [],
            keywords: ['sleepers', 'bulk', 'reprint', 'mismatch', 'gap', 'hotlist', 'analysis', 'tier', 'rank', 'S', 'F', 'undervalued', 'opportunity', 'arbitrage', 'ocean gap', 'custom comparison', 'seller', 'reference', 'target', 'TCGLow', 'MKMLow', 'MKMTrend', 'Manapool'],
            content: {
                description: '<p>Sleepers surfaces cards where market pricing hasn\'t kept pace with demand, scarcity, or cross-market differences. Every result is tiered <strong>S through F</strong> - higher tiers mean stronger signals.</p><p><strong>Four analysis modes</strong> (each is its own page; palette: <code>&gt;sleepers + Tab + &lt;mode&gt;</code>):</p><ul><li><strong>Bulk Me Up</strong> - cards deviating from their set\'s average over the last 5 years; unexpected gems hiding in bulk</li><li><strong>Long Time No Reprint</strong> - no reprint in 2+ years; excludes bulk, Reserved List, and non-tournament cards</li><li><strong>Market Mismatch</strong> - buylist exceeds market price, or card is priced below TCG Low; direct arbitrage signal</li><li><strong>Hotlist</strong> - most buylist growth over the past 3 months; emerging trends before they fully break</li></ul><p><strong>Ocean Gap</strong> (BETA) is a fifth, distinct tool on the same page: it compares two sellers head-to-head and surfaces cards where one is cheaper than the other. Preset pairings between common reference indexes are one click each; custom pairings (pick any reference, any target) require a higher tier.</p>',
                table: [
                    { value: 'Bulk Me Up',              short: 'Cards deviating from their set\'s 5-year average' },
                    { value: 'Long Time No Reprint',    short: 'No reprint in 2+ years (excludes bulk / RL / non-tournament)' },
                    { value: 'Market Mismatch',         short: 'Buylist > market, or priced below TCG Low' },
                    { value: 'Hotlist',                 short: 'Most buylist growth over past 3 months' },
                    { value: 'Ocean Gap (BETA)',        short: 'Head-to-head seller comparison' },
                    { value: 'Ocean Gap presets',       short: 'TCGLow vs MKMLow / MKMTrend; MKMTrend vs CK / SCG / Manapool' },
                    { value: 'Custom comparison',       short: 'Pick any reference seller and target seller (tier-gated)' }
                ],
                examples: [
                    { query: '>sleepers + Tab + "Bulk Me Up"', desc: 'Jump straight to Bulk analysis', palette: true },
                    { query: 'on:hotlist sort:buylist', desc: 'Cards on the buylist hot list, sorted by value' }
                ]
            }
        },

        {
            id: 'feature-upload',
            category: 'Tools',
            requiresNav: 'Upload',
            title: 'Upload & Optimize',
            icon: 'upload',
            summary: 'Upload a collection in any common format and compare prices across vendors.',
            snippets: [],
            keywords: ['upload', 'collection', 'CSV', 'excel', 'xls', 'xlsx', 'google sheets', 'moxfield', 'tcgplayer', 'tcg collection', 'deckbox', 'binderpos', 'cardsphere', 'buylist', 'optimize', 'export', 'CK', 'SCG', 'TCG', 'MKM', 'card kingdom', 'cardmarket', 'cardconduit', 'retail', 'mtgban', 'sheet'],
            content: {
                description: '<p>Upload &amp; Compare matches your collection against every active vendor and reports prices side-by-side. The page is a three-step flow.</p><p><strong>Step 1 - Mode &amp; Stores.</strong> Toggle between <strong>Retail</strong> (cheapest places to buy) and <strong>Buylist</strong> (best places to sell), then pick which vendors to include - Card Kingdom, Star City Games, Strike Zone, TCG Direct (net), TCGplayer SYP, and others depending on your tier. Your selection persists as a cookie, so the palette\'s upload mode (<code>+</code>) uses the same set.</p><p><strong>Step 2 - Load data.</strong> Three input paths:</p><ul><li><strong>Local CSV/XLS</strong> - drop or browse for a file (max 5MB)</li><li><strong>Remote URL</strong> - Google Sheets (must be publicly accessible), TCG Collection URLs, or Moxfield deck URLs</li><li><strong>Paste Text</strong> - any tab/comma-separated text, or a plain card-name decklist</li></ul><p><strong>Step 3 - Process.</strong> <em>Upload</em> runs the match and produces an in-browser results page. From there, <em>Get CSV</em> downloads the full results, and three export buttons format the data for specific destinations: <em>CardConduit</em> (estimate), <em>Deckbox CSV</em>, and <em>TCGplayer CSV</em>.</p><p><strong>Format detection.</strong> Exports from TCGplayer, Deckbox, BinderPOS, and Cardsphere are auto-detected. Plain card-name lists also work - the most recent printing is used for ambiguous names. To pin a specific printing of a multi-printing card, include the collector number or variant.</p><p><strong>Sheet quirks:</strong> Excel sheets must contain <code>mtgban</code> somewhere in the sheet name (BAN uses this to find the right tab in multi-sheet workbooks). A Google Sheets URL is remembered as a preference and reused on the next visit.</p><p><strong>Limits:</strong> 350 entries per upload (1000 with Optimizer tier). Rows with quantity 0 are skipped; identical entries with matching condition are merged.</p>',
                table: [
                    { value: 'CSV / TSV',                              short: 'Comma or tab separated with sensible headers' },
                    { value: 'Excel (.xls, .xlsx)',                    short: 'Sheet name must contain "mtgban"' },
                    { value: 'Google Sheets',                          short: 'Public URL; saved as a preference' },
                    { value: 'TCG Collection URL',                     short: 'TCGplayer store collection link' },
                    { value: 'Moxfield URL',                           short: 'Public deck URL' },
                    { value: 'Plain decklist',                         short: 'One card name per line (most recent printing)' },
                    { value: 'TCG / Deckbox / BinderPOS / Cardsphere', short: 'Auto-detected exports' }
                ],
                examples: [
                    { query: '+https://docs.google.com/spreadsheets/d/...', desc: 'Submit a Google Sheets collection from the palette', palette: true },
                    { query: '+https://www.moxfield.com/decks/abc', desc: 'Submit a Moxfield deck', palette: true },
                    { query: 'On a search results page: + then Send results', desc: 'Push current results to the Uploader', palette: true }
                ]
            }
        },

        {
            id: 'feature-global',
            category: 'Tools',
            requiresNav: 'Global',
            title: 'Global',
            icon: 'globe',
            summary: 'Cross-store arbitrage at the index level - pick a reference index and see where else is cheaper.',
            snippets: [],
            keywords: ['global', 'arbitrage', 'index', 'reference', 'card kingdom', 'star city games', 'tcg market', 'CT zero', 'TCG direct', 'TCG low', 'EV', 'sealed', 'spread', 'profit', 'difference', 'yield', 'bucks', 'SYP', 'stocks', 'legit', 'cross-store'],
            content: {
                description: '<p>Global is a cross-store arbitrage tool that picks one store as a reference (the <em>index</em>) and surfaces cards where other markets are charging more. Unlike per-card Search, Global operates at the index level: every result is a comparison between the chosen index and one or more target stores.</p><p><strong>Pick an index:</strong></p><ul><li><strong>Singles</strong> - Card Kingdom, Star City Games, TCG Market</li><li><strong>Sealed</strong> - CT Zero EV Sealed, TCG Direct (net) EV Sealed, TCG Low EV Sealed (EV = expected value of pack contents)</li></ul><p>The results page shows each card with the index price, the target store\'s price, the dollar profit, the dollar difference, and a spread percentage. Direct Buy links go to both the source (the cheap index) and the target.</p><p><strong>Filter presets</strong> - toggle one or more to narrow results. The palette\'s <code>&gt;global + Tab</code> menu exposes the same set:</p>',
                table: [
                    { value: 'only NM/SP',         short: 'Hide MP/HP/PO conditions' },
                    { value: 'only non-Foil',      short: 'Hide foils' },
                    { value: 'only Foil',          short: 'Hide non-foils' },
                    { value: 'only Rare/Mythic',   short: 'Hide commons and uncommons' },
                    { value: 'only Bucks+',        short: 'Hide low-dollar results' },
                    { value: 'only Yield+',        short: 'Minimum profit threshold' },
                    { value: 'only Difference+',   short: 'Minimum price difference' },
                    { value: 'only Difference++',  short: 'Higher minimum price difference' },
                    { value: 'only SYP',           short: 'On the TCGplayer Save Your Points list' },
                    { value: 'only Stocks',        short: 'Has stock at the target' },
                    { value: 'only Legit',         short: 'Filter out questionable results' }
                ],
                examples: [
                    { query: '>global + Tab + "Card Kingdom"', desc: 'Open Global with Card Kingdom as the index', palette: true },
                    { query: '>global + Tab + "Yield+" + Tab + "Bucks+"', desc: 'Compose a filtered Global URL', palette: true }
                ]
            }
        },

        {
            id: 'feature-arbitrage',
            category: 'Tools',
            requiresNav: 'Arbitrage',
            title: 'Arbitrage',
            icon: 'trending-up',
            summary: 'Per-vendor retail-to-buylist gaps; flip opportunities filtered by condition, finish, and rarity.',
            snippets: [],
            keywords: ['arbitrage', 'arb', 'gap', 'price difference', 'retail', 'buylist', 'profit', 'flip', 'condition', 'foil', 'rarity', 'filter', 'admin'],
            content: {
                description: '<p>Arbitrage identifies cards where a meaningful gap exists between a vendor\'s retail price and another vendor\'s buylist offer - i.e. potential flip opportunities. The same filter preset set used by Global applies here (Yield+, Bucks+, Difference+, SYP, etc.), and the <code>&gt;arbit + Tab</code> palette menu composes filter URLs directly.</p><p>See also the <strong>Reverse</strong> page (buylists paying more than retail) and the <strong>Global</strong> page (cross-store comparison at the index level), which are part of the same toolkit.</p>',
                table: [],
                examples: [
                    { query: '>arbit + Tab + "Yield+" + Tab + "Bucks+"', desc: 'Compose an Arbitrage URL with profit filters', palette: true }
                ]
            }
        },

        {
            id: 'feature-reverse',
            category: 'Tools',
            requiresNav: 'Reverse',
            title: 'Reverse',
            icon: 'trending-down',
            summary: 'Buylists paying more than retail - reverse arbitrage signals across the vendor list.',
            snippets: [],
            keywords: ['reverse', 'arbitrage', 'arb', 'buylist', 'retail', 'inverted', 'flip', 'admin', 'difference', 'profit'],
            content: {
                description: '<p>Reverse is the inverted complement to <strong>Arbitrage</strong>: it surfaces cards where a buylist is paying <em>more</em> than another vendor is selling for retail. These are the most direct flip signals on the site - if a buylist is over retail elsewhere and the source has stock, the gap is real.</p><p>The same filter presets apply (Yield+, Bucks+, Difference+, SYP, etc.) and the palette\'s <code>&gt;reverse + Tab</code> menu builds filtered URLs.</p>',
                table: [],
                examples: [
                    { query: '>reverse + Tab + "Yield+"', desc: 'Reverse arbitrage results with yield filter', palette: true }
                ]
            }
        },

        // Tips & Tricks
        {
            id: 'tips-reading-prices',
            category: 'Tips & Tricks',
            title: 'Reading Prices',
            icon: 'eye',
            summary: 'How to interpret refresh timing, conditions, buylist ratios, and trade credit values.',
            snippets: [],
            keywords: ['tips', 'tricks', 'reading', 'prices', 'refresh', 'timing', 'condition', 'buylist', 'ratio', 'trade credit', 'tooltip', 'index', 'NM', 'sealed', 'interpret'],
            content: {
                description: '<p>A few things to know when looking at price data:</p><p><strong>Price refresh:</strong> Data is updated periodically throughout the day. The exact delay is randomized to prevent sniping.</p><p><strong>Conditions:</strong> Inventory prices reflect stated conditions (accuracy depends on the provider). Buylist prices are always NM. Sealed products are always in sealed/unopened condition. The Index condition is for trend data only - no quantities are tracked.</p><p><strong>Buylist ratios:</strong> The percentage shown on buylist results reflects vendor desirability - higher means they want it more. Only shown when the vendor also has retail stock at matching conditions.</p><p><strong>Trade credit:</strong> Hover over a buylist price to see the corresponding trade credit value, if available.</p>',
                table: [],
                examples: [
                    { query: 'ratio>50 r:rare', desc: 'High-demand rares on buylists' },
                    { query: 'on:hotlist sort:buylist', desc: 'Hot list sorted by buylist value' }
                ]
            }
        },

        {
            id: 'tips-power-features',
            category: 'Tips & Tricks',
            title: 'Power Features',
            icon: 'zap',
            summary: 'Historical charts, reprint finder, flavor name search, and where to report issues.',
            snippets: [],
            keywords: ['tips', 'tricks', 'power user', 'history', 'chart', 'historical', 'reprint', 'finder', 'flavor name', 'feedback', 'discord', '📊', '📖', 'icon'],
            content: {
                description: '<p>A handful of features that are easy to miss:</p><p><strong>Historical data:</strong> Click the 📊 chart icon on any card to view price history from major vendors.</p><p><strong>Reprint finder:</strong> Click 📖 on a card to see every product containing any reprint of that card. Source products are also accessible via "Found in * products" links.</p><p><strong>Flavor names:</strong> Searching a flavor name returns only those specific art versions (unless disabled in preferences). This does not work for complex multi-filter queries.</p><p><strong>Feedback:</strong> Report issues in the #feedback channel on the BAN Discord with a URL or screenshot. Some errors originate from upstream providers.</p>',
                table: [],
                examples: [
                    { query: 'is:reserved price>50', desc: 'Expensive reserved list cards' }
                ]
            }
        }

    ]
};

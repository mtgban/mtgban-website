/* Guide Data — Shared Content Registry
 * Single source of truth for the command palette and /guide page.
 */
window.__BAN_GUIDE = {
    sections: [

        // ─── Command Palette ──────────────────────────────────────────────

        {
            id: 'palette',
            category: 'Command Palette',
            title: 'Getting Started',
            icon: 'terminal',
            summary: 'Open the command palette with Ctrl+K / Cmd+K or type / in the search box.',
            snippets: ['Ctrl+K', 'Cmd+K', '?:', '>'],
            keywords: ['palette', 'keyboard', 'shortcut', 'command', 'help', 'search', 'open', 'ctrl k', 'cmd k', 'slash', 'modes'],
            content: {
                description: 'The command palette gives you fast keyboard-driven access to search syntax help and site navigation. Open it with <code>Ctrl+K</code> (Windows/Linux) or <code>Cmd+K</code> (Mac), or by typing <code>/</code> anywhere in the main search box.<br><br>Once open, you can switch modes using prefixes:<br><code>?:</code> — inline syntax help<br><code>&gt;</code> — navigate to a page<br><code>saved:</code> — recall a saved search command',
                table: [
                    { value: 'Ctrl+K / Cmd+K', short: 'Open palette from anywhere' },
                    { value: '/', short: 'Open palette from search box' },
                    { value: '?:', short: 'Show inline syntax reference' },
                    { value: '>', short: 'Navigate to a site page' },
                    { value: 'saved:', short: 'Access saved search commands' }
                ],
                examples: [
                    { query: '?:rarity', desc: 'Show rarity syntax help inline' },
                    { query: '>newspaper', desc: 'Navigate to the Newspaper page' },
                    { query: 'saved:my list', desc: 'Run a saved search command' }
                ]
            }
        },

        {
            id: 'saved-commands',
            category: 'Command Palette',
            title: 'Saved Commands',
            icon: 'bookmark',
            summary: 'Save, manage, and reuse your most-used search queries from the palette.',
            snippets: ['saved:', 'Ctrl+S to save'],
            keywords: ['saved', 'bookmark', 'favorite', 'command', 'recall', 'reuse', 'store', 'manage', 'delete'],
            content: {
                description: 'Any search query can be saved as a named command for quick reuse. To save the current query, press <code>Ctrl+S</code> (or use the save icon in the search bar). Saved commands appear in the palette under the <code>saved:</code> prefix.<br><br>To manage saved commands, open the palette and type <code>saved:</code> — you can rename, delete, or run any entry from there.',
                table: [
                    { value: 'Ctrl+S', short: 'Save current search as a command' },
                    { value: 'saved:', short: 'Browse saved commands in palette' },
                    { value: 'Delete key', short: 'Delete highlighted saved command' }
                ],
                examples: [
                    { query: 'saved:fetchlands', desc: 'Run the "fetchlands" saved search' },
                    { query: 'saved:', desc: 'Browse all saved commands' }
                ]
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

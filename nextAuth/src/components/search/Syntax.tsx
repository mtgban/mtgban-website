"use client"

import { useState } from "react"
export default function WelcomeContent() {
    const [activeTab, setActiveTab] = useState<'syntax' | 'features'>('syntax');

    return (
        <div className="welcome-container">
            <div className="welcome-tabs">
                <button
                    className={`welcome-tab ${activeTab === 'syntax' ? 'active' : ''}`}
                    onClick={() => setActiveTab('syntax')}
                >
                    Search Syntax
                </button>
                <button
                    className={`welcome-tab ${activeTab === 'features' ? 'active' : ''}`}
                    onClick={() => setActiveTab('features')}
                >
                    Features
                </button>
            </div>

            <div className="welcome-content">
                {activeTab === 'syntax' && (
                    <div className="syntax-content">
                        <h3>Search Syntax Guide</h3>

                        <div className="syntax-section">
                            <h4>Basic Search Format</h4>
                            <p>
                                Use the format: <code className="code-snippet">name[|code[|number]]&#123;&amp;*~&#125;</code>
                            </p>
                            <p>Example: <code className="code-snippet">Lightning Bolt|M10|146</code> searches for Lightning Bolt from M10 with collector number 146</p>
                        </div>

                        <div className="syntax-section">
                            <h4>Finish Filters</h4>
                            <ul className="welcome-list">
                                <li><code className="code-snippet">&amp;</code> for nonfoil-only</li>
                                <li><code className="code-snippet">*</code> for foil-only</li>
                                <li><code className="code-snippet">~</code> for etched-only</li>
                                <li>Alternative: <code className="code-snippet">f:foil/nonfoil/etched</code></li>
                            </ul>
                        </div>

                        <div className="syntax-section">
                            <h4>Common Filters</h4>
                            <ul className="welcome-list two-column">
                                <li><code className="code-snippet">s:CODE</code> or <code className="code-snippet">s:"Set Name"</code> - filter by edition</li>
                                <li><code className="code-snippet">cn:NUMBER</code> - filter by collector number</li>
                                <li><code className="code-snippet">r:RARITY</code> - filter by rarity (mythic, rare, uncommon, common)</li>
                                <li><code className="code-snippet">t:TYPE</code> - filter by card type</li>
                                <li><code className="code-snippet">c:COLOR</code> - filter by color (WUBRG)</li>
                                <li><code className="code-snippet">is:PROPERTY</code> - filter by property (reserved, fullart, foil, etc.)</li>
                                <li><code className="code-snippet">not:PROPERTY</code> - exclude by property</li>
                                <li><code className="code-snippet">price&gt;VALUE</code> or <code className="code-snippet">price&lt;VALUE</code> - filter by price</li>
                            </ul>
                        </div>

                        <div className="syntax-section">
                            <h4>Search Modes</h4>
                            <ul className="welcome-list">
                                <li><code className="code-snippet">sm:exact</code> - exact name match (default)</li>
                                <li><code className="code-snippet">sm:prefix</code> - matches beginning of name</li>
                                <li><code className="code-snippet">sm:any</code> - matches any part of name</li>
                                <li><code className="code-snippet">sm:regexp</code> - uses regular expression</li>
                                <li><code className="code-snippet">sm:scryfall</code> - forwards search to Scryfall</li>
                            </ul>
                        </div>

                        <div className="syntax-section">
                            <h4>Sort Options</h4>
                            <p>
                                <code className="code-snippet">sort:chrono</code> (default),
                                <code className="code-snippet">sort:alpha</code>,
                                <code className="code-snippet">sort:hybrid</code>,
                                <code className="code-snippet">sort:retail</code>,
                                <code className="code-snippet">sort:buylist</code>
                            </p>
                        </div>
                    </div>
                )}

                {activeTab === 'features' && (
                    <div className="features-content">
                        <h3>MTG Price Search Features</h3>

                        <div className="features-section">
                            <h4>Price Data</h4>
                            <ul className="welcome-list">
                                <li>Data is refreshed periodically throughout the day</li>
                                <li>Inventory prices refer to the stated conditions</li>
                                <li>Buylist prices always refer to NM conditions</li>
                                <li>TCG Low may differ from quantity and quality of listings</li>
                                <li>Price ratio percentage in buylist offers shows vendor demand (higher = higher demand)</li>
                                <li>Hover on buylist price to see trade-in value (when available)</li>
                            </ul>
                        </div>

                        <div className="features-section">
                            <h4>Additional Features</h4>
                            <ul className="welcome-list">
                                <li>Click on 📊 icon to view historical price data</li>
                                <li>Click on 📖 button to find all printings of a card</li>
                                <li>Entries are formatted as <i>card name (finish) - edition (collector #) - # of prints</i></li>
                                <li>Use the "Found in * products" to retrieve the source product</li>
                                <li>Filter results using the powerful search syntax</li>
                                <li>Download results as CSV for further analysis</li>
                                <li>Access various price sources including major vendors and marketplaces</li>
                            </ul>
                        </div>

                        <div className="features-section">
                            <h4>Support</h4>
                            <ul className="welcome-list">
                                <li>In case of mistakes or incongruities, please notify the devs in the BAN Discord</li>
                                <li>Consider using the provided affiliate links when making purchases to support BAN</li>
                            </ul>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export function HelpContent() {
    const [activeTab, setActiveTab] = useState<'syntax' | 'features'>('syntax');

    return (
        <div className="help-section glass-card">
            <div className="card-inner">
                <div className="help-tabs">
                    <button
                        className={`help-tab ${activeTab === 'syntax' ? 'active' : ''}`}
                        onClick={() => setActiveTab('syntax')}
                    >
                        Syntax
                    </button>
                    <button
                        className={`help-tab ${activeTab === 'features' ? 'active' : ''}`}
                        onClick={() => setActiveTab('features')}
                    >
                        Features
                    </button>
                </div>

                {activeTab === 'syntax' && (
                    <div className="syntax-content">
                        <ul className="help-list">
                            <li>
                                <strong>Basic format:</strong> <code className="code-snippet">name[|code[|number]]&#123;&amp;*~&#125;</code>
                            </li>
                            <li>
                                <strong>Filters:</strong>
                                <ul className="nested-list">
                                    <li><code className="code-snippet">&amp;</code> = nonfoil, <code className="code-snippet">*</code> = foil, <code className="code-snippet">~</code> = etched</li>
                                    <li><code className="code-snippet">s:CODE</code> or <code className="code-snippet">s:"Set Name"</code> = filter by edition</li>
                                    <li><code className="code-snippet">cn:NUMBER</code> = filter by collector number</li>
                                    <li><code className="code-snippet">f:foil/nonfoil/etched</code> = filter by finish</li>
                                    <li><code className="code-snippet">r:rarity</code> = filter by rarity (mythic, rare, etc.)</li>
                                    <li><code className="code-snippet">t:type</code> = filter by card type</li>
                                    <li><code className="code-snippet">is:property</code> = filter by properties (reserved, fullart, etc.)</li>
                                </ul>
                            </li>
                            <li>
                                <strong>Search modes:</strong> <code className="code-snippet">sm:exact/prefix/any/regexp/scryfall</code>
                            </li>
                            <li>
                                <strong>Sort options:</strong> <code className="code-snippet">sort:chrono/hybrid/alpha/retail/buylist</code>
                            </li>
                            <li>
                                <strong>Advanced:</strong> <code className="code-snippet">price&gt;VALUE</code>, <code className="code-snippet">price&lt;VALUE</code>, <code className="code-snippet">store:NAME</code>
                            </li>
                            <li>
                                Add <code className="code-snippet">-</code> before any filter to invert results
                            </li>
                        </ul>
                    </div>
                )}

                {activeTab === 'features' && (
                    <div className="features-content">
                        <ul className="help-list">
                            <li>Access historical data by clicking on the 📊 icon for each card</li>
                            <li>Data is refreshed periodically throughout the day</li>
                            <li>Price ratio percentage in buylist offers shows vendor demand (higher = higher demand)</li>
                            <li>Inventory prices refer to the stated conditions</li>
                            <li>Buylist prices always refer to NM conditions</li>
                            <li>TCG Low refers to TCG algorithms that may differ from actual listings</li>
                            <li>Hover on buylist price to see trade-in value (when available)</li>
                            <li>Use 📖 button to find all printings of a card</li>
                            <li>Support BAN by using provided affiliate links when making purchases</li>
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
}
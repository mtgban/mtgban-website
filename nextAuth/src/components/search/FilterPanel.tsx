"use client"

import type React from "react"
import { useState } from "react"
import type { SearchFilters } from "@/hooks/useSearch"

interface FilterPanelProps {
  filters: SearchFilters
  onFilterChange: (filters: Partial<SearchFilters>) => void
  isSealed: boolean
  onClose: () => void
}

const FilterPanel: React.FC<FilterPanelProps> = ({ filters, onFilterChange, isSealed, onClose }) => {
  const [activeTab, setActiveTab] = useState<"basic" | "advanced">("basic")

  // Handle condition change
  const handleConditionChange = (condition: string) => {
    onFilterChange({ condition })
  }

  // Handle rarity change
  const handleRarityChange = (rarity: string) => {
    onFilterChange({ rarity })
  }

  // Handle color change
  const handleColorChange = (color: string) => {
    onFilterChange({ color })
  }

  // Handle finish change
  const handleFinishChange = (finish: string) => {
    onFilterChange({ finish })
  }

  // Handle type change
  const handleTypeChange = (type: string) => {
    onFilterChange({ type })
  }

  // Handle edition change
  const handleEditionChange = (edition: string) => {
    onFilterChange({ edition })
  }

  // Handle collector number change
  const handleCollectorNumberChange = (collectorNumber: string) => {
    onFilterChange({ collectorNumber })
  }

  // Handle price range change
  const handlePriceChange = (min?: number, max?: number) => {
    onFilterChange({
      price: {
        ...filters.price,
        min,
        max,
      },
    })
  }

  // Handle store selection
  const handleStoreChange = (store: string, checked: boolean) => {
    const stores = [...filters.stores]

    if (checked) {
      if (!stores.includes(store)) {
        stores.push(store)
      }
    } else {
      const index = stores.indexOf(store)
      if (index !== -1) {
        stores.splice(index, 1)
      }
    }

    onFilterChange({ stores })
  }

  // Reset all filters
  const resetFilters = () => {
    onFilterChange({
      condition: "",
      rarity: "",
      color: "",
      finish: "",
      type: "",
      edition: "",
      collectorNumber: "",
      price: {
        min: undefined,
        max: undefined,
      },
      stores: [],
    })
  }

  return (
    <div className="filter-panel">
      <div className="filter-header">
        <h3>Filters</h3>
        <button type="button" className="close-button" onClick={onClose}>
          ×
        </button>
      </div>

      <div className="filter-tabs">
        <button
          type="button"
          className={`tab-button ${activeTab === "basic" ? "active" : ""}`}
          onClick={() => setActiveTab("basic")}
        >
          Basic
        </button>
        <button
          type="button"
          className={`tab-button ${activeTab === "advanced" ? "active" : ""}`}
          onClick={() => setActiveTab("advanced")}
        >
          Advanced
        </button>
      </div>

      <div className="filter-content">
        {activeTab === "basic" ? (
          <div className="basic-filters">
            {!isSealed && (
              <>
                <div className="filter-group">
                  <h4>Condition</h4>
                  <div className="filter-options">
                    {["NM", "SP", "MP", "HP", "PO"].map((condition) => (
                      <label key={condition} className="filter-option">
                        <input
                          type="radio"
                          name="condition"
                          value={condition}
                          checked={filters.condition === condition}
                          onChange={() => handleConditionChange(condition)}
                        />
                        {condition}
                      </label>
                    ))}
                    {filters.condition && (
                      <button type="button" className="clear-filter" onClick={() => handleConditionChange("")}>
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                <div className="filter-group">
                  <h4>Rarity</h4>
                  <div className="filter-options">
                    {["mythic", "rare", "uncommon", "common", "special"].map((rarity) => (
                      <label key={rarity} className="filter-option">
                        <input
                          type="radio"
                          name="rarity"
                          value={rarity}
                          checked={filters.rarity === rarity}
                          onChange={() => handleRarityChange(rarity)}
                        />
                        {rarity}
                      </label>
                    ))}
                    {filters.rarity && (
                      <button type="button" className="clear-filter" onClick={() => handleRarityChange("")}>
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                <div className="filter-group">
                  <h4>Color</h4>
                  <div className="filter-options color-options">
                    {["W", "U", "B", "R", "G", "C", "M"].map((color) => (
                      <label key={color} className={`color-option color-${color.toLowerCase()}`}>
                        <input
                          type="radio"
                          name="color"
                          value={color}
                          checked={filters.color === color}
                          onChange={() => handleColorChange(color)}
                        />
                        {color}
                      </label>
                    ))}
                    {filters.color && (
                      <button type="button" className="clear-filter" onClick={() => handleColorChange("")}>
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                <div className="filter-group">
                  <h4>Finish</h4>
                  <div className="filter-options">
                    {["nonfoil", "foil", "etched"].map((finish) => (
                      <label key={finish} className="filter-option">
                        <input
                          type="radio"
                          name="finish"
                          value={finish}
                          checked={filters.finish === finish}
                          onChange={() => handleFinishChange(finish)}
                        />
                        {finish}
                      </label>
                    ))}
                    {filters.finish && (
                      <button type="button" className="clear-filter" onClick={() => handleFinishChange("")}>
                        Clear
                      </button>
                    )}
                  </div>
                </div>
              </>
            )}

            <div className="filter-group">
              <h4>Price Range</h4>
              <div className="price-range">
                <div className="price-input">
                  <label htmlFor="price-min">Min $</label>
                  <input
                    type="number"
                    id="price-min"
                    min="0"
                    step="0.01"
                    value={filters.price.min || ""}
                    onChange={(e) =>
                      handlePriceChange(e.target.value ? Number(e.target.value) : undefined, filters.price.max)
                    }
                  />
                </div>
                <div className="price-input">
                  <label htmlFor="price-max">Max $</label>
                  <input
                    type="number"
                    id="price-max"
                    min="0"
                    step="0.01"
                    value={filters.price.max || ""}
                    onChange={(e) =>
                      handlePriceChange(filters.price.min, e.target.value ? Number(e.target.value) : undefined)
                    }
                  />
                </div>
                {(filters.price.min !== undefined || filters.price.max !== undefined) && (
                  <button
                    type="button"
                    className="clear-filter"
                    onClick={() => handlePriceChange(undefined, undefined)}
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="filter-group">
              <h4>Stores</h4>
              <div className="store-options">
                {["TCGPlayer", "CardKingdom", "ChannelFireball", "StarCityGames"].map((store) => (
                  <label key={store} className="filter-option">
                    <input
                      type="checkbox"
                      name="stores"
                      value={store}
                      checked={filters.stores.includes(store)}
                      onChange={(e) => handleStoreChange(store, e.target.checked)}
                    />
                    {store}
                  </label>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="advanced-filters">
            <div className="filter-group">
              <h4>Edition</h4>
              <div className="text-input">
                <input
                  type="text"
                  placeholder="Set code or name (e.g., MH2)"
                  value={filters.edition || ""}
                  onChange={(e) => handleEditionChange(e.target.value)}
                />
                {filters.edition && (
                  <button type="button" className="clear-input" onClick={() => handleEditionChange("")}>
                    ×
                  </button>
                )}
              </div>
            </div>

            <div className="filter-group">
              <h4>Collector Number</h4>
              <div className="text-input">
                <input
                  type="text"
                  placeholder="e.g., 1 or 1-10"
                  value={filters.collectorNumber || ""}
                  onChange={(e) => handleCollectorNumberChange(e.target.value)}
                />
                {filters.collectorNumber && (
                  <button type="button" className="clear-input" onClick={() => handleCollectorNumberChange("")}>
                    ×
                  </button>
                )}
              </div>
            </div>

            <div className="filter-group">
              <h4>Type</h4>
              <div className="text-input">
                <input
                  type="text"
                  placeholder="e.g., Creature, Artifact"
                  value={filters.type || ""}
                  onChange={(e) => handleTypeChange(e.target.value)}
                />
                {filters.type && (
                  <button type="button" className="clear-input" onClick={() => handleTypeChange("")}>
                    ×
                  </button>
                )}
              </div>
            </div>

            <div className="filter-group">
              <h4>Search Syntax Help</h4>
              <div className="syntax-help">
                <p>Use these advanced search operators:</p>
                <ul>
                  <li>
                    <code>s:CODE</code> - Filter by set code
                  </li>
                  <li>
                    <code>cn:NUMBER</code> - Filter by collector number
                  </li>
                  <li>
                    <code>cond:COND</code> - Filter by condition
                  </li>
                  <li>
                    <code>r:RARITY</code> - Filter by rarity
                  </li>
                  <li>
                    <code>c:COLOR</code> - Filter by color
                  </li>
                  <li>
                    <code>f:VALUE</code> - Filter by finish
                  </li>
                  <li>
                    <code>t:VALUE</code> - Filter by type
                  </li>
                  <li>
                    <code>price&gt;VALUE</code> - Filter by minimum price
                  </li>
                  <li>
                    <code>price&lt;VALUE</code> - Filter by maximum price
                  </li>
                  <li>
                    <code>store:NAME</code> - Filter by store
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="filter-actions">
        <button type="button" className="reset-button" onClick={resetFilters}>
          Reset All Filters
        </button>
        <button type="button" className="apply-button" onClick={onClose}>
          Apply Filters
        </button>
      </div>
    </div>
  )
}

export default FilterPanel


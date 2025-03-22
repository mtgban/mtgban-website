"use client"

import React, { useState, useRef, useEffect, useCallback, FormEvent } from "react"
import Link from "next/link"
import { useRouter, usePathname } from "next/navigation"
import type { SearchFilters } from "@/hooks/useSearch"
import { useAuth } from "@/hooks/useAuth"
import FilterPanel from "./FilterPanel"

interface SearchFormProps {
  searchQuery: string
  isSealed: boolean
  searchSort: string
  noSort: boolean
  reverseMode: boolean
  filters: SearchFilters
  onQueryChange: (query: string) => void
  onFilterChange: (filters: SearchFilters) => void
  onSearch: () => void
}

/**
 * SearchForm component adapted for Go backend
 */
const SearchForm: React.FC<SearchFormProps> = ({
  searchQuery,
  isSealed,
  searchSort,
  noSort,
  reverseMode,
  filters,
  onQueryChange,
  onFilterChange,
  onSearch,
}) => {
  const router = useRouter()
  const searchboxRef = useRef<HTMLInputElement>(null)
  const searchformRef = useRef<HTMLFormElement>(null)
  const [showFilters, setShowFilters] = useState(false)
  const [inputValue, setInputValue] = useState(searchQuery)
  const { hasFeature } = useAuth()
  const pathname = usePathname()

  // Initialize autocomplete when component mounts
  // This uses the autocomplete function provided by the Go backend's JS
  useEffect(() => {
    if (typeof window !== "undefined" && window.autocomplete && searchformRef.current && searchboxRef.current) {
      window.autocomplete(searchformRef.current, searchboxRef.current, isSealed ? "true" : "false")
    }
  }, [isSealed])

  // Update input value when searchQuery changes
  useEffect(() => {
    setInputValue(searchQuery)
  }, [searchQuery])

  // Handle input change with debounce
  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setInputValue(value)
    
    // Use a timeout for debouncing
    const timeoutId = setTimeout(() => {
      onQueryChange(value)
    }, 300)
    
    return () => clearTimeout(timeoutId)
  }, [onQueryChange])

  // Handle form submission - using the Go backend's form handling
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    
    // Submit normally if using JS-disabled browsing
    if (!e.defaultPrevented) {
      // This will still allow the Go server to handle the form submission
      // while we also trigger the client-side search
      onSearch()
    }
  }

  // Toggle filter panel
  const toggleFilters = useCallback(() => {
    setShowFilters(!showFilters)
  }, [showFilters])

  // Generate sort option props for sort links
  const getSortButtonProps = useCallback((sortType: string) => {
    const isActive = searchSort === sortType || (!searchSort && sortType === "chrono")
    
    return {
      className: `btn info ${isActive ? "active" : ""}`,
      "aria-current": isActive ? "true" : undefined,
      onClick: (e: React.MouseEvent) => {
        e.preventDefault()
        onFilterChange({
          sort: sortType,
          price: {
            min: 0,
            max: 0
          },
          stores: []
        })
      }
    }
  }, [searchSort, onFilterChange])

  // Handle reverse sort toggle
  const handleReverseSort = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    onFilterChange({
      reverse: !reverseMode,
      price: {
        min: 0,
        max: 0
      },
      stores: []
    })
  }, [reverseMode, onFilterChange])

  // Check if random search is available
  const canUseRandomSearch = useAuth().hasFeature('RandomSearch')

  // Update local filters when props change
  useEffect(() => {
    onFilterChange(filters)
  }, [filters, onFilterChange])

  // Get placeholder text based on search type
  const placeholderText = isSealed 
    ? "Search for sealed products (e.g. 'Dominaria Collector Booster')" 
    : "Search for cards (e.g. 'lightning bolt' or 'o:flying t:dragon')"

  return (
    <div className="search-container">
      <form
        className="search autocomplete"
        action=""
        autoComplete="off"
        spellCheck={false}
        id="searchform"
        ref={searchformRef}
        onSubmit={handleSubmit}
        aria-label="Search form"
      >
        <div className="search-header">
          <label htmlFor="searchbox" className="search-label">
            {!searchQuery ? (
              <>
                Search for a {isSealed ? "product" : "card"}, or...{" "}
                {canUseRandomSearch && (
                  <Link href={`/random${isSealed ? "sealed" : ""}`} className="btn info">
                    surprise me
                  </Link>
                )}
              </>
            ) : (
              <>
                <div className="sort-options">
                  Sort by
                  {noSort ? (
                    " syntax"
                  ) : (
                    <>
                      {/* Chronological sort */}
                      <a
                        href={`?q=${searchQuery}&sort=`}
                        title="Sort by chronological order"
                        {...getSortButtonProps("chrono")}
                        aria-current={searchSort === "chrono" || !searchSort ? "page" : undefined}
                      >
                        chrono
                      </a>
                      {(searchSort === "chrono" || !searchSort) && (
                        <button
                          type="button"
                          className="btn-icon"
                          title={`Sort by ${reverseMode ? "chronological" : "reverse chronological"} order`}
                          onClick={handleReverseSort}
                        >
                          🔄
                        </button>
                      )}

                      {/* Alphabetical sort */}
                      <a  
                        href={`?q=${searchQuery}&sort=alpha`}
                        title={`Sort by alphabetical order${searchSort === "hybrid" ? " (keeping sets grouped)" : ""}`}
                        {...getSortButtonProps("alpha")}
                        aria-current={searchSort === "alpha" || searchSort === "hybrid" ? "page" : undefined}
                      >
                        alpha
                      </a>
                      {(searchSort === "alpha" || searchSort === "hybrid") && (
                        <button
                          type="button"
                          className="btn-icon"
                          title={`Sort by ${reverseMode ? "alphabetical" : "reverse alphabetical"} order${
                            searchSort === "hybrid" ? " (keeping sets grouped)" : ""
                          }`}
                          onClick={handleReverseSort}
                        >
                          🔄
                        </button>
                      )}

                      {/* Retail price sort */}
                      <a  
                        href={`?q=${searchQuery}&sort=retail`}
                        title="Sort by best retail price (off TCGplayer)"
                        {...getSortButtonProps("retail")}
                        aria-current={searchSort === "retail" ? "page" : undefined}
                      >
                        retail
                      </a>
                      {searchSort === "retail" && (
                        <button
                          type="button"
                          className="btn-icon"
                          title={`Sort by ${reverseMode ? "highest" : "lowest"} retail price (off TCGplayer)`}
                          onClick={handleReverseSort}
                        >
                          🔄
                        </button>
                      )}

                      {/* Buylist price sort */}
                      <a
                        href={`?q=${searchQuery}&sort=buylist`}
                        title="Sort by best buylist price (off Card Kingdom)"
                        {...getSortButtonProps("buylist")}
                        aria-current={searchSort === "buylist" ? "page" : undefined}
                      >
                        buylist
                      </a>
                      {searchSort === "buylist" && (
                        <button
                          type="button"
                          className="btn-icon"
                          title={`Sort by ${reverseMode ? "highest" : "lowest"} buylist price (off Card Kingdom)`}
                          onClick={handleReverseSort}
                        >
                          🔄
                        </button>
                      )}
                    </>
                  )}
                </div>
                <div className="search-actions">
                  {canUseRandomSearch && (
                    <Link href={`/random${isSealed ? "sealed" : ""}`} className="btn info" title="...more surprises">
                      🎰
                    </Link>
                  )}
                  <button
                    type="button"
                    className="btn-icon filter-toggle"
                    title="Toggle filters"
                    aria-expanded={showFilters}
                    aria-controls="filter-panel"
                    onClick={toggleFilters}
                  >
                    🔍
                  </button>
                </div>
              </>
            )}
            {!isSealed && (
              <Link href="?page=options" className="settings-link" title="Search settings">
                ⚙️
              </Link>
            )}
          </label>
        </div>

        <div className="search-input-container">
          <input
            id="searchbox"
            className="search-input"
            onFocus={(e) => e.target.setSelectionRange(0, e.target.value.length)}
            type="text"
            name="q"
            placeholder={placeholderText}
            value={inputValue}
            onChange={handleInputChange}
            maxLength={1000}
            autoFocus
            autoCapitalize="none"
            ref={searchboxRef}
          />
          <button type="submit" className="search-button">
            Search
          </button>
        </div>
      </form>

      {showFilters && (
        <div id="filter-panel">
          <FilterPanel
            filters={filters}
            onFilterChange={onFilterChange as (filters: Partial<SearchFilters>) => void}
            isSealed={isSealed}
            onClose={() => setShowFilters(false)}
          />
        </div>
      )}

      {/* Search hints */}
      {!isSealed && pathname === '/' && !inputValue && (
        <div className="search-hints">
          <h3>Search tips:</h3>
          <ul>
            <li><code>name:"lightning bolt"</code> - Search for exact name</li>
            <li><code>t:dragon</code> - Search for card type</li>
            <li><code>o:flying</code> - Search for text in oracle text</li>
            <li><code>c:r</code> - Search for red cards</li>
            <li><code>e:dom</code> - Search in Dominaria set</li>
          </ul>
        </div>
      )}
    </div>
  )
}

export default SearchForm
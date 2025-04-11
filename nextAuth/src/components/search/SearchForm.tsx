"use client"

import type React from "react"
import { useState, useEffect, useRef } from "react"
import { Search, X } from "lucide-react"

interface SearchFormProps {
  onSearch: (query: string) => void
}

export default function SearchForm({ onSearch }: SearchFormProps) {
  const [query, setQuery] = useState("")
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [recentSearches, setRecentSearches] = useState<string[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  // Load recent searches from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem('recentSearches')
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed)) {
          setRecentSearches(parsed.slice(0, 5))
        }
      } catch (e) {
        console.error('Failed to parse recent searches', e)
      }
    }
  }, [])

  // Save a new search to recent searches
  const saveToRecentSearches = (searchQuery: string) => {
    if (!searchQuery.trim()) return
    
    const updated = [searchQuery, ...recentSearches.filter(s => s !== searchQuery)].slice(0, 5)
    setRecentSearches(updated)
    localStorage.setItem('recentSearches', JSON.stringify(updated))
  }

  // Fetch suggestions when query changes
  useEffect(() => {
    if (query.length >= 3) {
      fetchSuggestions(query)
    } else {
      setSuggestions([])
      setShowSuggestions(false)
    }
  }, [query])

  // Function to fetch suggestions from the API using the actual endpoint
  const fetchSuggestions = async (input: string) => {
    try {
      const response = await fetch(`/api/suggest?q=${encodeURIComponent(input)}`)
      
      if (!response.ok) {
        setSuggestions([])
        setShowSuggestions(false)
        return
      }
      
      // Parse the response - format is [prefix, [suggestions], [results], [links]]
      const data = await response.json()
      
      if (Array.isArray(data) && data.length >= 2 && Array.isArray(data[1])) {
        // Extract the suggestions array (second element)
        const receivedSuggestions = data[1]
        setSuggestions(receivedSuggestions.filter(s => s !== ""))
        setShowSuggestions(receivedSuggestions.length > 0 && receivedSuggestions[0] !== "")
      } else {
        setSuggestions([])
        setShowSuggestions(false)
      }
    } catch (error) {
      console.error('Error fetching suggestions:', error)
      setSuggestions([])
      setShowSuggestions(false)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return
    
    onSearch(query)
    saveToRecentSearches(query)
    setShowSuggestions(false)
  }

  const handleSuggestionClick = (suggestion: string) => {
    setQuery(suggestion)
    onSearch(suggestion)
    saveToRecentSearches(suggestion)
    setShowSuggestions(false)
  }

  const handleRecentSearchClick = (recentSearch: string) => {
    setQuery(recentSearch)
    onSearch(recentSearch)
    saveToRecentSearches(recentSearch)
    setShowSuggestions(false)
  }

  const clearSearch = () => {
    setQuery("")
    inputRef.current?.focus()
  }

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (inputRef.current && !inputRef.current.contains(e.target as Node)) {
        setShowSuggestions(false)
      }
    }

    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  return (
    <div className="search-form-container">
      <form onSubmit={handleSubmit} className="search-form">
        <div className="search-input-wrapper">
          <input
            ref={inputRef}
            type="text"
            className="search-input"
            placeholder="Search for a card..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onFocus={() => {
              if (query.length >= 3 && suggestions.length > 0) {
                setShowSuggestions(true)
              } else if (recentSearches.length > 0 && query.length === 0) {
                setShowSuggestions(true)
              }
            }}
            aria-label="Search input"
          />
          <Search className="search-icon" />
          
          {query && (
            <button 
              type="button"
              onClick={clearSearch}
              className="clear-button"
              aria-label="Clear search"
            >
              <X className="clear-icon" />
            </button>
          )}
          
          <button
            type="submit"
            className="search-button"
          >
            Search
          </button>
        </div>
      </form>

      {showSuggestions && (
        <div className="suggestions-dropdown">
          {suggestions.length > 0 && (
            <>
              <div className="suggestions-header">Suggestions</div>
              <ul className="suggestions-list">
                {suggestions.map((suggestion, index) => (
                  <li
                    key={`suggestion-${index}`}
                    className="suggestion-item"
                    onClick={() => handleSuggestionClick(suggestion)}
                  >
                    <Search className="suggestion-icon" />
                    {suggestion}
                  </li>
                ))}
              </ul>
            </>
          )}

          {recentSearches.length > 0 && !suggestions.length && (
            <>
              <div className="suggestions-header">Recent Searches</div>
              <ul className="suggestions-list">
                {recentSearches.map((recent, index) => (
                  <li
                    key={`recent-${index}`}
                    className="suggestion-item"
                    onClick={() => handleRecentSearchClick(recent)}
                  >
                    <div className="suggestion-content">
                      <Search className="suggestion-icon" />
                      {recent}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      
      <div className="search-syntax-help">
        <span>Syntax: </span>
        <code className="syntax-code">name[|code[|number]]&#123;&amp;*~&#125;</code>
        <span> or </span>
        <code className="syntax-code">s:"Set Name"</code>
      </div>
    </div>
  )
}
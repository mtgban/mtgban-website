"use client"

import { useState, useEffect } from "react"
import SearchResults from "@/components/search/SearchResults"
import CardImage from "@/components/search/CardImage"
import SearchForm from "@/components/search/SearchForm"
import WelcomeContent, {HelpContent } from "@/components/search/Syntax"


// Define the card interface
interface Card {
  id: string;
  name?: string;
  printings?: string;
  products?: string;
  [key: string]: any;
}

// Define the search mode type
type SearchMode = 'retail' | 'buylist' | 'sealed';

export default function SearchPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [sortBy, setSortBy] = useState("chrono")
  const [reverseMode, setReverseMode] = useState(false)
  const [selectedCard, setSelectedCard] = useState<Card | null>(null)
  const [printings, setPrintings] = useState("")
  const [products, setProducts] = useState("")
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchMode, setSearchMode] = useState<SearchMode>('retail')

  // Fetch search results from backend
  useEffect(() => {
    if (!searchQuery) {
      setResults([]);
      return;
    }

    const fetchSearchResults = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Check if we're in development mode to handle missing API
        if (process.env.NODE_ENV !== "production") {
          // In development, simulate API response timing
          await new Promise(resolve => setTimeout(resolve, 500));
          setResults([]);
          setLoading(false);
          return;
        }

        // Construct the API URL with the correct path format
        const apiUrl = `/api/search-json/${searchMode}/${encodeURIComponent(searchQuery)}?sort=${sortBy}&reverse=${reverseMode ? 1 : 0}`;
        
        const response = await fetch(apiUrl);
        
        if (!response.ok) {
          throw new Error(`Search failed with status: ${response.status}`);
        }
        
        // Check content type to avoid JSON parse errors
        const contentType = response.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
          throw new Error("Search API did not return valid JSON");
        }
        
        const data = await response.json();
        
        if (data.success === false) {
          throw new Error(data.error || "Search failed");
        }
        
        setResults(data.results || []);
      } catch (err: any) {
        console.error("Search error:", err);
        setError(err.message || "Failed to perform search");
        setResults([]);
      } finally {
        setLoading(false);
      }
    };

    const timer = setTimeout(() => {
      fetchSearchResults();
    }, 300);

    return () => clearTimeout(timer);
  }, [searchQuery, sortBy, reverseMode, searchMode]);

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const handleSortChange = (sort: string) => {
    if (sort === sortBy) {
      setReverseMode(!reverseMode);
    } else {
      setSortBy(sort);
      setReverseMode(false);
    }
  };

  const handleModeChange = (mode: SearchMode) => {
    setSearchMode(mode);
  };

  const updateSidebar = (card: Card) => {
    setSelectedCard(card);
    setPrintings(card?.printings || "");
    setProducts(card?.products || "");
    
    // Optional: Fetch additional card details if needed
    if (card && card.id && process.env.NODE_ENV === "production") {
      fetchCardDetails(card.id);
    }
  };

  const fetchCardDetails = async (cardId: string) => {
    try {
      const response = await fetch(`/api/card/${cardId}`);
      if (response.ok) {
        const contentType = response.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
          console.error("Card details API did not return valid JSON");
          return;
        }
        
        const details = await response.json();
        setPrintings(formatPrintings(details.printings));
        setProducts(formatProducts(details.products));
      }
    } catch (err: any) {
      console.error("Error fetching card details:", err);
    }
  };

  const formatPrintings = (printingsData: any) => {
    if (!printingsData || printingsData.length === 0) return "";
    return printingsData.map((p: any) => `${p.set} (${p.rarity})`).join(", ");
  };

  const formatProducts = (productsData: any) => {
    if (!productsData || productsData.length === 0) return "";
    return productsData.map((p: any) => p.name).join(", ");
  };

  const downloadCSV = () => {
    const downloadUrl = `/api/search/${searchMode}/${encodeURIComponent(searchQuery)}?sort=${sortBy}&reverse=${reverseMode ? 1 : 0}`;
    window.open(downloadUrl, '_blank');
  };

  return (
    <div className="min-h-screen">
      {/* Glassmorphism background effect */}
      <div className="bg-gradient">
        <div className="bg-pattern"></div>
        <div className="backdrop-blur"></div>
      </div>

      <div className="page-layout">
        {/* Menu bar - Purple */}
        <div className="menu-bar glass-card">
          <h1 className="site-title text-gradient">MTG Price Search</h1>
          <div className="menu-actions">
            <button className="nav-link">Options</button>
            <button className="nav-link">Help</button>
          </div>
        </div>

        {/* Search section - Green */}
        <div className="search-section glass-card">
          <div className="card-inner">
            <SearchForm onSearch={handleSearch} />
            
            {searchQuery && (
              <div className="search-controls">
                <div className="mode-controls">
                  <span className="control-label">Mode:</span>
                  <button 
                    className={`mode-option ${searchMode === 'retail' ? 'active' : ''}`}
                    onClick={() => handleModeChange('retail')}
                  >
                    Retail
                  </button>
                  
                  <button 
                    className={`mode-option ${searchMode === 'buylist' ? 'active' : ''}`}
                    onClick={() => handleModeChange('buylist')}
                  >
                    Buylist
                  </button>
                  
                  <button 
                    className={`mode-option ${searchMode === 'sealed' ? 'active' : ''}`}
                    onClick={() => handleModeChange('sealed')}
                  >
                    Sealed
                  </button>
                  
                  <button 
                    className="download-csv"
                    onClick={downloadCSV}
                    title="Download results as CSV"
                  >
                    Download CSV
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Quick reference help section - Blue */}
        <HelpContent />

        {/* Card image section - Orange */}
        <div className="card-image-section glass-card">
          <div className="card-inner">
            <div className="card-image-container">
              <CardImage card={selectedCard} />
            </div>
            
            {selectedCard && (
              <div className="card-details">
                {printings && (
                  <div className="card-section">
                    <h3 className="section-title">Printings</h3>
                    <div className="section-content">{printings}</div>
                  </div>
                )}
                
                {products && (
                  <div className="card-section">
                    <h3 className="section-title">Available In</h3>
                    <div className="section-content">{products}</div>
                  </div>
                )}
                
                <div className="card-actions">
                  <button className="btn btn-secondary">
                    <span className="icon">📊</span>
                    Price History
                  </button>
                  <button 
                    className="btn btn-secondary"
                    onClick={() => window.open(`/card/${selectedCard.id}`, '_blank')}
                  >
                    <span className="icon">🔗</span>
                    View Details
                  </button>
                </div>
              </div>
            )}
            
            {!selectedCard && (
              <div className="empty-card-message">
                Select a card to view details
              </div>
            )}
          </div>
        </div>

        {/* Results section - Yellow */}
        <div className="results-section glass-card">
          <div className="card-inner">
            <div className="results-header">
              <h2 className="section-title">
                {searchQuery ? `Results for "${searchQuery}"` : "Welcome to MTG Price Search"}
              </h2>
              
              {searchQuery && (
                <div className="sort-controls">
                  <span className="sort-label">Sort by:</span>
                  <button 
                    className={`sort-option ${sortBy === 'chrono' ? 'active' : ''}`}
                    onClick={() => handleSortChange('chrono')}
                  >
                    chrono
                    {sortBy === 'chrono' && (
                      <span className="sort-indicator">
                        {reverseMode ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                  
                  <button 
                    className={`sort-option ${sortBy === 'alpha' ? 'active' : ''}`}
                    onClick={() => handleSortChange('alpha')}
                  >
                    alpha
                    {sortBy === 'alpha' && (
                      <span className="sort-indicator">
                        {reverseMode ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                  
                  <button 
                    className={`sort-option ${sortBy === 'retail' ? 'active' : ''}`}
                    onClick={() => handleSortChange('retail')}
                  >
                    retail
                    {sortBy === 'retail' && (
                      <span className="sort-indicator">
                        {reverseMode ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                  
                  <button 
                    className={`sort-option ${sortBy === 'buylist' ? 'active' : ''}`}
                    onClick={() => handleSortChange('buylist')}
                  >
                    buylist
                    {sortBy === 'buylist' && (
                      <span className="sort-indicator">
                        {reverseMode ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                </div>
              )}
            </div>

            <div className="results-content">
              {!searchQuery ? (
                <WelcomeContent />
              ) : (
                <SearchResults 
                  searchQuery={searchQuery} 
                  sortBy={sortBy} 
                  reverseMode={reverseMode}
                  onCardSelect={updateSidebar}
                  results={results}
                  loading={loading}
                  error={error}
                />
              )}
            </div>
          </div>
        </div>
      </div>

      <footer className="site-footer">
        <div className="container text-center">
          <p>© {new Date().getFullYear()} MTGBAN - Prices updated daily</p>
        </div>
      </footer>
    </div>
  )
}
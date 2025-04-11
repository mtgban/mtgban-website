"use client"

export default function SearchResults({ 
  searchQuery, 
  sortBy, 
  reverseMode, 
  onCardSelect,
  results = [],
  loading = false,
  error = null
}: {
  searchQuery: string,
  sortBy: string,
  reverseMode: boolean,
  onCardSelect: (card: any) => void,
  results: any[],
  loading: boolean,
  error: string | null
}) {
  if (loading) {
    return (
      <div className="glass-card">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p className="loading-text">Searching...</p>
          <div className="progress-container">
            <div className="progress-bar" style={{ width: '60%' }}></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card">
        <div className="error-container">
          <p className="error-title">Error</p>
          <p className="error-message">{error}</p>
          <button className="btn btn-secondary retry-button">Try Again</button>
        </div>
      </div>
    );
  }

  if (results.length === 0) {
    return (
      <div className="glass-card">
        <div className="empty-container">
          <p className="empty-title">No results found</p>
          <p className="empty-message">Try adjusting your search terms</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="results-container">
      <div className="results-count">
        Found {results.length} {results.length === 1 ? 'result' : 'results'} for "{searchQuery}"
      </div>
      
      {results.map((card, idx) => (
        <div 
          key={`${card.id}-${idx}`}
          className="result-card glass-card"
          onClick={() => onCardSelect(card)}
        >
          <div className="result-content">
            <div className="result-header">
              <div className="set-icon">
                {card.setCode}
              </div>
              
              <div className="card-info">
                <h3 className="card-name">
                  {card.name}
                  {card.foil && <span className="card-tag foil">FOIL</span>}
                  {card.etched && <span className="card-tag etched">ETCHED</span>}
                  {card.extended && <span className="card-tag extended">EXTENDED</span>}
                </h3>
                <p className="card-set">
                  {card.setName} • #{card.collectorNumber}
                </p>
              </div>
              
              <div className="card-actions">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(card.name);
                  }}
                  className="action-button"
                  title="Copy card name"
                >
                  <span className="action-icon">📋</span>
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    window.open(`https://scryfall.com/search?q=${encodeURIComponent(card.name)}`, '_blank');
                  }}
                  className="action-button"
                  title="View on Scryfall"
                >
                  <span className="action-icon">📚</span>
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    window.open(`/api/chart/${card.id}`, '_blank');
                  }}
                  className="action-button"
                  title="View price history"
                >
                  <span className="action-icon">📊</span>
                </button>
              </div>
            </div>
            
            <div className="price-tables">
              {/* Sellers Table */}
              <div className="price-table-container">
                <h4 className="table-title">
                  Sellers {card.sellers?.length > 0 ? `(${card.sellers.length})` : ''}
                </h4>
                
                {card.sellers?.length > 0 ? (
                  <table className="price-table">
                    <tbody>
                      {card.sellers.map((seller: any, index: number) => (
                        <tr key={index} className="price-row">
                          <td className="seller-name">
                            {seller.name}
                            {seller.country && (
                              <span className="seller-country">{seller.country}</span>
                            )}
                            {seller.affiliate && (
                              <span className="seller-tag affiliate">affiliate</span>
                            )}
                          </td>
                          <td className="seller-price">
                            ${seller.price.toFixed(2)}
                          </td>
                          <td className="seller-condition">
                            {seller.condition}
                            {seller.quantity > 0 && (
                              <span className="seller-quantity">x{seller.quantity}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-table-message">No seller data available</div>
                )}
              </div>
              
              {/* Buyers Table */}
              <div className="price-table-container">
                <h4 className="table-title">
                  Buyers {card.buyers?.length > 0 ? `(${card.buyers.length})` : ''}
                </h4>
                
                {card.buyers?.length > 0 ? (
                  <table className="price-table">
                    <tbody> 
                      {card.buyers.map((buyer: any, index: number) => (
                        <tr key={index} className="price-row">
                          <td className="buyer-name">
                            {buyer.name}
                            {buyer.country && (
                              <span className="buyer-country">{buyer.country}</span>
                            )}
                            {buyer.affiliate && (
                              <span className="buyer-tag affiliate">affiliate</span>
                            )}
                          </td>
                          <td className="buyer-price">
                            ${buyer.price.toFixed(2)}
                          </td>
                          <td className="buyer-condition">
                            {buyer.condition}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-table-message">No buylist data available</div>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
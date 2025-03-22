/**
 * Search API service to interface with Go backend
 */

/**
 * Fetch search results from the Go backend
 */
export async function fetchSearchResults(query: string, options: {
    page?: number;
    sort?: string;
    reverse?: boolean;
    filters?: Record<string, any>;
  }) {
    try {
      // Build search query params in the format expected by Go backend
      const params = new URLSearchParams();
      params.set('q', query);
      
      if (options.page && options.page > 1) {
        params.set('p', options.page.toString());
      }
      
      if (options.sort) {
        params.set('sort', options.sort);
      }
      
      if (options.reverse) {
        params.set('reverse', 'true');
      }
      
      // Add filters in the format expected by Go backend
      if (options.filters) {
        if (options.filters.condition) params.set('cond', options.filters.condition);
        if (options.filters.rarity) params.set('r', options.filters.rarity);
        if (options.filters.color) params.set('c', options.filters.color);
        if (options.filters.finish) params.set('f', options.filters.finish);
        if (options.filters.type) params.set('t', options.filters.type);
        if (options.filters.edition) params.set('s', options.filters.edition);
        if (options.filters.collectorNumber) params.set('cn', options.filters.collectorNumber);
        
        if (options.filters.price?.min) params.set('price_min', options.filters.price.min.toString());
        if (options.filters.price?.max) params.set('price_max', options.filters.price.max.toString());
        
        // Handle stores as expected by Go backend (multiple 'store' params)
        if (options.filters.stores && Array.isArray(options.filters.stores)) {
          options.filters.stores.forEach(store => {
            params.append('store', store);
          });
        }
      }
      
      // Make the request to the Go backend API
      const response = await fetch(`/api/search?${params.toString()}`);
      
      if (!response.ok) {
        throw new Error(`Search request failed with status ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Search API error:', error);
      throw error;
    }
  }
  
  /**
   * Fetch chart data for a specific card
   */
  export async function fetchChartData(cardId: string) {
    try {
      const response = await fetch(`/api/search/chart/${cardId}`);
      
      if (!response.ok) {
        throw new Error(`Chart data request failed with status ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Chart API error:', error);
      throw error;
    }
  }
  
  /**
   * Download search results as CSV
   */
  export function downloadSearchResultsCSV(query: string, options: {
    type: 'retail' | 'buylist';
    isSealed?: boolean;
  }) {
    // Go backend uses specific URL pattern for CSV downloads
    const baseUrl = `/api/search/${options.type}`;
    const sealedPath = options.isSealed ? '/sealed' : '';
    const encodedQuery = encodeURIComponent(query);
    
    // Construct final URL
    const downloadUrl = `${baseUrl}${sealedPath}/${encodedQuery}`;
    
    // Trigger download by navigating to URL
    window.location.href = downloadUrl;
  }
  
  /**
   * Fetch last sold data from TCGPlayer
   */
  export async function fetchLastSoldData(cardId: string) {
    try {
      const response = await fetch(`/api/tcgplayer/lastsold/${cardId}`);
      
      if (!response.ok) {
        throw new Error(`Last sold data request failed with status ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Last sold API error:', error);
      throw error;
    }
  }
  
  /**
   * Get search suggestions for autocomplete
   */
  export async function fetchSearchSuggestions(query: string, isSealed: boolean = false) {
    try {
      const params = new URLSearchParams({
        q: query,
        sealed: isSealed ? 'true' : 'false'
      });
      
      const response = await fetch(`/api/suggest?${params.toString()}`);
      
      if (!response.ok) {
        throw new Error(`Suggestion request failed with status ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.error('Suggestion API error:', error);
      throw error;
    }
  }
  
  /**
   * Load TCGPlayer decklist
   */
  export function downloadTCGPlayerDecklist(uuid: string) {
    window.location.href = `/api/tcgplayer/decklist/${uuid}`;
  }
  
  export default {
    fetchSearchResults,
    fetchChartData,
    downloadSearchResultsCSV,
    fetchLastSoldData,
    fetchSearchSuggestions,
    downloadTCGPlayerDecklist
  };
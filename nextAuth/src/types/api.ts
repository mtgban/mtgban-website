/**
 * API response structure
 */
export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
    meta?: Record<string, any>;
  }
  
  /**
   * Card data structure
   */
  export interface Card {
    id: string;
    name: string;
    set_code: string;
    set_name: string;
    number: string;
    rarity: string;
    image_url?: string;
    foil: boolean;
    etched: boolean;
    reserved: boolean;
    prices?: Record<string, number>;
    metadata?: Record<string, any>;
    stocks_url?: string;
    identifiers?: Record<string, string>;
  }
  
  /**
   * Price source data
   */
  export interface PriceSource {
    source: string;
    price: number;
    condition: string;
    url?: string;
    in_stock: boolean;
    quantity?: number;
  }
  
  /**
   * Set information
   */
  export interface MtgSet {
    name: string;
    code: string;
    date: string;
    keyrune: string;
    size: number;
    special: boolean;
    show_fin: boolean;
    has_reg: boolean;
    has_foil: boolean;
    rarities?: string[];
    colors?: string[];
  }
  
  /**
   * Edition list structure
   */
  export interface EditionList {
    editionSort: string[];
    editionList: Record<string, MtgSet[]>;
  }
  
  /**
   * Price trend data point
   */
  export interface TrendDataPoint {
    date: string;
    price: number;
    source: string;
  }
  
  /**
   * Arbitrage opportunity
   */
  export interface ArbitrageOpportunity {
    card_id: string;
    name: string;
    set_name: string;
    buy_price: number;
    sell_price: number;
    spread: number;
    profit: number;
    buy_source: string;
    sell_source: string;
    buy_url?: string;
    sell_url?: string;
    condition: string;
  }
  
  /**
   * User favorite data
   */
  export interface UserFavorite {
    card_id: string;
    added_date: string;
    card: Card;
  }
  
  /**
   * User history item
   */
  export interface UserHistoryItem {
    id: string;
    type: 'search' | 'view';
    query?: string;
    card_id?: string;
    timestamp: string;
    card?: Card;
  }
  
  /**
   * Upload status
   */
  export interface UploadStatus {
    upload_id: string;
    filename: string;
    status: 'processing' | 'completed' | 'failed';
    progress?: number;
    message?: string;
    result_url?: string;
    created_at: string;
    completed_at?: string;
    error?: string;
    card_count?: number;
    matched_count?: number;
  }
  
  /**
   * Pagination params
   */
  export interface PaginationParams {
    page: number;
    pageSize: number;
  }
  
  /**
   * Search filters
   */
  export interface SearchFilters {
    sets?: string[];
    rarities?: string[];
    colors?: string[];
    types?: string[];
    reserved?: boolean;
    foil?: boolean;
    etched?: boolean;
    minPrice?: number;
    maxPrice?: number;
  }
  
  /**
   * API client for making requests to the MTG Price API
   */
  export class MtgPriceApi {
    private baseUrl: string;
    
    constructor(baseUrl = '/api/v1') {
      this.baseUrl = baseUrl;
    }
    
    /**
     * Make an API request
     */
    private async request<T>(
      endpoint: string, 
      options?: RequestInit
    ): Promise<ApiResponse<T>> {
      const url = `${this.baseUrl}${endpoint}`;
      
      try {
        const response = await fetch(url, {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            ...options?.headers,
          },
          credentials: 'include', // Include cookies for authentication
        });
        
        const data: ApiResponse<T> = await response.json();
        
        if (!response.ok) {
          throw new Error(data.error || 'An error occurred');
        }
        
        return data;
      } catch (error) {
        console.error('API request failed:', error);
        return {
          success: false,
          error: error instanceof Error ? error.message : 'An unknown error occurred',
        };
      }
    }
    
    /**
     * Get cards with pagination and filtering
     */
    async getCards(
      params: PaginationParams & SearchFilters = { page: 0, pageSize: 20 }
    ): Promise<ApiResponse<Card[]>> {
      const queryParams = new URLSearchParams();
      
      // Add pagination params
      queryParams.append('page', params.page.toString());
      queryParams.append('pageSize', params.pageSize.toString());
      
      // Add filter params
      if (params.sets && params.sets.length > 0) {
        params.sets.forEach(set => queryParams.append('set', set));
      }
      
      if (params.rarities && params.rarities.length > 0) {
        params.rarities.forEach(rarity => queryParams.append('rarity', rarity));
      }
      
      if (params.colors && params.colors.length > 0) {
        params.colors.forEach(color => queryParams.append('color', color));
      }
      
      if (params.types && params.types.length > 0) {
        params.types.forEach(type => queryParams.append('type', type));
      }
      
      if (params.reserved) {
        queryParams.append('reserved', 'true');
      }
      
      if (params.foil) {
        queryParams.append('foil', 'true');
      }
      
      if (params.etched) {
        queryParams.append('etched', 'true');
      }
      
      if (params.minPrice) {
        queryParams.append('minPrice', params.minPrice.toString());
      }
      
      if (params.maxPrice) {
        queryParams.append('maxPrice', params.maxPrice.toString());
      }
      
      return this.request<Card[]>(`/cards?${queryParams.toString()}`);
    }
    
    /**
     * Get a specific card by ID
     */
    async getCard(cardId: string): Promise<ApiResponse<Card>> {
      return this.request<Card>(`/cards/${cardId}`);
    }
    
    /**
     * Get prices for multiple cards
     */
    async getPrices(
      cardIds: string[],
      sources?: string[],
      includeOutOfStock = false
    ): Promise<ApiResponse<Record<string, PriceSource[]>>> {
      const queryParams = new URLSearchParams();
      
      cardIds.forEach(id => queryParams.append('id', id));
      
      if (sources && sources.length > 0) {
        sources.forEach(source => queryParams.append('source', source));
      }
      
      if (includeOutOfStock) {
        queryParams.append('includeOutOfStock', 'true');
      }
      
      return this.request<Record<string, PriceSource[]>>(`/prices?${queryParams.toString()}`);
    }
    
    /**
     * Get all prices for a specific card
     */
    async getCardPrices(cardId: string): Promise<ApiResponse<PriceSource[]>> {
      return this.request<PriceSource[]>(`/prices/${cardId}`);
    }
    
    /**
     * Search for cards
     */
    async search(
      query: string,
      params: PaginationParams & SearchFilters = { page: 0, pageSize: 20 }
    ): Promise<ApiResponse<Card[]>> {
      const queryParams = new URLSearchParams();
      
      queryParams.append('q', query);
      queryParams.append('page', params.page.toString());
      queryParams.append('pageSize', params.pageSize.toString());
      
      // Add filter params
      if (params.sets && params.sets.length > 0) {
        params.sets.forEach(set => queryParams.append('set', set));
      }
      
      if (params.rarities && params.rarities.length > 0) {
        params.rarities.forEach(rarity => queryParams.append('rarity', rarity));
      }
      
      if (params.colors && params.colors.length > 0) {
        params.colors.forEach(color => queryParams.append('color', color));
      }
      
      if (params.types && params.types.length > 0) {
        params.types.forEach(type => queryParams.append('type', type));
      }
      
      if (params.reserved) {
        queryParams.append('reserved', 'true');
      }
      
      if (params.foil) {
        queryParams.append('foil', 'true');
      }
      
      if (params.etched) {
        queryParams.append('etched', 'true');
      }
      
      if (params.minPrice) {
        queryParams.append('minPrice', params.minPrice.toString());
      }
      
      if (params.maxPrice) {
        queryParams.append('maxPrice', params.maxPrice.toString());
      }
      
      return this.request<Card[]>(`/search?${queryParams.toString()}`);
    }
    
    /**
     * Get autocomplete suggestions for card names
     */
    async getAutocompleteSuggestions(query: string): Promise<ApiResponse<string[]>> {
      return this.request<string[]>(`/autocomplete?q=${encodeURIComponent(query)}`);
    }
    
    /**
     * Get all sets
     */
    async getSets(sortBy?: 'name' | 'size' | 'date'): Promise<ApiResponse<EditionList>> {
      const queryParams = new URLSearchParams();
      
      if (sortBy) {
        queryParams.append('sort', sortBy);
      }
      
      return this.request<EditionList>(`/sets?${queryParams.toString()}`);
    }
    
    /**
     * Get sealed product sets
     */
    async getSealedSets(): Promise<ApiResponse<EditionList>> {
      return this.request<EditionList>('/sets?sealed=true');
    }
    
    /**
     * Get details for a specific set
     */
    async getSetDetails(setCode: string): Promise<ApiResponse<MtgSet>> {
      return this.request<MtgSet>(`/sets/${setCode}`);
    }
    
    /**
     * Get arbitrage opportunities
     */
    async getArbitrageData(
      source?: string,
      target?: string,
      minSpread = 10.0,
      minPrice = 1.0
    ): Promise<ApiResponse<ArbitrageOpportunity[]>> {
      const queryParams = new URLSearchParams();
      
      if (source) {
        queryParams.append('source', source);
      }
      
      if (target) {
        queryParams.append('target', target);
      }
      
      queryParams.append('minSpread', minSpread.toString());
      queryParams.append('minPrice', minPrice.toString());
      
      return this.request<ArbitrageOpportunity[]>(`/analytics/arbitrage?${queryParams.toString()}`);
    }
    
    /**
     * Get price trend data for a card
     */
    async getTrendData(
      cardId: string,
      period: 'week' | 'month' | 'year' | 'all' = 'month'
    ): Promise<ApiResponse<TrendDataPoint[]>> {
      return this.request<TrendDataPoint[]>(
        `/analytics/trends?id=${cardId}&period=${period}`
      );
    }
    
    /**
     * Get user's search/view history
     */
    async getUserHistory(
      type?: 'search' | 'view',
      limit = 20
    ): Promise<ApiResponse<UserHistoryItem[]>> {
      const queryParams = new URLSearchParams();
      
      if (type) {
        queryParams.append('type', type);
      }
      
      queryParams.append('limit', limit.toString());
      
      return this.request<UserHistoryItem[]>(`/user/history?${queryParams.toString()}`);
    }
    
    /**
     * Clear user's history
     */
    async clearUserHistory(
      type?: 'search' | 'view'
    ): Promise<ApiResponse<{ cleared: boolean }>> {
      const queryParams = new URLSearchParams();
      
      if (type) {
        queryParams.append('type', type);
      }
      
      return this.request<{ cleared: boolean }>(
        `/user/history?${queryParams.toString()}`,
        { method: 'DELETE' }
      );
    }
    
    /**
     * Upload a card list file
     */
    async uploadCardList(
      file: File,
      type: 'inventory' | 'buylist'
    ): Promise<ApiResponse<{ uploadId: string; status: string }>> {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('type', type);
      
      return this.request<{ uploadId: string; status: string }>('/upload', {
        method: 'POST',
        body: formData,
        headers: {}, // Let browser set content-type with boundary
      });
    }
    
    /**
     * Get upload status
     */
    async getUploadStatus(uploadId: string): Promise<ApiResponse<UploadStatus>> {
      return this.request<UploadStatus>(`/upload/${uploadId}`);
    }
  }
  
  // Create and export a default instance of the API client
  const mtgPriceApi = new MtgPriceApi();
  export default mtgPriceApi;
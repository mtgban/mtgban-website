  "use client"

  import { useState, useCallback, useEffect, useMemo } from 'react'
  import { useRouter } from 'next/router'

  // Define types for search filters
  export interface PriceRange {
    min?: number
    max?: number
  }

  export interface SearchFilters {
    sort?: string
    reverse?: boolean
    condition?: string
    rarity?: string
    color?: string
    finish?: string
    type?: string
    edition?: string
    collectorNumber?: string
    price: PriceRange
    stores: string[]
  }

  // Define the search status type
  export type SearchStatus = 'idle' | 'loading' | 'success' | 'error';

  // Define the search state interface
  export interface SearchState {
    query: string
    filters: SearchFilters
    page: number
    status: SearchStatus
    results: any | null  // Will be populated with Go server response
    error: string | null
    isInitialized: boolean
  }

  // Create default filters
  const createDefaultFilters = (): SearchFilters => ({
    sort: "",
    reverse: false,
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
  });

  // Create initial state
  const createInitialState = (initialQuery: string = ""): SearchState => ({
    query: initialQuery,
    filters: createDefaultFilters(),
    page: 1,
    status: 'idle',
    results: null,
    error: null,
    isInitialized: false,
  });

  /**
   * Custom hook for search functionality integrated with Go backend
   * @param initialQuery - Initial search query
   */
  export function useSearch(initialQuery: string = "") {
    const router = useRouter()
    
    // Get initial filters from URL params
    const getInitialFilters = (): SearchFilters => {
      return {
        sort: typeof router.query.sort === 'string' ? router.query.sort : undefined,
        reverse: router.query.reverse === 'true',
        condition: typeof router.query.cond === 'string' ? router.query.cond : undefined,
        rarity: typeof router.query.r === 'string' ? router.query.r : undefined,
        color: typeof router.query.c === 'string' ? router.query.c : undefined,
        finish: typeof router.query.f === 'string' ? router.query.f : undefined,
        price: {
          min: router.query.price_min ? Number(router.query.price_min) : undefined,
          max: router.query.price_max ? Number(router.query.price_max) : undefined,
        },
        stores: Array.isArray(router.query.store) ? router.query.store : 
          typeof router.query.store === 'string' ? [router.query.store] : [],
      }
    }
    
    // State
    const [state, setState] = useState<SearchState>(createInitialState(initialQuery));
    
    // Parse URL parameters when router is ready
    useEffect(() => {
      if (!router.isReady) return;
      
      // Extract query parameters - Go server uses these exact query param names
      const { 
        q, sort, reverse, p, cond, r, c, f, t, s, cn, 
        price_min, price_max, store 
      } = router.query;
      
      // Process stores param which may be array or string in Go's implementation
      let storesArray: string[] = [];
      if (store) {
        storesArray = Array.isArray(store) ? store : [store as string];
      }
      
      // Create new filters based on URL parameters
      const newFilters: SearchFilters = {
        sort: (sort as string) || state.filters.sort,
        reverse: reverse === "true" || false,
        condition: (cond as string) || state.filters.condition,
        rarity: (r as string) || state.filters.rarity,
        color: (c as string) || state.filters.color,
        finish: (f as string) || state.filters.finish,
        type: (t as string) || state.filters.type,
        edition: (s as string) || state.filters.edition,
        collectorNumber: (cn as string) || state.filters.collectorNumber,
        price: {
          min: price_min ? Number(price_min) : state.filters.price.min,
          max: price_max ? Number(price_max) : state.filters.price.max,
        },
        stores: storesArray || state.filters.stores,
      };
      
      // Update state with URL parameters
      setState(prev => ({
        ...prev,
        query: (q as string) || initialQuery,
        filters: newFilters,
        page: p ? Number(p) : 1,
        isInitialized: true,
      }));
    }, [router.isReady, router.query, initialQuery]);
    
    // Generate URL query string based on current state - must match Go's expected format
    const queryString = useMemo(() => {
      const queryParams = new URLSearchParams();
      
      if (state.query) queryParams.set('q', state.query);
      if (state.filters.sort) queryParams.set('sort', state.filters.sort);
      if (state.filters.reverse) queryParams.set('reverse', String(state.filters.reverse));
      if (state.page > 1) queryParams.set('p', String(state.page));
      if (state.filters.condition) queryParams.set('cond', state.filters.condition);
      if (state.filters.rarity) queryParams.set('r', state.filters.rarity);
      if (state.filters.color) queryParams.set('c', state.filters.color);
      if (state.filters.finish) queryParams.set('f', state.filters.finish);
      if (state.filters.type) queryParams.set('t', state.filters.type);
      if (state.filters.edition) queryParams.set('s', state.filters.edition);
      if (state.filters.collectorNumber) queryParams.set('cn', state.filters.collectorNumber);
      if (state.filters.price.min) queryParams.set('price_min', String(state.filters.price.min));
      if (state.filters.price.max) queryParams.set('price_max', String(state.filters.price.max));
      
      // Add stores as 'store' param - this matches Go's expectation
      state.filters.stores.forEach(store => {
        queryParams.append('store', store);
      });
      
      return queryParams.toString();
    }, [state]);
    
    // Update URL when parameters change - use shallow routing
    useEffect(() => {
      if (!state.isInitialized || !state.query) return;
      
      const timeoutId = setTimeout(() => {
        router.push(`${router.pathname}?${queryString}`, undefined, { shallow: true });
      }, 300);
      
      return () => clearTimeout(timeoutId);
    }, [queryString, router, state.isInitialized, state.query]);
    
    // Set search query
    const setQuery = useCallback((query: string) => {
      setState(prev => ({
        ...prev,
        query,
        page: 1, // Reset page when query changes
      }));
    }, []);
    
    // Set search filters
    const setFilters = useCallback((filters: Partial<SearchFilters>) => {
      setState(prev => ({
        ...prev,
        filters: {
          ...prev.filters,
          ...filters,
        },
        page: 1, // Reset page when filters change
      }));
    }, []);
    
    // Set page number
    const setPage = useCallback((page: number) => {
      setState(prev => ({
        ...prev,
        page,
      }));
    }, []);
    
    // Execute search via the Go backend API
    const executeSearch = useCallback(async () => {
      if (!state.query) return;
      
      setState(prev => ({ ...prev, status: 'loading' }));
      
      try {
        // Format query string compatible with Go backend
        const searchParams = new URLSearchParams();
        searchParams.set('q', state.query);
        searchParams.set('p', String(state.page));
        
        if (state.filters.sort) searchParams.set('sort', state.filters.sort);
        if (state.filters.reverse) searchParams.set('reverse', 'true');
        if (state.filters.condition) searchParams.set('cond', state.filters.condition);
        if (state.filters.rarity) searchParams.set('r', state.filters.rarity);
        if (state.filters.color) searchParams.set('c', state.filters.color);
        if (state.filters.finish) searchParams.set('f', state.filters.finish);
        if (state.filters.type) searchParams.set('t', state.filters.type);
        if (state.filters.edition) searchParams.set('s', state.filters.edition);
        if (state.filters.collectorNumber) searchParams.set('cn', state.filters.collectorNumber);
        
        if (state.filters.price.min) searchParams.set('price_min', String(state.filters.price.min));
        if (state.filters.price.max) searchParams.set('price_max', String(state.filters.price.max));
        
        // Add stores as multiple 'store' parameters - this matches Go's API
        state.filters.stores.forEach(store => {
          searchParams.append('store', store);
        });
        
        // Call the Go API endpoint
        const response = await fetch(`/api/search?${searchParams.toString()}`);
        
        if (!response.ok) {
          throw new Error(`Search failed: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Update state with search results from Go API
        setState(prev => ({
          ...prev,
          status: 'success',
          results: data,
          error: null,
        }));
      } catch (error) {
        setState(prev => ({
          ...prev,
          status: 'error',
          error: error instanceof Error ? error.message : "An unknown error occurred",
        }));
      }
    }, [state.query, state.filters, state.page]);
    
    // Extract and expose what the Go API returns in a more accessible way
    const extractedResults = useMemo(() => {
      if (!state.results) return null;
      
      return {
        allKeys: state.results.AllKeys || [],
        metadata: state.results.Metadata || {},
        foundSellers: state.results.FoundSellers || {},
        foundVendors: state.results.FoundVendors || {},
        condKeys: state.results.CondKeys || [],
        totalResults: state.results.TotalUnique || 0,
      };
    }, [state.results]);
    
    // Execute search when dependencies change
    useEffect(() => {
      if (state.query && state.isInitialized) {
        executeSearch();
      }
    }, [state.query, state.filters, state.page, state.isInitialized, executeSearch]);
    
    // Reset search state
    const resetSearch = useCallback(() => {
      setState(prev => ({
        ...createInitialState(),
        isInitialized: prev.isInitialized,
      }));
    }, []);
    
    return {
      // State
      query: state.query,
      filters: state.filters,
      page: state.page,
      results: extractedResults,
      status: state.status,
      error: state.error,
      isLoading: state.status === 'loading',
      isError: state.status === 'error',
      isSuccess: state.status === 'success',
      
      // Raw results for debugging
      rawResults: state.results,
      
      // Actions
      setQuery,
      setFilters,
      setPage,
      executeSearch,
      resetSearch,
      
      // Computed
      hasResults: !!extractedResults?.allKeys.length,
      totalResults: extractedResults?.totalResults || 0,
      isEmpty: state.status === 'success' && (!extractedResults?.allKeys.length),
    };
  }

  export default useSearch;
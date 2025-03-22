"use client"

import { useReducer, useCallback, useEffect, useMemo } from "react"
import { useRouter } from "next/router"

// Define more specific types for search filters
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

// Define the search state with a discriminated union for loading states
export type SearchStatus = 'idle' | 'loading' | 'success' | 'error';

export interface SearchResult {
  id: string;
  title: string;
  metadata: GenericCard;
  sellers: Record<string, SearchEntry[]>;
  vendors: Record<string, SearchEntry[]>;
}

export interface SearchState {
  query: string
  filters: SearchFilters
  page: number
  status: SearchStatus
  results: SearchResult[]
  totalResults: number
  error: string | null
}

// Define action types using discriminated unions for type safety
type SearchAction = 
  | { type: 'SET_QUERY'; payload: string }
  | { type: 'SET_FILTERS'; payload: Partial<SearchFilters> }
  | { type: 'SET_PAGE'; payload: number }
  | { type: 'SET_LOADING' }
  | { type: 'SET_RESULTS'; payload: { results: any[]; totalResults: number } }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'RESET_STATE'; payload?: { query?: string } };

// Initial state for the search
const createInitialState = (initialQuery: string = ''): SearchState => ({
  query: initialQuery,
  filters: {
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
  },
  page: 1,
  status: 'idle',
  results: [],
  totalResults: 0,
  error: null,
});

// Search reducer for state management
const searchReducer = (state: SearchState, action: SearchAction): SearchState => {
  switch (action.type) {
    case 'SET_QUERY':
      return {
        ...state,
        query: action.payload,
        page: 1, // Reset page when query changes
      };
    case 'SET_FILTERS':
      return {
        ...state,
        filters: {
          ...state.filters,
          ...action.payload,
        },
        page: 1, // Reset page when filters change
      };
    case 'SET_PAGE':
      return {
        ...state,
        page: action.payload,
      };
    case 'SET_LOADING':
      return {
        ...state,
        status: 'loading',
      };
    case 'SET_RESULTS':
      return {
        ...state,
        results: action.payload.results,
        totalResults: action.payload.totalResults,
        status: 'success',
        error: null,
      };
    case 'SET_ERROR':
      return {
        ...state,
        error: action.payload,
        status: 'error',
      };
    case 'RESET_STATE':
      return {
        ...createInitialState(action.payload?.query || ''),
      };
    default:
      return state;
  }
};

/**
 * Custom hook for managing search state
 * @param initialQuery - Initial search query
 */
export const useSearchState = (initialQuery = "") => {
  const router = useRouter();
  const [state, dispatch] = useReducer(searchReducer, initialQuery, createInitialState);

  // Parse query parameters from URL when router is ready
  useEffect(() => {
    if (!router.isReady) return;

    const { 
      q, sort, reverse, p, cond, r, c, f, t, s, cn, 
      price_min, price_max, stores 
    } = router.query;

    // Convert URL parameters to state
    const newFilters: Partial<SearchFilters> = {
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
      stores: stores 
        ? (Array.isArray(stores) ? stores : [stores as string]) 
        : state.filters.stores,
    };

    // Update state based on URL parameters
    dispatch({ type: 'SET_QUERY', payload: (q as string) || initialQuery });
    dispatch({ type: 'SET_FILTERS', payload: newFilters });
    dispatch({ type: 'SET_PAGE', payload: p ? Number(p) : 1 });
  }, [router.isReady, router.query, initialQuery]);

  // Create URL query string based on current state
  const queryString = useMemo(() => {
    const query: Record<string, string | string[] | boolean> = {};

    if (state.query) query.q = state.query;
    if (state.filters.sort) query.sort = state.filters.sort;
    if (state.filters.reverse) query.reverse = state.filters.reverse;
    if (state.page > 1) query.p = String(state.page);
    if (state.filters.condition) query.cond = state.filters.condition;
    if (state.filters.rarity) query.r = state.filters.rarity;
    if (state.filters.color) query.c = state.filters.color;
    if (state.filters.finish) query.f = state.filters.finish;
    if (state.filters.type) query.t = state.filters.type;
    if (state.filters.edition) query.s = state.filters.edition;
    if (state.filters.collectorNumber) query.cn = state.filters.collectorNumber;
    if (state.filters.price.min) query.price_min = String(state.filters.price.min);
    if (state.filters.price.max) query.price_max = String(state.filters.price.max);
    if (state.filters.stores.length > 0) query.stores = state.filters.stores;

    return new URLSearchParams(
      Object.entries(query).flatMap(([key, value]) => {
        if (Array.isArray(value)) {
          return value.map(v => [key, v]);
        }
        return [[key, String(value)]];
      })
    ).toString();
  }, [state]);

  // Update URL when state changes (debounced)
  useEffect(() => {
    if (!state.query) return;
    
    const updateUrl = () => {
      router.push(
        { pathname: router.pathname, query: router.query.q ? queryString : {} },
        undefined,
        { shallow: true }
      );
    };
    
    const timeoutId = setTimeout(updateUrl, 300);
    return () => clearTimeout(timeoutId);
  }, [queryString, router, state.query]);

  // Action creators as callbacks
  const setQuery = useCallback((query: string) => {
    dispatch({ type: 'SET_QUERY', payload: query });
  }, []);

  const setFilters = useCallback((filters: Partial<SearchFilters>) => {
    dispatch({ type: 'SET_FILTERS', payload: filters });
  }, []);

  const setPage = useCallback((page: number) => {
    dispatch({ type: 'SET_PAGE', payload: page });
  }, []);

  // Execute search
  const executeSearch = useCallback(async () => {
    if (!state.query) return;

    dispatch({ type: 'SET_LOADING' });

    try {
      // Format query to include filters
      const formattedQuery = buildFormattedQuery(state.query, state.filters);
      
      // Execute search request
      const response = await fetch(
        `/api/search?q=${encodeURIComponent(formattedQuery)}&p=${state.page}&sort=${state.filters.sort}&reverse=${state.filters.reverse}`,
        {
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          signal: AbortSignal.timeout(8000), // Timeout after 8 seconds
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      dispatch({ 
        type: 'SET_RESULTS', 
        payload: { 
          results: data.results || [], 
          totalResults: data.totalResults || 0 
        } 
      });
    } catch (error) {
      dispatch({ 
        type: 'SET_ERROR', 
        payload: error instanceof Error ? error.message : "An unknown error occurred" 
      });
    }
  }, [state.query, state.filters, state.page]);

  // Build formatted query with filters
  const buildFormattedQuery = (query: string, filters: SearchFilters): string => {
    const parts: string[] = [query.trim()];

    if (filters.condition) parts.push(`condition:${filters.condition}`);
    if (filters.rarity) parts.push(`rarity:${filters.rarity}`);
    if (filters.color) parts.push(`color:${filters.color}`);
    if (filters.finish) parts.push(`finish:${filters.finish}`);
    if (filters.type) parts.push(`type:${filters.type}`);
    if (filters.edition) parts.push(`set:${filters.edition}`);
    if (filters.collectorNumber) parts.push(`number:${filters.collectorNumber}`);
    
    if (filters.price.min !== undefined) parts.push(`price>=${filters.price.min}`);
    if (filters.price.max !== undefined) parts.push(`price<=${filters.price.max}`);
    
    if (filters.stores.length > 0) {
      parts.push(`store:(${filters.stores.join(' OR ')})`);
    }

    return parts.join(' ');
  };

  // Execute search when dependencies change
  useEffect(() => {
    if (state.query) {
      executeSearch();
    }
  }, [state.query, state.filters, state.page, executeSearch]);

  return {
    searchState: state,
    setQuery,
    setFilters,
    setPage,
    executeSearch,
    // Additional helpers
    isLoading: state.status === 'loading',
    isError: state.status === 'error',
    hasResults: state.status === 'success' && state.results.length > 0,
    resetState: useCallback((options?: { query?: string }) => {
      dispatch({ type: 'RESET_STATE', payload: options });
    }, []),
  };
};

export default useSearchState;
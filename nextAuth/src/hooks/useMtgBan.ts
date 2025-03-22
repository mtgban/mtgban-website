import { useState, useEffect, useCallback } from 'react';
import mtgPriceApi, {
  ApiResponse,
  Card,
  PriceSource,
  EditionList,
  MtgSet,
  ArbitrageOpportunity,
  TrendDataPoint,
  UserFavorite,
  UserHistoryItem,
  UploadStatus,
  PaginationParams,
  SearchFilters
} from './api-models';

/**
 * Hook response including loading and error states
 */
interface HookResponse<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  meta?: Record<string, any>;
  refetch: () => Promise<void>;
}

/**
 * Hook to fetch cards with pagination and filtering
 */
export function useCards(
  params: PaginationParams & SearchFilters = { page: 0, pageSize: 20 }
): HookResponse<Card[]> {
  const [data, setData] = useState<Card[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<Record<string, any> | undefined>(undefined);

  const fetchCards = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getCards(params);
      
      if (response.success) {
        setData(response.data || null);
        setMeta(response.meta);
      } else {
        setError(response.error || 'Failed to fetch cards');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    fetchCards();
  }, [fetchCards]);

  return { data, loading, error, meta, refetch: fetchCards };
}

/**
 * Hook to fetch a specific card by ID
 */
export function useCard(cardId: string): HookResponse<Card> {
  const [data, setData] = useState<Card | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCard = useCallback(async () => {
    if (!cardId) {
      setError('Card ID is required');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getCard(cardId);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch card');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [cardId]);

  useEffect(() => {
    fetchCard();
  }, [fetchCard]);

  return { data, loading, error, refetch: fetchCard };
}

/**
 * Hook to search for cards
 */
export function useCardSearch(
  query: string,
  params: PaginationParams & SearchFilters = { page: 0, pageSize: 20 }
): HookResponse<Card[]> {
  const [data, setData] = useState<Card[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false); // Don't load immediately
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<Record<string, any> | undefined>(undefined);

  const search = useCallback(async () => {
    if (!query || query.length < 2) {
      setData(null);
      setError('Search query must be at least 2 characters');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.search(query, params);
      
      if (response.success) {
        setData(response.data || null);
        setMeta(response.meta);
      } else {
        setError(response.error || 'Search failed');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [query, params]);

  useEffect(() => {
    if (query && query.length >= 2) {
      search();
    }
  }, [search, query]);

  return { data, loading, error, meta, refetch: search };
}

/**
 * Hook to get price data for a card
 */
export function useCardPrices(cardId: string): HookResponse<PriceSource[]> {
  const [data, setData] = useState<PriceSource[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPrices = useCallback(async () => {
    if (!cardId) {
      setError('Card ID is required');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getCardPrices(cardId);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch prices');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [cardId]);

  useEffect(() => {
    fetchPrices();
  }, [fetchPrices]);

  return { data, loading, error, refetch: fetchPrices };
}

/**
 * Hook to get autocomplete suggestions
 */
export function useAutocomplete(query: string): HookResponse<string[]> {
  const [data, setData] = useState<string[] | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSuggestions = useCallback(async () => {
    if (!query || query.length < 2) {
      setData(null);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getAutocompleteSuggestions(query);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch suggestions');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (query && query.length >= 2) {
        fetchSuggestions();
      } else {
        setData(null);
      }
    }, 300); // Debounce

    return () => clearTimeout(timeoutId);
  }, [fetchSuggestions, query]);

  return { data, loading, error, refetch: fetchSuggestions };
}

/**
 * Hook to get all sets
 */
export function useSets(sortBy?: 'name' | 'size' | 'date'): HookResponse<EditionList> {
  const [data, setData] = useState<EditionList | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<Record<string, any> | undefined>(undefined);

  const fetchSets = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getSets(sortBy);
      
      if (response.success) {
        setData(response.data || null);
        setMeta(response.meta);
      } else {
        setError(response.error || 'Failed to fetch sets');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [sortBy]);

  useEffect(() => {
    fetchSets();
  }, [fetchSets]);

  return { data, loading, error, meta, refetch: fetchSets };
}

/**
 * Hook to get sealed product sets
 */
export function useSealedSets(): HookResponse<EditionList> {
  const [data, setData] = useState<EditionList | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [meta, setMeta] = useState<Record<string, any> | undefined>(undefined);

  const fetchSealedSets = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getSealedSets();
      
      if (response.success) {
        setData(response.data || null);
        setMeta(response.meta);
      } else {
        setError(response.error || 'Failed to fetch sealed sets');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSealedSets();
  }, [fetchSealedSets]);

  return { data, loading, error, meta, refetch: fetchSealedSets };
}

/**
 * Hook to get set details
 */
export function useSetDetails(setCode: string): HookResponse<MtgSet> {
  const [data, setData] = useState<MtgSet | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSetDetails = useCallback(async () => {
    if (!setCode) {
      setError('Set code is required');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getSetDetails(setCode);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch set details');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [setCode]);

  useEffect(() => {
    fetchSetDetails();
  }, [fetchSetDetails]);

  return { data, loading, error, refetch: fetchSetDetails };
}

/**
 * Hook to get arbitrage opportunities
 */
export function useArbitrageData(
  source?: string,
  target?: string,
  minSpread = 10.0,
  minPrice = 1.0
): HookResponse<ArbitrageOpportunity[]> {
  const [data, setData] = useState<ArbitrageOpportunity[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchArbitrageData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getArbitrageData(source, target, minSpread, minPrice);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch arbitrage data');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [source, target, minSpread, minPrice]);

  useEffect(() => {
    fetchArbitrageData();
  }, [fetchArbitrageData]);

  return { data, loading, error, refetch: fetchArbitrageData };
}

/**
 * Hook to get price trend data for a card
 */
export function useTrendData(
  cardId: string,
  period: 'week' | 'month' | 'year' | 'all' = 'month'
): HookResponse<TrendDataPoint[]> {
  const [data, setData] = useState<TrendDataPoint[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTrendData = useCallback(async () => {
    if (!cardId) {
      setError('Card ID is required');
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getTrendData(cardId, period);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch trend data');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [cardId, period]);

  useEffect(() => {
    fetchTrendData();
  }, [fetchTrendData]);

  return { data, loading, error, refetch: fetchTrendData };
}

/**
 * Hook to get user's search/view history
 */
export function useUserHistory(
  type?: 'search' | 'view',
  limit = 20
): HookResponse<UserHistoryItem[]> & {
  clearHistory: (historyType?: 'search' | 'view') => Promise<boolean>;
} {
  const [data, setData] = useState<UserHistoryItem[] | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getUserHistory(type, limit);
      
      if (response.success) {
        setData(response.data || null);
      } else {
        setError(response.error || 'Failed to fetch history');
        setData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [type, limit]);

  const clearHistory = useCallback(async (historyType?: 'search' | 'view'): Promise<boolean> => {
    try {
      const response = await mtgPriceApi.clearUserHistory(historyType);
      
      if (response.success) {
        fetchHistory(); // Refresh the list
        return true;
      } else {
        setError(response.error || 'Failed to clear history');
        return false;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      return false;
    }
  }, [fetchHistory]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  return { 
    data, 
    loading, 
    error, 
    refetch: fetchHistory,
    clearHistory
  };
}

/**
 * Hook to upload a card list and track its status
 */
export function useCardListUpload() {
  const [uploadId, setUploadId] = useState<string | null>(null);
  const [status, setStatus] = useState<UploadStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const uploadCardList = useCallback(async (
    file: File,
    type: 'inventory' | 'buylist'
  ): Promise<string | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.uploadCardList(file, type);
      
      if (response.success && response.data) {
        setUploadId(response.data.uploadId);
        return response.data.uploadId;
      } else {
        setError(response.error || 'Upload failed');
        return null;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const checkStatus = useCallback(async (id: string): Promise<UploadStatus | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await mtgPriceApi.getUploadStatus(id);
      
      if (response.success && response.data) {
        setStatus(response.data);
        return response.data;
      } else {
        setError(response.error || 'Failed to get upload status');
        return null;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Poll for status if we have an uploadId
  useEffect(() => {
    if (!uploadId) return;

    const intervalId = setInterval(async () => {
      const currentStatus = await checkStatus(uploadId);
      
      if (currentStatus && ['completed', 'failed'].includes(currentStatus.status)) {
        clearInterval(intervalId);
      }
    }, 2000); // Poll every 2 seconds

    return () => clearInterval(intervalId);
  }, [uploadId, checkStatus]);

  return { 
    uploadCardList, 
    checkStatus, 
    uploadId, 
    status, 
    loading, 
    error 
  };
}
import { useQuery, useMutation, useQueryClient, QueryKey } from 'react-query';
import { useGoData } from '@/context/GoDataContext';
import { callGoFunction } from '@/utils/GoNextBridge';

/**
 * Helper function to create a React Query key that includes auth information
 * This ensures queries are properly invalidated when user auth changes
 */
export function createGoQueryKey(baseKey: QueryKey): QueryKey {
  const { user } = useGoData();
  // Include user info in the query key to ensure cache is user-specific
  return [baseKey, { userId: user.email }];
}

/**
 * Custom hook for fetching data from Go backend with React Query
 * Automatically includes auth information from GoDataContext
 */
export function useGoQuery<TData = unknown>(
  queryKey: QueryKey,
  url: string,
  options?: {
    queryParams?: Record<string, string | number | boolean>;
    enabled?: boolean;
    staleTime?: number;
    cacheTime?: number;
    refetchInterval?: number | false;
    onSuccess?: (data: TData) => void;
    onError?: (error: Error) => void;
  }
) {
  const { user, features } = useGoData();
  
  // Get the full query key including auth info
  const fullQueryKey = createGoQueryKey(queryKey);
  
  // Build the complete URL with query parameters
  const buildUrl = () => {
    if (!options?.queryParams) return url;
    
    const params = new URLSearchParams();
    Object.entries(options.queryParams).forEach(([key, value]) => {
      params.append(key, String(value));
    });
    
    return `${url}${url.includes('?') ? '&' : '?'}${params.toString()}`;
  };
  
  // Fetch function that handles authentication and error handling
  const fetchData = async (): Promise<TData> => {
    const response = await fetch(buildUrl(), {
      headers: {
        'Accept': 'application/json',
        // Add any auth headers if needed
        ...(user.isLoggedIn && { 'X-User-Email': user.email }),
      },
      // Include credentials for session cookies
      credentials: 'include',
    });
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.message || `Request failed with status ${response.status}`
      );
    }
    
    return response.json();
  };
  
  // Use React Query's useQuery with our enhanced fetch function
  return useQuery<TData, Error>(
    fullQueryKey,
    fetchData,
    {
      // Enable the query based on auth status and features if needed
      enabled: options?.enabled !== false && user.isLoggedIn,
      // Default stale time to 5 minutes unless specified
      staleTime: options?.staleTime || 5 * 60 * 1000,
      // Cache time defaults to 10 minutes
      cacheTime: options?.cacheTime || 10 * 60 * 1000,
      // Don't refetch by default unless specified
      refetchInterval: options?.refetchInterval || false,
      // Pass through success and error callbacks
      onSuccess: options?.onSuccess,
      onError: options?.onError,
    }
  );
}

/**
 * Custom hook for mutations (POST, PUT, DELETE) with Go backend
 */
export function useGoMutation<TData = unknown, TVariables = unknown>(
  url: string,
  options?: {
    method?: 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    invalidateQueries?: QueryKey[];
    onSuccess?: (data: TData) => void;
    onError?: (error: Error) => void;
  }
) {
  const { user } = useGoData();
  const queryClient = useQueryClient();
  
  // Mutation function that sends data to the Go backend
  const mutationFn = async (variables: TVariables): Promise<TData> => {
    const response = await fetch(url, {
      method: options?.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // Add any auth headers if needed
        ...(user.isLoggedIn && { 'X-User-Email': user.email }),
      },
      body: JSON.stringify(variables),
      credentials: 'include',
    });
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.message || `Mutation failed with status ${response.status}`
      );
    }
    
    return response.json();
  };
  
  // Use React Query's useMutation with our enhanced mutation function
  return useMutation<TData, Error, TVariables>(mutationFn, {
    onSuccess: (data) => {
      // Invalidate relevant queries when mutation succeeds
      if (options?.invalidateQueries) {
        options.invalidateQueries.forEach(queryKey => {
          queryClient.invalidateQueries(createGoQueryKey(queryKey));
        });
      }
      
      // Call the success callback if provided
      if (options?.onSuccess) {
        options.onSuccess(data);
      }
    },
    onError: options?.onError,
  });
}

/**
 * Custom hook to handle Go search functionality in a React Query compatible way
 * @param query Search query string
 * @returns React Query result object
 */
export function useGoSearch(query: string) {
  return useQuery(
    ['search', query],
    async () => {
      if (!query) return null
      
      // If window.search_cards exists (Go backend), call it directly
      if (typeof window !== 'undefined' && window.search_cards) {
        try {
          return await callGoFunction('search_cards', query)
        } catch (error) {
          console.error('Error calling Go search function:', error)
          throw new Error('Failed to search using Go backend')
        }
      }
      
      // Fallback to API route if Go function doesn't exist
      try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`)
        if (!response.ok) {
          throw new Error(`Search API returned ${response.status}`)
        }
        return await response.json()
      } catch (error) {
        console.error('Error fetching search results:', error)
        throw new Error('Failed to search')
      }
    },
    {
      // Don't refetch on window focus
      refetchOnWindowFocus: false,
      // Keep previous data while fetching new data
      keepPreviousData: true,
      // Don't auto-fetch if query is empty
      enabled: !!query,
      // Stale time to prevent too frequent refetches
      staleTime: 1000 * 60 * 5, // 5 minutes
    }
  )
}

export default {
  useGoQuery,
  useGoMutation,
  useGoSearch,
  createGoQueryKey,
};
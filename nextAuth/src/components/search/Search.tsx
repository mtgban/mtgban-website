'use client'

import Head from 'next/head'
import { useRouter } from 'next/router'
import ErrorBoundary from '@/components/utility/ErrorBoundary'
import SearchForm from '@/components/search/SearchForm'
import CardResults from '@/components/search/CardResults'
import Instructions from '@/components/search/Instructions'
import { useGoData } from '@/context/GoDataContext'
import { useGoSearch } from '@/hooks/useGoQuery'
import { LiveRegion } from '@/components/utility/Accessibility'
import type { GenericCard, SearchEntry } from '@/types/pageVars'
import type { GoPageData } from '@/types/go/pageVars'

// Define search data interface
interface SearchData {
  allKeys: string[];
  metadata: Record<string, GenericCard>;
  foundSellers: Record<string, Record<string, SearchEntry[]>>;
  foundVendors: Record<string, Record<string, SearchEntry[]>>;
  condKeys: string[];
  totalResults: number;
}

// Create a default empty search data object
const emptySearchData: SearchData = {
  allKeys: [],
  metadata: {},
  foundSellers: {},
  foundVendors: {},
  condKeys: [],
  totalResults: 0
}

/**
 * Search page component that uses GoData and React Query
 */
export default function SearchPage() {
  const router = useRouter()
  
  // Get data from Go backend via context
  const { pageData, features, user } = useGoData()
  
  // Helper to get params safely
  const getParam = (key: string): string => {
    const value = router.query[key];
    return typeof value === 'string' ? value : '';
  }

  // Get initial query from URL or Go template data
  const initialQuery = getParam('q') || (pageData?.searchQuery as string) || ''
  
  // Use React Query for search functionality
  const searchQuery = useGoSearch(initialQuery)
  
  // Extract search data from either API response or Go template
  const searchData: SearchData = searchQuery.data || {
    allKeys: pageData?.allKeys as string[] || [],
    metadata: pageData?.metadata as Record<string, GenericCard> || {},
    foundSellers: pageData?.foundSellers as Record<string, Record<string, SearchEntry[]>> || {},
    foundVendors: pageData?.foundVendors as Record<string, Record<string, SearchEntry[]>> || {},
    condKeys: pageData?.condKeys as string[] || [],
    totalResults: pageData?.totalUnique as number || 0
  }
  
  // Create URL with updated search params
  const createUrlWithParams = (params: Record<string, string>): {pathname: string; query: any} => {
    const newParams = { ...router.query };
    
    // Update or remove params
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined || value === null || value === '') {
        delete newParams[key];
      } else {
        newParams[key] = value;
      }
    });
    
    return {
      pathname: router.pathname,
      query: newParams
    };
  }
  
  // Handle page change
  const handlePageChange = (page: number) => {
    router.push(createUrlWithParams({ p: page.toString() }));
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  
  // Check if this is the sealed search page
  const isSealed = !!pageData?.isSealed || router.pathname === '/sealed'
  
  // Determine the page title
  const pageTitle = isSealed
    ? "MTG Sealed Product Search"
    : "MTG Card Search"
    
  // Check permissions
  const canDownloadCSV = !!features?.DownloadCSV || false
  
  return (
    <>
      <Head>
        <title>
          {`${pageTitle}${initialQuery ? ` - ${initialQuery}` : ''}`}
        </title>
      </Head>
      
      <ErrorBoundary>
        <div className="search-page">
          {/* Search Form */}
          <SearchForm
            searchQuery={initialQuery}
            isSealed={isSealed}
            searchSort={getParam('sort') || (pageData?.searchSort as string) || ''}
            noSort={!!pageData?.noSort || false}
            reverseMode={getParam('reverse') === 'true' || !!pageData?.reverseMode || false}
            filters={{
              sort: getParam('sort') || '',
              reverse: getParam('reverse') === 'true',
              // Other filters from URL or Go data
              condition: getParam('cond') || '',
              rarity: getParam('r') || '',
              color: getParam('c') || '',
              finish: getParam('f') || '',
              price: {
                min: getParam('price_min') ? Number(getParam('price_min')) : undefined,
                max: getParam('price_max') ? Number(getParam('price_max')) : undefined,
              },
              stores: Array.isArray(router.query.store) 
                ? router.query.store 
                : getParam('store') ? [getParam('store')] : [],
            }}
            onQueryChange={(query) => {
              // Reset page to 1 on new query
              router.push(createUrlWithParams({ q: query, p: '1' }));
            }}
            onFilterChange={(filters) => {
              const newParams: Record<string, string> = {
                p: '1', // Reset page when filters change
              }
              
              if (filters.sort !== undefined) newParams.sort = filters.sort
              if (filters.reverse !== undefined) newParams.reverse = String(filters.reverse)
              if (filters.condition !== undefined) newParams.cond = filters.condition
              if (filters.rarity !== undefined) newParams.r = filters.rarity
              if (filters.color !== undefined) newParams.c = filters.color
              if (filters.finish !== undefined) newParams.f = filters.finish
              if (filters.price?.min !== undefined) newParams.price_min = String(filters.price.min)
              if (filters.price?.max !== undefined) newParams.price_max = String(filters.price.max)
              
              router.push(createUrlWithParams(newParams));
            }}
            onSearch={() => {
              // Force a refetch of search results
              searchQuery.refetch()
            }}
          />
          
          {/* Search status for screen readers */}
          <LiveRegion ariaLive="polite">
            {searchQuery.isLoading ? 'Searching...' : 
              searchQuery.isSuccess ? `Found ${searchData.totalResults} results.` : 
              searchQuery.isError ? `Error: ${(searchQuery.error as Error)?.message}` : ''}
          </LiveRegion>
          
          {/* Search results */}
          {initialQuery ? (
            <>
              {/* Stats bar */}
              {searchData.totalResults > 0 && (
                <div className="search-stats">
                  <p>
                    Found {searchData.totalResults} {isSealed ? 'product' : 'card'}
                    {searchData.totalResults !== 1 ? 's' : ''}
                  </p>
                </div>
              )}
              
              {/* Loading state */}
              {searchQuery.isLoading && !searchData.allKeys.length && (
                <div className="loading-state">
                  <div className="loading-spinner large"></div>
                  <p>Searching for {isSealed ? 'products' : 'cards'}...</p>
                </div>
              )}
              
              {/* Empty state */}
              {searchQuery.isSuccess && !searchData.allKeys.length && (
                <div className="empty-state">
                  <h2>No {isSealed ? 'products' : 'cards'} found</h2>
                  <p>Try adjusting your search criteria or check your spelling.</p>
                </div>
              )}
              
              {/* Error state */}
              {searchQuery.isError && (
                <div className="error-state">
                  <h2>Error</h2>
                  <p>{(searchQuery.error as Error)?.message || 'An unknown error occurred'}</p>
                </div>
              )}
              
              {/* Results */}
              {searchData.allKeys.length > 0 && (
                <CardResults
                  allKeys={searchData.allKeys}
                  metadata={searchData.metadata}
                  foundSellers={searchData.foundSellers}
                  foundVendors={searchData.foundVendors}
                  condKeys={searchData.condKeys}
                  chartID={(pageData?.chartID as string) || getParam('chart') || ''}
                  axisLabels={(pageData?.axisLabels as string[]) || []}
                  datasets={(pageData?.datasets as any[]) || []}
                  isSealed={isSealed}
                  firstImg={searchData.metadata[searchData.allKeys[0]]?.ImageURL || ''}
                  firstPrint={searchData.metadata[searchData.allKeys[0]]?.Printings || ''}
                  firstProduct={searchData.metadata[searchData.allKeys[0]]?.Products || ''}
                  setFirstImg={() => {}} // Will be handled by the component
                  setFirstPrint={() => {}}
                  setFirstProduct={() => {}}
                  alternative={(pageData?.alternative as string) || ''}
                  altEtchedId={(pageData?.altEtchedId as string) || ''}
                  stocksURL={(pageData?.stocksURL as string) || ''}
                  canShowAll={!!pageData?.canShowAll || false}
                  hasAvailable={!!pageData?.hasAvailable || false}
                  hasReserved={!!pageData?.hasReserved || false}
                  hasStocks={!!pageData?.hasStocks || false}
                  hasSypList={!!pageData?.hasSypList || false}
                  showSYP={!!pageData?.showSYP || false}
                  showUpsell={!user?.isLoggedIn || !canDownloadCSV}
                  canDownloadCSV={canDownloadCSV}
                  cardHashes={(pageData?.cardHashes as string[]) || []}
                  currentIndex={Number(getParam('p')) || 1}
                  totalIndex={Math.ceil(searchData.totalResults / 20)} // 20 items per page
                  prevIndex={Math.max(1, (Number(getParam('p')) || 1) - 1)}
                  nextIndex={Math.min(
                    Math.ceil(searchData.totalResults / 20), 
                    (Number(getParam('p')) || 1) + 1
                  )}
                  infoMessage={(pageData?.infoMessage as string) || ''}
                  searchSort={getParam('sort') || ''}
                  reverseMode={getParam('reverse') === 'true'}
                  disableChart={!!pageData?.disableChart || false}
                  hash={(pageData?.hash as string) || ''}
                  searchQuery={initialQuery}
                  onPageChange={handlePageChange}
                />
              )}
            </>
          ) : (
            // Show instructions when no search query
            <Instructions promoTags={(pageData?.promoTags as string[]) || []} />
          )}
        </div>
      </ErrorBoundary>
    </>
  )
}
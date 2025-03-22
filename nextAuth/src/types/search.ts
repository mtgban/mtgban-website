// Types for search components that interface with Go backend

import type { GenericCard, SearchEntry, ChartDataset } from './pageVars'

export interface SearchPageProps {
  title?: string
  searchQuery?: string
  cleanSearchQuery?: string
  errorMessage?: string
  isSealed?: boolean
  totalUnique?: number
  totalCards?: number
  allKeys?: string[]
  metadata?: Record<string, GenericCard>
  foundSellers?: Record<string, Record<string, SearchEntry[]>>
  foundVendors?: Record<string, Record<string, SearchEntry[]>>
  condKeys?: string[]
  chartID?: string
  axisLabels?: string[]
  datasets?: ChartDataset[]
  alternative?: string
  altEtchedId?: string
  stocksURL?: string
  cardBackURL?: string
  hash?: string
  canShowAll?: boolean
  hasAvailable?: boolean
  hasReserved?: boolean
  hasStocks?: boolean
  hasSypList?: boolean
  showSYP?: boolean
  showUpsell?: boolean
  canDownloadCSV?: boolean
  cardHashes?: string[]
  currentIndex?: number
  totalIndex?: number
  prevIndex?: number
  nextIndex?: number
  infoMessage?: string
  searchSort?: string
  reverseMode?: boolean
  noSort?: boolean
  disableChart?: boolean
  editionSort?: string[]
  editionList?: Record<string, EditionEntry[]>
  promoTags?: string[]
}

export interface CardResultsProps {
  allKeys: string[]
  metadata: Record<string, GenericCard>
  foundSellers: Record<string, Record<string, SearchEntry[]>>
  foundVendors: Record<string, Record<string, SearchEntry[]>>
  condKeys: string[]
  chartID?: string
  axisLabels?: string[]
  datasets?: ChartDataset[]
  isSealed: boolean
  firstImg?: string
  firstPrint?: string
  firstProduct?: string
  setFirstImg: (img: string) => void
  setFirstPrint: (print: string) => void
  setFirstProduct: (product: string) => void
  alternative?: string
  altEtchedId?: string
  stocksURL?: string
  canShowAll?: boolean
  hasAvailable?: boolean
  hasReserved?: boolean
  hasStocks?: boolean
  hasSypList?: boolean
  showSYP?: boolean
  showUpsell?: boolean
  canDownloadCSV?: boolean
  cardHashes?: string[]
  currentIndex?: number
  totalIndex?: number
  prevIndex?: number
  nextIndex?: number
  infoMessage?: string
  searchSort?: string
  reverseMode?: boolean
  disableChart?: boolean
  hash?: string
  searchQuery: string
  onPageChange: (page: number) => void
}

export interface CardSidebarProps {
  firstImg?: string
  firstPrint?: string
  firstProduct?: string
  isSealed: boolean
  canShowAll?: boolean
  hasAvailable?: boolean
  alternative?: string
  altEtchedId?: string
  stocksURL?: string
  canDownloadCSV?: boolean
  cardHashes?: string[]
  showUpsell?: boolean
  hasReserved?: boolean
  hasStocks?: boolean
  hasSypList?: boolean
  chartID?: string
  searchQuery: string
}

export interface CardTableProps {
  allKeys: string[]
  metadata: Record<string, GenericCard>
  foundSellers: Record<string, Record<string, SearchEntry[]>>
  foundVendors: Record<string, Record<string, SearchEntry[]>>
  condKeys: string[]
  isSealed: boolean
  setFirstImg: (img: string) => void
  setFirstPrint: (print: string) => void
  setFirstProduct: (product: string) => void
  showSYP: boolean
  disableChart: boolean
  chartID?: string
}

export interface CardRowProps {
  cardId: string
  card: GenericCard
  foundSellers: Record<string, SearchEntry[]>
  foundVendors: Record<string, SearchEntry[]>
  condKeys: string[]
  isSealed: boolean
  setFirstImg: (img: string) => void
  setFirstPrint: (print: string) => void
  setFirstProduct: (product: string) => void
  showSYP: boolean
  disableChart: boolean
  chartID: string
}

export interface PriceTableProps {
  entries: Record<string, SearchEntry[]>
  condKeys: string[]
  isSealed: boolean
  cardId: string
  card: GenericCard
  isSeller: boolean
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
  price: {
    min?: number
    max?: number
  }
  stores: string[]
}

export interface FilterPanelProps {
  filters: SearchFilters
  onFilterChange: (filters: Partial<SearchFilters>) => void
  isSealed: boolean
  onClose: () => void
}

export interface PriceChartProps {
  chartID: string
  axisLabels?: string[]
  datasets?: ChartDataset[]
}

export interface PaginationProps {
  currentPage: number
  totalPages: number
  onPageChange: (page: number) => void
  searchQuery: string
  searchSort?: string
  reverseMode?: boolean
}

export interface SearchResult {
  id: string
  title: string
  metadata: GenericCard
  sellers: Record<string, SearchEntry[]>
  vendors: Record<string, SearchEntry[]>
}
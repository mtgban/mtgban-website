// Debounce function to limit how often a function can be called
export function debounce<T extends (...args: any[]) => any>(func: T, wait: number): (...args: Parameters<T>) => void {
    let timeout: NodeJS.Timeout | null = null
  
    return (...args: Parameters<T>) => {
      if (timeout) clearTimeout(timeout)
  
      timeout = setTimeout(() => {
        func(...args)
      }, wait)
    }
  }
  
  // Format price with currency symbol
  export function formatPrice(price: number): string {
    return `$${price.toFixed(2)}`
  }
  
  // Parse search query to extract special syntax
  export function parseSearchQuery(query: string): {
    baseQuery: string
    filters: Record<string, string>
  } {
    const filters: Record<string, string> = {}
  
    // Extract set code (s:CODE)
    const setMatch = query.match(/\bs:([^\s]+)/)
    if (setMatch) {
      filters.edition = setMatch[1]
    }
  
    // Extract collector number (cn:NUMBER)
    const cnMatch = query.match(/\bcn:([^\s]+)/)
    if (cnMatch) {
      filters.collectorNumber = cnMatch[1]
    }
  
    // Extract condition (cond:COND)
    const condMatch = query.match(/\bcond:([^\s]+)/)
    if (condMatch) {
      filters.condition = condMatch[1]
    }
  
    // Extract rarity (r:RARITY)
    const rarityMatch = query.match(/\br:([^\s]+)/)
    if (rarityMatch) {
      filters.rarity = rarityMatch[1]
    }
  
    // Extract color (c:COLOR)
    const colorMatch = query.match(/\bc:([^\s]+)/)
    if (colorMatch) {
      filters.color = colorMatch[1]
    }
  
    // Extract finish (f:VALUE)
    const finishMatch = query.match(/\bf:([^\s]+)/)
    if (finishMatch) {
      filters.finish = finishMatch[1]
    }
  
    // Extract type (t:VALUE)
    const typeMatch = query.match(/\bt:([^\s]+)/)
    if (typeMatch) {
      filters.type = typeMatch[1]
    }
  
    // Extract price range (price>VALUE, price<VALUE)
    const priceMinMatch = query.match(/\bprice>([^\s]+)/)
    if (priceMinMatch) {
      filters.priceMin = priceMinMatch[1]
    }
  
    const priceMaxMatch = query.match(/\bprice<([^\s]+)/)
    if (priceMaxMatch) {
      filters.priceMax = priceMaxMatch[1]
    }
  
    // Extract store filter (store:VALUE)
    const storeMatch = query.match(/\bstore:([^\s]+)/)
    if (storeMatch) {
      filters.store = storeMatch[1]
    }
  
    // Remove all filter syntax from the query to get the base query
    let baseQuery = query
    Object.keys(filters).forEach((key) => {
      const pattern = new RegExp(`\\b${key}:[^\\s]+`, "g")
      baseQuery = baseQuery.replace(pattern, "")
    })
  
    // Clean up extra spaces
    baseQuery = baseQuery.replace(/\s+/g, " ").trim()
  
    return {
      baseQuery,
      filters,
    }
  }
  
  // Generate a unique ID
  export function generateId(): string {
    return Math.random().toString(36).substring(2, 15)
  }
  
  // Check if an element is in viewport
  export function isInViewport(element: HTMLElement): boolean {
    const rect = element.getBoundingClientRect()
    return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    )
  }
  
  // Format date for display
  export function formatDate(dateString: string): string {
    const date = new Date(dateString)
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    }).format(date)
  }
  
  
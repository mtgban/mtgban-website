"use client"

import * as React from "react"
import { memo } from "react"
import type { CardTableProps } from "../../types/search"
import CardRow from "./CardRow"
import { useWindowSize } from "../../hooks/useWindowSize"
import { useAuth } from "../../hooks/useAuth"

// Fix component type with memo
function CardTableComponent({
  allKeys,
  metadata,
  foundSellers,
  foundVendors,
  condKeys,
  isSealed,
  setFirstImg,
  setFirstPrint,
  setFirstProduct,
  showSYP,
  disableChart,
  chartID,
}: CardTableProps) {
  // Get auth status to check feature permissions
  const { hasFeature } = useAuth()
  
  // Adaptively calculate items per page based on window height
  const { height } = useWindowSize()
  const itemsPerPage = React.useMemo(() => {
    const baseItems = Math.max(10, Math.floor((height ?? 800) / 150))
    // If user has premium features, allow more items per page for smoother experience
    return hasFeature('PremiumSearch') ? baseItems * 2 : baseItems
  }, [height, hasFeature])
  
  // State for tracking visible items with pagination
  const [visibleRange, setVisibleRange] = React.useState({ 
    start: 0, 
    end: Math.min(itemsPerPage, allKeys.length) 
  })
  
  // Refs for DOM elements and intersection observer
  const containerRef = React.useRef<HTMLDivElement>(null)
  const observerRef = React.useRef<IntersectionObserver | null>(null)
  const loadMoreRef = React.useRef<HTMLDivElement>(null)
  const loadingRef = React.useRef<boolean>(false)

  // Handle observation of load more element
  const handleObserver = React.useCallback(
    (entries: IntersectionObserverEntry[]) => {
      const [entry] = entries
      
      if (entry?.isIntersecting && !loadingRef.current) {
        loadingRef.current = true
        
        // Load more items when scroll reaches bottom indicator
        setTimeout(() => {
          setVisibleRange(prev => {
            const newEnd = Math.min(prev.end + itemsPerPage, allKeys.length)
            return { ...prev, end: newEnd }
          })
          loadingRef.current = false
        }, 300) // Add small timeout to prevent rapid firing
      }
    },
    [allKeys, itemsPerPage]
  )

  // Set up intersection observer for infinite scrolling
  React.useEffect(() => {
    if (!loadMoreRef.current) return
    
    // Clean up previous observer
    if (observerRef.current) {
      observerRef.current.disconnect()
    }
    
    observerRef.current = new IntersectionObserver(handleObserver, {
      root: null, // use viewport as root
      rootMargin: '0px',
      threshold: 0.1, // trigger when 10% visible
    })
    
    observerRef.current.observe(loadMoreRef.current)
    
    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect()
      }
    }
  }, [handleObserver, visibleRange.end, allKeys.length])

  // Reset visible range when allKeys changes (new search)
  React.useEffect(() => {
    setVisibleRange({ 
      start: 0, 
      end: Math.min(itemsPerPage, allKeys.length) 
    })
  }, [allKeys, itemsPerPage])

  // Memoize visible keys to prevent unnecessary calculations
  const visibleKeys = React.useMemo(() => 
    allKeys.slice(visibleRange.start, visibleRange.end),
    [allKeys, visibleRange.start, visibleRange.end]
  )

  // Reset hover image when mouse leaves table - this works with Go's template
  const handleMouseLeave = React.useCallback(() => {
    if (isSealed) {
      const hoverImage = document.getElementById("hoverImage") as HTMLImageElement
      if (hoverImage) {
        hoverImage.style.display = "none"
      }
    }
  }, [isSealed])
  
  // This function is used for compatibility with Go's direct DOM manipulations  
  const updateGlobalSidebar = React.useCallback((imgSrc: string, printingsHtml: string, productsHtml: string) => {
    // Update firstImg, firstPrint, firstProduct via props
    setFirstImg(imgSrc)
    setFirstPrint(printingsHtml)
    setFirstProduct(productsHtml)
    
    // Also update DOM directly for backwards compatibility with Go template code
    const imgElement: HTMLImageElement | null = document.getElementById("cardImg") as HTMLImageElement
    const printsElement: HTMLElement | null = document.getElementById("printings")
    const productsElement: HTMLElement | null = document.getElementById("products")
    
    if (imgElement) imgElement.src = imgSrc
    if (printsElement) printsElement.innerHTML = printingsHtml
    if (productsElement) productsElement.innerHTML = productsHtml
  }, [setFirstImg, setFirstPrint, setFirstProduct])

  // Empty state handling
  if (allKeys.length === 0) {
    return (
      <div className="empty-results">
        <p>No cards found matching your search criteria.</p>
      </div>
    )
  }

  return (
    <div className="card-table-container" ref={containerRef} onMouseLeave={handleMouseLeave}>
      <table
        className="card-table"
        aria-label="Card search results"
      >
        <thead>
          {allKeys && allKeys.length > 0 && (
            <tr>
              <th className="column-header sellers-header" scope="col">Sellers</th>
              <th className="column-header buyers-header" scope="col">Buyers</th>
              <th 
                className="column-header sales-header" 
                style={{ display: "none" }} 
                id="lastsalesth"
                scope="col"
              >
                Last Sales
              </th>
            </tr>
          )}
        </thead>

        <tbody>
          <tr style={{ height: 0 }}>
            <td colSpan={3}>
              <svg height="0" width="0" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <linearGradient 
                    id="gradient-foil" 
                    x1="0%" 
                    y1="0%" 
                    x2="100%" 
                    y2="0%" 
                    gradientTransform="rotate(45)"
                  >
                    <stop offset="4%" stopColor="#ea8d66" />
                    <stop offset="18%" stopColor="#fdef8a" />
                    <stop offset="42%" stopColor="#8bcc93" />
                    <stop offset="63%" stopColor="#a6dced" />
                    <stop offset="100%" stopColor="#e599c2" />
                  </linearGradient>
                </defs>
              </svg>
            </td>
          </tr>

          {visibleKeys.map((cardId) => {
            const card = metadata[cardId]
            return (
              <CardRow
                key={cardId}
                cardId={cardId}
                card={card}
                foundSellers={foundSellers[cardId] || {}}
                foundVendors={foundVendors[cardId] || {}}
                condKeys={condKeys}
                isSealed={isSealed}
                setFirstImg={(img: string) => updateGlobalSidebar(img, card.Printings, card.Products)}
                setFirstPrint={(print: string) => updateGlobalSidebar(card.ImageURL, print, card.Products)}
                setFirstProduct={(product: string) => updateGlobalSidebar(card.ImageURL, card.Printings, product)}
                showSYP={showSYP}
                disableChart={disableChart}
                chartID={chartID || ""}
              />
            )
          })}
        </tbody>
      </table>

      {visibleRange.end < allKeys.length && (
        <div ref={loadMoreRef} className="load-more-indicator">
          Loading more results...
        </div>
      )}
    </div>
  )
}

// Use memo to prevent unnecessary rerenders
const CardTable = memo(CardTableComponent)

export default CardTable
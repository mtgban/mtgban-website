"use client"

import * as React from "react"
import { useCallback } from "react"
import Link from "next/link"
import type { PaginationProps } from "../../types/search"

// Fix component type
function Pagination({ 
  currentPage, 
  totalPages, 
  onPageChange, 
  searchQuery, 
  searchSort = "",
  reverseMode = false 
}: PaginationProps) {
  // Get query string for pagination links
  const getPageUrl = useCallback(
    (page: number) => {
      const params = new URLSearchParams()
      params.set("q", searchQuery)
      params.set("p", String(page))
      
      if (searchSort) {
        params.set("sort", searchSort)
      }
      
      if (reverseMode) {
        params.set("reverse", "true")
      }
      
      return `?${params.toString()}`
    },
    [searchQuery, searchSort, reverseMode]
  )

  // Generate pagination buttons with proper ranges
  const renderPaginationButtons = useCallback(() => {
    const buttons = []
    const range = 2 // How many pages to show on each side of current page
    
    // Add first page
    if (currentPage > 1) {
      buttons.push(
        <Link
          key="first"
          href={getPageUrl(1)}
          className="pagination-button"
          onClick={(e) => {
            e.preventDefault()
            onPageChange(1)
          }}
        >
          First
        </Link>
      )
    }
    
    // Add previous page
    if (currentPage > 1) {
      buttons.push(
        <Link
          key="prev"
          href={getPageUrl(currentPage - 1)}
          className="pagination-button"
          onClick={(e) => {
            e.preventDefault()
            onPageChange(currentPage - 1)
          }}
        >
          &lt;
        </Link>
      )
    }
    
    // Calculate range to display
    let startPage = Math.max(1, currentPage - range)
    let endPage = Math.min(totalPages, currentPage + range)
    
    // Adjust if we're at the edges
    if (startPage <= 3) {
      endPage = Math.min(totalPages, 5)
      startPage = 1
    }
    
    if (endPage >= totalPages - 2) {
      startPage = Math.max(1, totalPages - 4)
      endPage = totalPages
    }
    
    // Add page numbers
    for (let i = startPage; i <= endPage; i++) {
      buttons.push(
        <Link
          key={i}
          href={getPageUrl(i)}
          className={`pagination-button ${i === currentPage ? "active" : ""}`}
          aria-current={i === currentPage ? "page" : undefined}
          onClick={(e) => {
            e.preventDefault()
            onPageChange(i)
          }}
        >
          {i}
        </Link>
      )
    }
    
    // Add next page
    if (currentPage < totalPages) {
      buttons.push(
        <Link
          key="next"
          href={getPageUrl(currentPage + 1)}
          className="pagination-button"
          onClick={(e) => {
            e.preventDefault()
            onPageChange(currentPage + 1)
          }}
        >
          &gt;
        </Link>
      )
    }
    
    // Add last page
    if (currentPage < totalPages) {
      buttons.push(
        <Link
          key="last"
          href={getPageUrl(totalPages)}
          className="pagination-button"
          onClick={(e) => {
            e.preventDefault()
            onPageChange(totalPages)
          }}
        >
          Last
        </Link>
      )
    }
    
    return buttons
  }, [currentPage, totalPages, getPageUrl, onPageChange])

  return (
    <div className="pagination">
      <div className="pagination-info">
        Page {currentPage} of {totalPages}
      </div>
      <div className="pagination-controls">{renderPaginationButtons()}</div>
    </div>
  )
}

export default Pagination


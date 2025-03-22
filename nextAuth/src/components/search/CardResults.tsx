"use client"

import * as React from "react"
import { useEffect, useRef, useCallback } from "react"
import type { CardResultsProps } from "@/types/search"
import PriceChart from "./PriceChart"
import CardSidebar from "./CardSidebar"
import CardTable from "./CardTable"
import Pagination from "./Pagination"

function CardResults({
  allKeys,
  metadata,
  foundSellers,
  foundVendors,
  condKeys,
  chartID,
  axisLabels,
  datasets,
  isSealed,
  firstImg,
  firstPrint,
  firstProduct,
  setFirstImg,
  setFirstPrint,
  setFirstProduct,
  alternative,
  altEtchedId,
  stocksURL,
  canShowAll,
  hasAvailable,
  hasReserved,
  hasStocks,
  hasSypList,
  showSYP = false,
  showUpsell,
  canDownloadCSV,
  cardHashes,
  currentIndex = 1,
  totalIndex = 1,
  prevIndex,
  nextIndex,
  infoMessage,
  searchSort,
  reverseMode,
  disableChart = false,
  hash,
  searchQuery,
  onPageChange,
}: CardResultsProps) {
  const resultsRef = useRef<HTMLDivElement>(null)

  // Initialize scripts
  useEffect(() => {
    const scriptSrcs = ["/js/copy2clip.js", "/js/updatesearch.js"]

    const scripts: HTMLScriptElement[] = []

    scriptSrcs.forEach((src) => {
      const script = document.createElement("script")
      script.src = `${src}?hash=${hash || ""}`
      script.async = true
      document.body.appendChild(script)
      scripts.push(script)
    })

    return () => {
      scripts.forEach((script) => {
        document.body.removeChild(script)
      })
    }
  }, [hash])

  // Scroll to top when page changes
  useEffect(() => {
    if (resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth" })
    }
  }, [currentIndex])

  // Handle page change
  const handlePageChange = useCallback(
    (page: number) => {
      onPageChange(page)
    },
    [onPageChange],
  )

  return (
    <div className="card-results" ref={resultsRef}>
      <div className="results-layout">
        <aside className="sidebar">
          <CardSidebar
            firstImg={firstImg || ""}
            firstPrint={firstPrint || ""}
            firstProduct={firstProduct || ""}
            isSealed={isSealed}
            canShowAll={!!canShowAll}
            hasAvailable={!!hasAvailable}
            alternative={alternative || ""}
            altEtchedId={altEtchedId || ""}
            stocksURL={stocksURL || ""}
            canDownloadCSV={!!canDownloadCSV}
            cardHashes={cardHashes || []}
            showUpsell={!!showUpsell}
            hasReserved={!!hasReserved}
            hasStocks={!!hasStocks}
            hasSypList={!!hasSypList}
            chartID={chartID || ""}
            searchQuery={searchQuery}
          />
        </aside>

        <div className="main-content">
          {chartID && (
            <div className="chart-container">
              <PriceChart 
                chartID={chartID} 
                axisLabels={axisLabels || []} 
                datasets={datasets || []} 
              />
            </div>
          )}

          <div className="results-table-container">
            <CardTable
              allKeys={allKeys}
              metadata={metadata}
              foundSellers={foundSellers}
              foundVendors={foundVendors}
              condKeys={condKeys}
              isSealed={isSealed}
              setFirstImg={setFirstImg}
              setFirstPrint={setFirstPrint}
              setFirstProduct={setFirstProduct}
              showSYP={!!showSYP}
              disableChart={!!disableChart}
              chartID={chartID}
            />
          </div>

          {totalIndex > 1 && (
            <Pagination
              currentPage={currentIndex}
              totalPages={totalIndex}
              onPageChange={handlePageChange}
              searchQuery={searchQuery}
              searchSort={searchSort || ""}
              reverseMode={!!reverseMode}
            />
          )}

          {infoMessage && (
            <div className="info-message">
              <p>{infoMessage}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default CardResults


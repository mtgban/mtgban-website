"use client"

import React, { useMemo, memo } from "react"
import type { PriceTableProps } from "../../types/search"
import { formatPrice } from "../../lib/api/helpers"

const PriceTable: React.FC<PriceTableProps> = ({ entries, condKeys, isSealed, cardId, card, isSeller }) => {
  // Memoize the table content to prevent unnecessary re-renders
  const tableContent = useMemo(() => {
    if (!entries || Object.keys(entries).length === 0) {
      return (
        <tr>
          <td colSpan={4} className="no-offers">
            <span>No offers</span>
          </td>
        </tr>
      )
    }

    return (
      <>
        {condKeys.map((condition) => {
          const condEntries = entries[condition] || []
          if (condEntries.length === 0) return null

          return (
            <React.Fragment key={condition}>
              {condition === "INDEX" && isSealed ? (
                <tr className="index-header">
                  <td></td>
                  <th className="ev-header">EV</th>
                  <th className="sim-median-header">Sim (Median)</th>
                  <th className="sim-stddev-header">Sim (StdDev)</th>
                </tr>
              ) : (
                condition !== "INDEX" && (
                  <tr className="condition-header">
                    <td colSpan={4} className="condition-label">
                      {isSealed ? (isSeller ? "Purchase from" : "Sell to") : `Condition: ${condition}`}
                    </td>
                  </tr>
                )
              )}

              {condEntries.map((entry, index) => (
                <tr key={index} className="price-entry">
                  <td className="store-name">
                    {entry.URL ? (
                      <a className="store-link" href={entry.URL} target="_blank" rel="noopener noreferrer">
                        {entry.ScraperName}
                        {condition !== "INDEX" && entry.Country && (
                          <span className="store-country">{entry.Country}</span>
                        )}
                      </a>
                    ) : (
                      <span className="store-name-text">
                        {entry.ScraperName}
                        {condition !== "INDEX" && entry.Country && (
                          <span className="store-country">{entry.Country}</span>
                        )}
                      </span>
                    )}
                  </td>

                  {condition === "INDEX" && isSealed ? (
                    <>
                      <td className="price-value ev-price">{formatPrice(entry.Price)}</td>
                      <td className="price-value sim-median">
                        {entry.Secondary ? (
                          <>
                            {formatPrice(entry.Secondary)}
                            {entry.ExtraValues?.iqr && entry.ExtraValues.iqr > 150.0 && (
                              <span
                                className="warning-icon"
                                title={`High Simulation IQR: ${entry.ExtraValues.iqr.toFixed(2)}`}
                              >
                                ‼️
                              </span>
                            )}
                          </>
                        ) : (
                          <span className="na-value">n/a</span>
                        )}
                      </td>
                      <td className="price-value sim-stddev">
                        {entry.Secondary && entry.ExtraValues?.stdDev ? (
                          formatPrice(entry.ExtraValues.stdDev)
                        ) : (
                          <span className="na-value">n/a</span>
                        )}
                      </td>
                    </>
                  ) : (
                    <>
                      {isSealed && <td></td>}
                      <td className="price-value">
                        {formatPrice(entry.Price)}
                        {entry.Shorthand === "TCGDirect" && (
                          <>
                            {window.tcg_market_price &&
                              typeof window.tcg_market_price === "function" &&
                              window.tcg_market_price(cardId) &&
                              entry.Price > window.tcg_market_price(cardId) * 2 && (
                                <span
                                  className="warning-icon"
                                  title={`CAUTION - This price looks a bit off, TCG Market is ${
                                    window.tcg_market_price(cardId)
                                      ? formatPrice(window.tcg_market_price(cardId))
                                      : "missing"
                                  }`}
                                >
                                  ‼️
                                </span>
                              )}
                          </>
                        )}
                      </td>

                      {entry.Secondary ? (
                        <>
                          <td className="price-separator">/</td>
                          <td className="price-value secondary-price">{formatPrice(entry.Secondary)}</td>
                        </>
                      ) : (
                        <>
                          {!isSealed && <td></td>}
                          <td
                            className="quantity-value"
                            id={
                              entry.Shorthand === "TCGDirect"
                                ? `qty-${entry.Shorthand}-${condition}-${cardId}`
                                : undefined
                            }
                          >
                            {entry.BundleIcon ? (
                              <img className="bundle-icon" src={entry.BundleIcon || "/placeholder.svg"} alt="Bundle" />
                            ) : !entry.NoQuantity ? (
                              <span className="quantity-text">{entry.Quantity}</span>
                            ) : null}
                          </td>
                        </>
                      )}
                    </>
                  )}
                </tr>
              ))}
            </React.Fragment>
          )
        })}
      </>
    )
  }, [entries, condKeys, isSealed, cardId, card, isSeller])

  return (
    <table className="price-table">
      <tbody>{tableContent}</tbody>
    </table>
  )
}

// Use memo to prevent unnecessary re-renders
export default memo(PriceTable)


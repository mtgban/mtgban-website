"use client"

import type React from "react"
import { useCallback, memo } from "react"
import Link from "next/link"
import type { CardRowProps } from "@/types/search"
import PriceTable from "./PriceTable"

const CardRow: React.FC<CardRowProps> = ({
  cardId,
  card,
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
}) => {
  // Use useCallback for event handlers to prevent unnecessary re-renders
  const updateSidebar = useCallback(() => {
    setFirstImg(card.ImageURL)
    setFirstPrint(card.Printings)
    setFirstProduct(card.Products)
  }, [card, setFirstImg, setFirstPrint, setFirstProduct])

  // Handle copy to clipboard
  const handleCopyToClipboard = useCallback(() => {
    if (typeof window !== "undefined" && window.copyAndBlink) {
      window.copyAndBlink(null, card.Name)
    }
  }, [card.Name])

  // Handle last sold retrieval
  const handleGetLastSold = useCallback(() => {
    if (typeof window !== "undefined" && window.getLastSold) {
      window.getLastSold(cardId)
    }
  }, [cardId])

  return (
    <>
      <tr onMouseOver={updateSidebar} title={`[${card.SetCode}] ${card.Title}`}>
        <th colSpan={3} className="card-header">
          <div className="card-header-content">
            <div className="card-set-icon">
              <Link href={`search?q=s:${card.SetCode}`}>
                <span className="set-code-text" aria-hidden="true">
                  {card.SetCode}
                </span>
                {card.Keyrune ? (
                  <i className={`ss ${card.Keyrune} ss-2x ss-fw`}></i>
                ) : card.RarityColor ? (
                  <svg width="32" height="32" xmlns="http://www.w3.org/2000/svg" className="set-icon-svg">
                    <circle
                      r="15"
                      cx="16"
                      cy="16"
                      fill={card.Foil ? "url(#gradient-foil)" : card.RarityColor}
                      stroke={card.Foil ? "black" : card.RarityColor}
                    />
                    <text
                      fontSize="20"
                      x="50%"
                      y="60%"
                      textAnchor="middle"
                      fill={card.Foil ? "black" : "var(--background)"}
                    >
                      {card.SetCode}
                    </text>
                  </svg>
                ) : (
                  <span className="set-code">{card.SetCode}</span>
                )}
              </Link>
            </div>

            <div className="card-info">
              <div className="card-name-row">
                <Link href={card.SearchURL} className="card-name">
                  {card.Name}
                </Link>
                {card.Variant && <span className="card-variant">({card.Variant})</span>}
                {card.Flag && <span className="card-flag">{card.Flag}</span>}
                {card.Reserved && (
                  <span className="card-reserved" title="Reserved List">
                    *
                  </span>
                )}
                {card.Stocks && (
                  <span className="card-stocks" title="On MTGStocks Interests">
                    •
                  </span>
                )}
                {showSYP && card.SypList && (
                  <span className="card-syp" title="SYP Pull Sheet">
                    †
                  </span>
                )}
              </div>

              <div className="card-set-row">
                <Link href={`?q=s:${card.SetCode}${card.Date ? ` date:${card.Date}` : ""}`} className="card-set">
                  {card.Title}
                </Link>
                {card.SourceSealed && (
                  <Link href={`/sealed?q=container:${card.UUID}`} className="card-source">
                    Found in {card.SourceSealed.length} product{card.SourceSealed.length > 1 ? "s" : ""}
                  </Link>
                )}
              </div>
            </div>

            <div className="card-actions">
              {card.Sealed ? (
                <>
                  {card.Booster && (
                    <Link
                      href={`/search?q=unpack:"${card.Name}"`}
                      title="Simulate opening a booster pack"
                      className="card-action-button"
                    >
                      🎁
                    </Link>
                  )}
                  {card.HasDeck && (
                    <a
                      href={`/api/tcgplayer/decklist/${card.UUID}`}
                      title="Download a TCGplayer-formatted decklist"
                      className="card-action-button"
                    >
                      <img width={28} src="/img/misc/decklist.png" alt="Decklist" />
                    </a>
                  )}
                  <Link
                    href={`/search?q=${card.Booster ? "contents" : "decklist"}:"${card.Name}"`}
                    title="Search what can be found in this product"
                    className="card-action-button"
                  >
                    🔎
                  </Link>
                </>
              ) : (
                <Link
                  href={`/sealed?q=container:"${card.Name}"`}
                  title="Search which products can contain a reprint"
                  className="card-action-button"
                >
                  📖
                </Link>
              )}

              <button
                type="button"
                className="card-action-button"
                onClick={handleCopyToClipboard}
                title="Copy to clipboard"
              >
                📝
              </button>

              {!card.Sealed && (
                <a
                  href={card.DeckboxURL}
                  title="Open the Deckbox page for this card"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="card-action-button"
                >
                  <img width={22} src="/img/logo/deckbox.webp" alt="Deckbox" />
                </a>
              )}

              {card.CKRestockURL && (
                <a
                  href={card.CKRestockURL}
                  title="Set a Restock Notice at CardKingdom"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="card-action-button"
                >
                  🏰
                </a>
              )}

              {card.ScryfallURL && (
                <a
                  href={card.ScryfallURL}
                  title="Check this card on Scryfall.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="card-action-button"
                >
                  <img width={28} src="/img/logo/scryfall.svg" alt="Scryfall" />
                </a>
              )}

              {card.TCGId && (
                <>
                  <a
                    href={`https://store.tcgplayer.com/admin/product/manage/${card.TCGId}`}
                    title="Manage your TCGplayer inventory"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="card-action-button"
                  >
                    <img width={22} src="/img/logo/tcgapp.png" alt="TCGplayer" />
                  </a>
                  <button
                    type="button"
                    className="card-action-button"
                    onClick={handleGetLastSold}
                    title="Retrieve last sales on TCG"
                    id={`lastsolda${cardId}`}
                  >
                    💸
                  </button>
                </>
              )}

              {!disableChart && chartID === "" && (
                <Link href={`?chart=${cardId}`} title="See historical data" className="card-action-button">
                  📊
                </Link>
              )}
            </div>
          </div>
        </th>
      </tr>

      <tr className="price-row" onMouseOver={updateSidebar}>
        <td className="sellers-cell">
          <PriceTable
            entries={foundSellers}
            condKeys={condKeys}
            isSealed={isSealed}
            cardId={cardId}
            card={card}
            isSeller={true}
          />
        </td>

        <td className="vendors-cell">
          <PriceTable
            entries={foundVendors}
            condKeys={condKeys}
            isSealed={isSealed}
            cardId={cardId}
            card={card}
            isSeller={false}
          />
        </td>

        <td className="sales-cell">
          <table className="sales-table" id={cardId} style={{ display: "none" }}>
            {/* Last sales data will be populated by JavaScript */}
          </table>
        </td>
      </tr>
    </>
  )
}

// Use memo to prevent unnecessary re-renders
export default memo(CardRow)


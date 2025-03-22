"use client"

import React from "react"
import Link from "next/link"
import type { CardSidebarProps } from "../../types/search"
import { callGoFunction } from "../../utils/GoNextBridge"

// Explicit type annotation for React component
function CardSidebar(props: CardSidebarProps) {
  const {
    firstImg,
    firstPrint,
    firstProduct,
    isSealed,
    canShowAll,
    hasAvailable,
    alternative,
    altEtchedId,
    stocksURL,
    canDownloadCSV,
    cardHashes = [], // Provide default empty array
    showUpsell,
    hasReserved,
    hasStocks,
    hasSypList,
    chartID,
    searchQuery,
  } = props

  return (
    <table className="card-sidebar" style={{ float: "left", backgroundColor: "var(--background)", width: "354px" }}>
      <tbody>
        {isSealed ? (
          <tr className="no-hover" style={{ backgroundColor: "var(--background)" }}>
            <td>
              <div id="printings" style={{ textAlign: "center", maxWidth: "354px", display: "block" }}></div>
            </td>
          </tr>
        ) : (
          <tr className="no-hover" style={{ backgroundColor: "var(--background)" }}>
            <td>
              <img 
                id="cardImage" 
                src={firstImg || "/placeholder.svg"} 
                width="354" 
                height="493" 
                onClick={() => {
                  const input = document.getElementById('searchbox') as HTMLInputElement;
                  if (input) {
                    input.focus();
                    input.setSelectionRange(0, input.value.length);
                  }
                  return false;
                }}
              />
            </td>
          </tr>
        )}
        
        <tr>
          <td>
            <div id="printings" style={{ textAlign: "center", maxWidth: "354px", display: "block" }}></div>
            {canShowAll && (
              <center>
                <Link className="btn info" href={`search?q=${searchQuery}`}>
                  Show all versions
                </Link>
              </center>
            )}
          </td>
        </tr>
        
        {hasAvailable && (
          <tr>
            <td>
              <center>
                <h4>Available in</h4>
              </center>
              <div id="products" style={{ textAlign: "center", maxWidth: "354px", display: "block" }}></div>
            </td>
          </tr>
        )}
        
        {!isSealed && alternative && (
          <tr>
            <td>
              <center>
                <Link className="btn warning" href={`/search?chart=${alternative}`}>
                  Switch Foil/Non-Foil
                </Link>
              </center>
            </td>
          </tr>
        )}
        
        {!isSealed && altEtchedId && (
          <tr>
            <td>
              <center>
                <Link className="btn warning" href={`/search?chart=${altEtchedId}`}>
                  Switch Etched/Non-Etched
                </Link>
              </center>
            </td>
          </tr>
        )}
        
        {!isSealed && stocksURL && (
          <tr>
            <td>
              <center>
                <a className="btn success" href={stocksURL} target="_blank" rel="noopener noreferrer">
                  Check MTGStocks charts
                </a>
              </center>
            </td>
          </tr>
        )}
        
        {canDownloadCSV && (
          <tr>
            <td>
              <center>
                Download prices as CSV<br />
                <a className="btn success" href={`/api/search/retail${isSealed ? '/sealed' : ''}/${searchQuery}`}>
                  Retail
                </a>
                <a className="btn warning" href={`/api/search/buylist${isSealed ? '/sealed' : ''}/${searchQuery}`}>
                  Buylist
                </a>
              </center>
            </td>
          </tr>
        )}
        
        {canDownloadCSV && !isSealed && (
          <tr>
            <td>
              <center>
                Load search in Uploader<br />
                <form action="/upload" method="post">
                  <input id="mode" type="hidden" name="mode" value="false" />
                  {cardHashes.map((hash, index) => (
                    <input key={index} type="hidden" name="hashes" value={hash} />
                  ))}
                  <a 
                    className="btn success" 
                    style={{ textAlign: "center" }} 
                    onClick={(e) => {
                      e.preventDefault();
                      const modeInput = document.getElementById('mode') as HTMLInputElement;
                      if (modeInput) {
                        modeInput.value = 'false';
                        (e.target as HTMLElement).closest('form')?.submit();
                      }
                      return false;
                    }}
                  >
                    Retail
                  </a>
                  <a 
                    className="btn warning" 
                    style={{ textAlign: "center" }} 
                    onClick={(e) => {
                      e.preventDefault();
                      const modeInput = document.getElementById('mode') as HTMLInputElement;
                      if (modeInput) {
                        modeInput.value = 'true';
                        (e.target as HTMLElement).closest('form')?.submit();
                      }
                      return false;
                    }}
                  >
                    Buylist
                  </a>
                  <noscript>
                    <input type="submit" value="Check Uploader!" />
                  </noscript>
                </form>
              </center>
            </td>
          </tr>
        )}
        
        {!canDownloadCSV && showUpsell && (
          <tr>
            <td>
              <center>
                <i>
                  Increase your tier to be able to download any search results as CSVs
                  {!isSealed && " or to transfer them to the Upload optimizer!"}
                </i>
              </center>
            </td>
          </tr>
        )}
        
        <tr>
          <td style={{ backgroundColor: "var(--background)" }}>
            {hasReserved && (
              <h4>
                {chartID ? (<center>* =</center>) : "* ="}
                Part of the <a href="https://mtg.gamepedia.com/Reserved_List">Reserved List</a>
                {chartID && <center></center>}
              </h4>
            )}
            
            {hasStocks && (
              <h4>
                {chartID ? (<center>• =</center>) : "• ="}
                On <a href="https://mtgstocks.com/interests">MTGStocks Interests</a> page
                {chartID && <center></center>}
              </h4>
            )}
            
            {hasSypList && (
              <h4>
                {chartID ? (<center>† =</center>) : "† ="}
                Found in the <a href="https://help.tcgplayer.com/hc/en-us/articles/360054178934-Store-Your-Products-SYP-Pull-Sheet">SYP Pull Sheet</a>
                {chartID && <center></center>}
              </h4>
            )}
          </td>
        </tr>
      </tbody>
    </table>
  );
}

export default CardSidebar


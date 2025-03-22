"use client"

import React, { useEffect } from "react"

interface OptionsProps {
  sellerKeys: string[]
  vendorKeys: string[]
  hash: string
}

const Options: React.FC<OptionsProps> = ({ sellerKeys, vendorKeys, hash }) => {
  useEffect(() => {
    // Load scripts
    const script = document.createElement("script")
    script.src = `/js/cookies.js?hash=${hash}`
    script.async = true
    document.body.appendChild(script)

    // Initialize form values
    if (typeof window !== "undefined") {
      window.onload = () => {
        window.loadForm("SearchSellersList", "sellers")
        window.loadForm("SearchVendorsList", "vendors")
        window.loadForm("SearchMiscOpts", "miscOpts")
        window.loadRadio("SearchDefaultSort", "defaultSort")
        window.loadRadio("SearchListingPriority", "listingPriority")
        window.loadDropdown("SearchSellersPriority", "sellersPriority")
        window.loadDropdown("SearchVendorsPriority", "vendorsPriority")
      }
    }

    return () => {
      document.body.removeChild(script)
    }
  }, [hash])

  return (
    <>
      <br />
      <div className="indent">
        <h2>Stores</h2>
        Select which sellers or vendors you <b>don't</b> want to display in your searches.
        <br />
        <a
          className="btn warning"
          onClick={() => {
            window.clearForm("sellers")
            window.clearForm("vendors")
          }}
        >
          <b>CLEAR</b>
        </a>
        <a className="btn success" onClick={() => window.selectAll("sellers")}>
          <b>Select ALL Sellers</b>
        </a>
        <a className="btn success" onClick={() => window.selectAll("vendors")}>
          <b>Select ALL Vendors</b>
        </a>
        <a
          className="btn success"
          onClick={() => {
            window.saveForm("SearchSellersList", "sellers")
            window.saveForm("SearchVendorsList", "vendors")
            window.location.href = "/search"
          }}
        >
          <b>SAVE</b>
        </a>
      </div>

      <br />
      <div className="indent row">
        <div className="column" id="sellers">
          {sellerKeys.map((key) => (
            <React.Fragment key={key}>
              <input type="checkbox" id={`s${key}`} name={key} />
              <label htmlFor={`s${key}`}>
                {key.includes("Sealed") ? (
                  <>
                    {key.replace("Sealed", "")}
                    <i>(Sealed)</i>
                  </>
                ) : (
                  key
                )}
              </label>
              <br />
            </React.Fragment>
          ))}
        </div>
        <div className="column" id="vendors">
          {vendorKeys.map((key) => (
            <React.Fragment key={key}>
              <input type="checkbox" id={`v${key}`} name={key} />
              <label htmlFor={`v${key}`}>
                {key.includes("Sealed") ? (
                  <>
                    {key.replace("Sealed", "")}
                    <i>(Sealed)</i>
                  </>
                ) : (
                  key
                )}
              </label>
              <br />
            </React.Fragment>
          ))}
        </div>
      </div>

      <br />
      <div className="indent">
        <h2>Result sorting</h2>
        Select how card results should be sorted by.
        <br />
        <a
          className="btn success"
          onClick={() => {
            window.saveRadio("SearchDefaultSort", "defaultSort")
            window.location.href = "/search"
          }}
        >
          <b>SAVE</b>
        </a>
      </div>

      <br />
      <div className="indent row">
        <div className="column" id="defaultSort">
          <input type="radio" id="chrono" name="sort" value="chrono" defaultChecked />
          <label htmlFor="chrono">By chronological order</label>
          <br />
          <input type="radio" id="hybrid" name="sort" value="hybrid" />
          <label htmlFor="hybrid">By alphabetical order, grouping sets by chronological order</label>
          <br />
          <input type="radio" id="alpha" name="sort" value="alpha" />
          <label htmlFor="alpha">By alphabetical order</label>
          <br />
          <input type="radio" id="retail" name="sort" value="retail" />
          <label htmlFor="retail">By best retail price (off TCGplayer)</label>
          <br />
          <input type="radio" id="buylist" name="sort" value="buylist" />
          <label htmlFor="buylist">By best buylist price (off Card Kingdom)</label>
          <br />
        </div>
      </div>

      <br />
      <div className="indent">
        <h2>Preferred retail/buylist sort option</h2>
        Select which retail and buylist stores should sort by.
        <br />
        <a
          className="btn success"
          onClick={() => {
            window.saveDropdown("SearchSellersPriority", "sellersPriority")
            window.saveDropdown("SearchVendorsPriority", "vendorsPriority")
            window.location.href = "/search"
          }}
        >
          <b>SAVE</b>
        </a>
      </div>

      <br />
      <div className="indent row">
        <div className="column" id="sortPriority">
          <label htmlFor="sellersPriority">Retail priority</label>
          <select id="sellersPriority" className="select-css">
            <option selected disabled hidden>
              &nbsp;&nbsp;&nbsp;Pick a store
            </option>
            <option value="">&nbsp;&nbsp;&nbsp;Reset to Default</option>
            {sellerKeys.map((key) => (
              <option key={key} value={key}>
                &nbsp;&nbsp;&nbsp;{key}
              </option>
            ))}
          </select>

          <label htmlFor="vendorsPriority">Buylist priority</label>
          <select id="vendorsPriority" className="select-css">
            <option selected disabled hidden>
              &nbsp;&nbsp;&nbsp;Pick a store
            </option>
            <option value="">&nbsp;&nbsp;&nbsp;Reset to Default</option>
            {vendorKeys.map((key) => (
              <option key={key} value={key}>
                &nbsp;&nbsp;&nbsp;{key}
              </option>
            ))}
          </select>
        </div>
      </div>

      <br />
      <div className="indent">
        <h2>Listing priority</h2>
        Select how price results should be sorted by.
        <br />
        <a
          className="btn success"
          onClick={() => {
            window.saveRadio("SearchListingPriority", "listingPriority")
            window.location.href = "/search"
          }}
        >
          <b>SAVE</b>
        </a>
      </div>

      <br />
      <div className="indent row">
        <div className="column" id="listingPriority">
          <input type="radio" id="stores" name="priority" value="stores" defaultChecked />
          <label htmlFor="stores">Alphabetical, by store name</label>
          <br />
          <input type="radio" id="prices" name="priority" value="prices" />
          <label htmlFor="prices">Asc for Retail, Desc for Buylist, by prices</label>
          <br />
        </div>
      </div>

      <br />
      <div className="indent">
        <h2>Other preferences</h2>
        Miscellaneous life hacks for Search.
        <br />
        <a className="btn warning" onClick={() => window.clearForm("miscOpts")}>
          <b>CLEAR</b>
        </a>
        <a
          className="btn success"
          onClick={() => {
            window.saveForm("SearchMiscOpts", "miscOpts")
            window.location.href = "/search"
          }}
        >
          <b>SAVE</b>
        </a>
      </div>

      <br />
      <div className="indent row">
        <div className="column" id="miscOpts">
          <input type="checkbox" id="noSussy" name="noSussy" />
          <label htmlFor="noSussy">Skip invalid TCGplayer Direct prices (2x Market, or no Market)</label>
          <br />
          <input type="checkbox" id="hidePrelPack" name="hidePrelPack" />
          <label htmlFor="hidePrelPack">
            Hide classic Promotional entries (<i>promopack, prerelease, etc</i>)
          </label>
          <br />
          <input type="checkbox" id="hidePromos" name="hidePromos" />
          <label htmlFor="hidePromos">
            Hide ALL Promotional entries (<i>judge, buyabox, bundle, some sets, etc</i>)
          </label>
          <br />
          <input type="checkbox" id="hideBLconds" name="hideBLconds" />
          <label htmlFor="hideBLconds">Hide non-NM Buylist entries</label>
          <br />
          <input type="checkbox" id="skipEmpty" name="skipEmpty" />
          <label htmlFor="skipEmpty">Skip results with no prices</label>
          <br />
          <input type="checkbox" id="noSyp" name="noSyp" />
          <label htmlFor="noSyp">Don't show the SYP indication (†)</label>
          <br />
          <input type="checkbox" id="noUpsell" name="noUpsell" />
          <label htmlFor="noUpsell">Hide the upsell reminder to download CSVs</label>
          <br />
        </div>
      </div>
    </>
  )
}

export default Options


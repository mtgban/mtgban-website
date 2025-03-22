"use client"

import React from "react"
import Link from "next/link"

interface SealedResultsProps {
  editionSort: string[]
  editionList: {
    [key: string]: {
      Name: string
      Code: string
      Keyrune: string
    }[]
  }
}

const SealedResults: React.FC<SealedResultsProps> = ({ editionSort, editionList }) => {
  return (
    <>
      <p style={{ maxWidth: "70%" }}>
        Make sure to read the{" "}
        <a className="btn normal" href="#faq">
          F.A.Q.
        </a>
        <br />
        Jump to
        {editionSort.map((edition) => (
          <a key={edition} className="btn normal" href={`#${edition}`}>
            {edition}
          </a>
        ))}
        <br />
        Filter by{" "}
        <input
          type="text"
          style={{ marginLeft: "8px" }}
          id="filterInput"
          onKeyUp={() => window.filterPageContent()}
          placeholder="Edition..."
        />
      </p>

      {editionSort.map((edition) => (
        <React.Fragment key={edition}>
          <div className="sticky" style={{ top: "48px", backgroundColor: "var(--background)" }}>
            <span className="anchor" id={edition}></span>
            <h3 className="storename">{edition}</h3>
            <hr width="15%" />
          </div>

          <div className="indent" style={{ maxWidth: "85%", paddingTop: "10px" }}>
            {editionList[edition]?.map((item, index) => (
              <nobr key={index}>
                <i className={`ss ss-${item.Keyrune} ss-2x ss-fw`}></i>
                <Link className="btn normal" href={`/sealed?q=s:${item.Code}`}>
                  {item.Name}
                </Link>
              </nobr>
            ))}
          </div>
          <br />
        </React.Fragment>
      ))}

      <div style={{ maxWidth: "85%", paddingTop: "10px" }}>
        <span className="anchor" id="faq"></span>
        <h3>F.A.Q.</h3>
        <br />
        <ul className="indent">
          <li>
            <h4>Understanding EV and SIM at BAN</h4>
            <ul className="indent">
              At BAN, we aim to empower our users with data-driven insight into the potential value of their sealed MTG
              products through two distinct but complementary methods: Expected Value (EV) and Simulated Box Openings
              (SIM).
              <br />
              For any product with a static decklist, the card values are just summed up and provided as is, and there
              is no difference between the two methods, while for product with randomness associated with it (ie.
              booster packs and certain decks) there can be profound differences between predicted value and typical
              openings, especially at low sample sizes. Thus, we take both approaches to help the user decide the spread
              and likely value of opening moderate to large amount of product vs. selling it outright.
            </ul>
          </li>
          {/* Additional FAQ items would go here */}
        </ul>
      </div>
    </>
  )
}

export default SealedResults


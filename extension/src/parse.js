// Reads the offers a Cardmarket page lists into plain rows.
//
// The page is segmented by the DOM and each row's fields are read with the
// patterns cmd/mkmhtml2csv already proves against saved pages: the segmenting
// is what a regex over flattened text does worst and querySelectorAll does
// best, and the field patterns are the ones known to hold. Attributes are read
// off outerHTML rather than off an img's src because the page lazy-loads its
// images, and until one is shown its product id sits in a data- attribute
// whose name is the page's business, not ours.

globalThis.MKM = globalThis.MKM || {};

(function (MKM) {
  "use strict";

  // Cardmarket grades in words; the site's upload reads the short forms.
  var CONDITIONS = {
    Mint: "NM",
    "Near Mint": "NM",
    Excellent: "SP",
    Good: "MP",
    "Light Played": "MP",
    Played: "HP",
    Poor: "PO",
  };

  // A card the seller has altered, signed or inked is not the printing the
  // catalog knows, and no id of ours names it.
  var SKIPPED = ["Altered", "Signed", "Inked"];

  var ARTICLE_RE = /stockRow(\d+)/;
  var PRODUCT_RE = /\/Products\/Singles\/([^/?"<& ]+)\/([^/?"<& ]+)/;
  var LANGUAGE_RE = /[?&]language=(\d+)/;
  var QTY_RE = /^\s*(\d+)/;
  // The product id as the two image hosts spell it.
  var IMG_RE = /\/items\/\d+\/(\d+)\//;
  var IMG_S3_RE = /product-images\.s3\.cardmarket\.com\/\d+\/[^/]+\/(\d+)\//;

  // titlesOf collects every tooltip the row carries. Cardmarket writes the
  // same fact into title or data-bs-original-title depending on whether the
  // tooltip has been initialised yet, so both are read.
  function titlesOf(row) {
    var found = [];
    var nodes = row.querySelectorAll("[title], [data-bs-original-title]");
    for (var i = 0; i < nodes.length; i++) {
      var title = nodes[i].getAttribute("title");
      var original = nodes[i].getAttribute("data-bs-original-title");
      if (title) {
        found.push(title.trim());
      }
      if (original) {
        found.push(original.trim());
      }
    }
    return found;
  }

  function firstMatch(html, patterns) {
    for (var i = 0; i < patterns.length; i++) {
      var found = patterns[i].exec(html);
      if (found) {
        return found[1];
      }
    }
    return "";
  }

  // slugToName turns a product slug back into the card's name, the way
  // mkmhtml2csv does: the version suffix goes, "-s-" is the apostrophe it
  // stands for, and the rest of the dashes were spaces.
  function slugToName(slug) {
    return slug
      .replace(/-V\d+$/, "")
      .replace(/-s-/g, "'s-")
      .replace(/-/g, " ");
  }

  // parseRow reads one offer, or returns null for a row naming no product and
  // for one the catalog cannot be asked about.
  function parseRow(row, languageFilter) {
    var article = ARTICLE_RE.exec(row.id || "");
    if (!article) {
      return null;
    }

    var link = row.querySelector('a[href*="/Products/Singles/"]');
    if (!link) {
      return null;
    }
    var href = link.getAttribute("href") || "";
    var product = PRODUCT_RE.exec(href);
    if (!product) {
      return null;
    }

    if (languageFilter) {
      var language = LANGUAGE_RE.exec(href);
      if (language && language[1] !== languageFilter) {
        return null;
      }
    }

    var titles = titlesOf(row);
    for (var i = 0; i < SKIPPED.length; i++) {
      if (titles.indexOf(SKIPPED[i]) !== -1) {
        return null;
      }
    }

    var condition = "";
    for (var j = 0; j < titles.length; j++) {
      if (Object.prototype.hasOwnProperty.call(CONDITIONS, titles[j])) {
        condition = CONDITIONS[titles[j]];
        break;
      }
    }

    var count = row.querySelector(".item-count");
    var quantity = "1";
    if (count) {
      var counted = QTY_RE.exec(count.textContent || "");
      if (counted) {
        quantity = counted[1];
      }
    }

    return {
      mcmID: firstMatch(row.outerHTML, [IMG_RE, IMG_S3_RE]),
      cardName: slugToName(product[2]),
      edition: product[1].replace(/-/g, " "),
      condition: condition,
      foil: titles.indexOf("Foil") !== -1 ? "foil" : "",
      quantity: quantity,
      articleID: article[1],
    };
  }

  // parseOffers reads every offer on the page, once each. A row repeated
  // under the same article id is the same offer drawn twice.
  MKM.parseOffers = function (root, languageFilter) {
    var rows = root.querySelectorAll('[id^="stockRow"]');
    var seen = Object.create(null);
    var offers = [];
    for (var i = 0; i < rows.length; i++) {
      var offer = parseRow(rows[i], languageFilter);
      if (!offer || seen[offer.articleID]) {
        continue;
      }
      seen[offer.articleID] = true;
      offers.push(offer);
    }
    return offers;
  };

  // countRows says how many offers the page holds at all, so the caller can
  // tell "no offers here" from "every offer was skipped".
  MKM.countRows = function (root) {
    return root.querySelectorAll('[id^="stockRow"]').length;
  };

  MKM.slugToName = slugToName;
})(globalThis.MKM);

// Writes the offers out in the shape the site's upload reads.
//
// Every column here is one the upload's header matcher already names, and the
// names are chosen so it names them the way it should: "card_name" reaches
// cardName rather than edition, "foil" reaches the printing column, and
// "mcm_id" reaches the Cardmarket id. "article_id" reaches nothing and is
// meant to - it is carried so a row can be traced back to the offer it came
// from, and the matcher ignores it.
//
// There is no price column. The upload compares a price it is given against
// BAN's own, which are dollars, and every price on Cardmarket is euros: a
// column here would be read as the currency it is not, and a valuation that
// is wrong by an exchange rate is worse than one the site works out itself.

globalThis.MKM = globalThis.MKM || {};

(function (MKM) {
  "use strict";

  var COLUMNS = [
    ["mcm_id", "mcmID"],
    ["card_name", "cardName"],
    ["edition", "edition"],
    ["condition", "condition"],
    ["foil", "foil"],
    ["quantity", "quantity"],
    ["article_id", "articleID"],
  ];

  // field quotes what has to be quoted and nothing else.
  function field(value) {
    var text = value === undefined || value === null ? "" : String(value);
    if (/[",\r\n]/.test(text)) {
      return '"' + text.replace(/"/g, '""') + '"';
    }
    return text;
  }

  function row(values) {
    var quoted = [];
    for (var i = 0; i < values.length; i++) {
      quoted.push(field(values[i]));
    }
    return quoted.join(",");
  }

  MKM.toCSV = function (offers) {
    var header = [];
    for (var i = 0; i < COLUMNS.length; i++) {
      header.push(COLUMNS[i][0]);
    }

    var lines = [row(header)];
    for (var j = 0; j < offers.length; j++) {
      var values = [];
      for (var k = 0; k < COLUMNS.length; k++) {
        values.push(offers[j][COLUMNS[k][1]]);
      }
      lines.push(row(values));
    }
    // A trailing newline: the last row ends like every other one.
    return lines.join("\r\n") + "\r\n";
  };

  MKM.csvColumns = function () {
    var names = [];
    for (var i = 0; i < COLUMNS.length; i++) {
      names.push(COLUMNS[i][0]);
    }
    return names;
  };
})(globalThis.MKM);

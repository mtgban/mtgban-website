package main

import (
	"encoding/csv"
	"fmt"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// We could add two extra headers, "TcgPlayer ID" and "Scryfall ID", but then each card
// missing in the Deckbox DB would be considered an invalid row
var deckboxHeader = []string{
	"Count", "Tradelist Count", "Name", "Edition", "Edition Code", "Card Number", "Condition",
	"Language", "Foil", "Signed", "Artist Proof", "Altered Art", "Misprint", "Promo", "Textless",
	"Printing Id", "Printing Note", "Tags", "My Price",
}

func deckboxIdConvert(w *csv.Writer, uploadedData []UploadEntry) error {
	err := w.Write(deckboxHeader)
	if err != nil {
		return err
	}
	for i := range uploadedData {
		if uploadedData[i].MismatchError != nil {
			continue
		}

		co, err := mtgmatcher.GetUUID(uploadedData[i].CardId)
		if err != nil {
			continue
		}

		deckboxId, found := co.Identifiers["deckboxId"]
		cardName := co.Name
		tags := ""

		// If id is missing instead tag the cards with the information available
		if !found {
			deckboxId = ""
			tags = co.SetCode + "\\t" + co.Number
		}

		var cond string
		if uploadedData[i].OriginalCondition != "" {
			cond = map[string]string{
				"NM": "Near Mint",
				"SP": "Good (Lightly Played)",
				"MP": "Played",
				"HP": "Heavily Played",
				"PO": "Poor",
			}[uploadedData[i].OriginalCondition]
		}

		qty := "1"
		if uploadedData[i].HasQuantity {
			qty = fmt.Sprintf("%d", uploadedData[i].Quantity)
		}

		foil := ""
		if co.Foil || co.Etched {
			foil = "foil"
		}

		lang := co.Language
		switch lang {
		case "Phyrexian":
			lang = ""
		case "Portuguese (Brazilian)":
			lang = "Portuguese"
		case "Chinese Simplified",
			"Chinese Traditional":
			lang = "Chinese"
		}

		price := ""
		if uploadedData[i].OriginalPrice != 0 {
			price = fmt.Sprintf("$%.02f", uploadedData[i].OriginalPrice)
		}

		err = w.Write([]string{
			qty, qty, cardName, "", "", "", cond, lang, foil, "", "", "", "", "", "", deckboxId, "", tags, price,
		})
		if err != nil {
			return err
		}

		w.Flush()
	}

	return nil
}

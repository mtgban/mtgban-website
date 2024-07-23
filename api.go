package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mtgban/go-mtgban/cardkingdom"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"golang.org/x/exp/maps"
)

type ckMeta struct {
	Id  int    `json:"id,omitempty"`
	URL string `json:"url,omitempty"`
}

type ck2id struct {
	Normal *ckMeta `json:"normal,omitempty"`
	Foil   *ckMeta `json:"foil,omitempty"`
	Etched *ckMeta `json:"etched,omitempty"`
}

var CKAPIMutex sync.RWMutex
var CKAPIOutput map[string]*ck2id
var CKAPIData []cardkingdom.CKCard

func CKMirrorAPI(w http.ResponseWriter, r *http.Request) {
	var pricelist struct {
		Data []cardkingdom.CKCard `json:"list"`
	}
	pricelist.Data = CKAPIData

	err := json.NewEncoder(w).Encode(&pricelist)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}
}

func prepareCKAPI() error {
	ServerNotify("api", "CK APIrefresh started")

	list, err := cardkingdom.NewCKClient().GetPriceList()
	if err != nil {
		log.Println(err)
		return err
	}
	CKAPIData = list

	// Backup option for stashing CK data
	rdbRT := ScraperOptions["cardkingdom"].RDBs["retail"]
	rdbBL := ScraperOptions["cardkingdom"].RDBs["buylist"]
	key := time.Now().Format("2006-01-02")

	output := map[string]*ck2id{}

	var skipRedis bool
	for _, card := range list {
		theCard, err := cardkingdom.Preprocess(card)
		if err != nil {
			continue
		}

		cardId, err := mtgmatcher.Match(theCard)
		if err != nil {
			continue
		}

		if card.SellQuantity > 0 && !skipRedis {
			// We use Set for retail because prices are more accurate
			err = rdbRT.HSet(context.Background(), cardId, key, card.SellPrice).Err()
			if err != nil {
				log.Printf("redis error for %s: %s", cardId, err)
				skipRedis = true
			}
		}
		if card.BuyQuantity > 0 && !skipRedis {
			err = rdbBL.HSetNX(context.Background(), cardId, key, card.BuyPrice).Err()
			if err != nil {
				log.Printf("redis error for %s: %s", cardId, err)
				skipRedis = true
			}
		}

		co, err := mtgmatcher.GetUUID(cardId)
		if err != nil {
			continue
		}

		id, found := co.Identifiers["mtgjsonId"]
		if !found {
			id = cardId
		}

		// Allocate memory
		_, found = output[id]
		if !found {
			output[id] = &ck2id{}
		}

		// Set data as needed
		data := &ckMeta{
			Id:  card.Id,
			URL: "https://www.cardkingdom.com/" + card.URL,
		}
		if co.Etched {
			output[id].Etched = data
		} else if co.Foil {
			output[id].Foil = data
		} else {
			output[id].Normal = data
		}
	}

	CKAPIMutex.Lock()
	CKAPIOutput = output
	CKAPIMutex.Unlock()

	ServerNotify("api", "CK API refresh completed")

	return nil
}

func API(w http.ResponseWriter, r *http.Request) {
	sig := r.FormValue("sig")

	param := GetParamFromSig(sig, "API")
	canAPI := strings.Contains(param, "CK")
	if SigCheck && !canAPI {
		w.Write([]byte(`{"error": "invalid signature"}`))
		return
	}

	CKAPIMutex.RLock()
	defer CKAPIMutex.RUnlock()
	if CKAPIOutput == nil {
		log.Println("CK API called when list was empty")
		w.Write([]byte(`{"error": "empty list"}`))
		return
	}
	outputMap := CKAPIOutput

	// Only scryfall and mtgjson ids are supported due to the unification of finishes
	// mtgjson is the default, perform a key conversion if scryfall is requested
	idMode := r.FormValue("id")
	if idMode == "scryfall" {
		altMap := map[string]*ck2id{}
		for uuid, meta := range CKAPIOutput {
			co, err := mtgmatcher.GetUUID(uuid)
			if err != nil {
				continue
			}
			id := getIdFunc(idMode)(co)
			altMap[id] = meta
		}
		outputMap = altMap
	}

	err := json.NewEncoder(w).Encode(outputMap)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}
}

var ErrMissingTCGId = errors.New("tcg id not found")

func getLastSold(cardId string) ([]tcgplayer.LatestSalesData, error) {
	co, err := mtgmatcher.GetUUID(cardId)
	if err != nil {
		return nil, err
	}

	tcgId := co.Identifiers["tcgplayerProductId"]
	if co.Etched {
		id, found := co.Identifiers["tcgplayerEtchedProductId"]
		if found {
			tcgId = id
		}
	}
	if tcgId == "" {
		return nil, ErrMissingTCGId
	}

	latestSales, err := tcgplayer.TCGLatestSales(tcgId, co.Foil || co.Etched)
	if err != nil {
		return nil, err
	}

	return latestSales.Data, nil
}

func TCGLastSoldAPI(w http.ResponseWriter, r *http.Request) {
	cardId := strings.TrimPrefix(r.URL.Path, "/api/tcgplayer/lastsold/")
	UserNotify("tcgLastSold", cardId)

	data, err := getLastSold(cardId)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println(err)
		w.Write([]byte(`{"error": "` + err.Error() + `"}`))
		return
	}
}

func UUID2CKCSV(w *csv.Writer, ids, qtys []string) error {
	var buylist mtgban.BuylistRecord
	for _, vendor := range Vendors {
		if vendor != nil && vendor.Info().Shorthand == "CK" {
			buylist, _ = vendor.Buylist()
			break
		}
	}
	if buylist == nil {
		return errors.New("CK scraper not found")
	}

	header := []string{"Title", "Edition", "Foil", "Quantity"}
	err := w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		name, found := blEntries[0].CustomFields["CKTitle"]
		if !found {
			continue
		}
		edition := blEntries[0].CustomFields["CKEdition"]
		finish := blEntries[0].CustomFields["CKFoil"]
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}

		err = w.Write([]string{name, edition, finish, quantity})
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

func UUID2SCGCSV(w *csv.Writer, ids, qtys []string) error {
	var buylist mtgban.BuylistRecord
	for _, vendor := range Vendors {
		if vendor != nil && vendor.Info().Shorthand == "SCG" {
			buylist, _ = vendor.Buylist()
			break
		}
	}
	if buylist == nil {
		return errors.New("SCG scraper not found")
	}

	header := []string{"name", "set_name", "language", "finish", "quantity"}
	err := w.Write(header)
	if err != nil {
		return err
	}
	for i, id := range ids {
		blEntries, found := buylist[id]
		if !found {
			continue
		}
		name, found := blEntries[0].CustomFields["SCGName"]
		if !found {
			continue
		}
		edition := blEntries[0].CustomFields["SCGEdition"]
		language := blEntries[0].CustomFields["SCGLanguage"]
		finish := blEntries[0].CustomFields["SCGFinish"]
		quantity := "1"
		if len(qtys) == len(ids) && qtys[i] != "0" {
			quantity = qtys[i]
		}

		err = w.Write([]string{name, edition, language, finish, quantity})
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

var tcgcsvHeader = []string{
	"TCGplayer Id",
	"Product Line",
	"Set Name",
	"Product Name",
	"Title",
	"Number",
	"Rarity",
	"Condition",
	"TCG Market Price",
	"TCG Direct Low",
	"TCG Low Price With Shipping",
	"TCG Low Price",
	"Total Quantity",
	"Add to Quantity",
	"TCG Marketplace Price",
	"Photo URL",
}

func GetInventoryForSeller(sellerName string) (mtgban.InventoryRecord, error) {
	for _, seller := range Sellers {
		if seller != nil && seller.Info().Shorthand == sellerName {
			return seller.Inventory()
		}
	}
	return nil, errors.New("scraper not found")
}

func UUID2TCGCSV(w *csv.Writer, ids []string) error {
	inventory, err := GetInventoryForSeller(TCG_MAIN)
	if err != nil {
		return err
	}
	direct, _ := GetInventoryForSeller(TCG_DIRECT_LOW)
	low, _ := GetInventoryForSeller(TCG_LOW)

	err = w.Write(tcgcsvHeader)
	if err != nil {
		return err
	}

	// Track total quantity, and skip repeats
	qty := map[string]int{}
	for _, id := range ids {
		qty[id]++
	}

	for _, id := range maps.Keys(qty) {
		price := 0.0
		lowPrice := 0.0
		directPrice := 0.0

		invEntries, found := inventory[id]
		if !found {
			continue
		}
		price = invEntries[0].Price
		directEntries, found := direct[id]
		if found {
			directPrice = directEntries[0].Price
		}
		lowEntries, found := low[id]
		if found {
			lowPrice = lowEntries[0].Price
		}

		co, err := mtgmatcher.GetUUID(id)
		if err != nil {
			continue
		}

		tcgSkuId := invEntries[0].InstanceId
		if tcgSkuId == "" {
			continue
		}

		cond := "Near Mint"
		if co.Foil {
			cond = "Near Mint Foil"
		}

		record := make([]string, 0, len(tcgcsvHeader))

		record = append(record, tcgSkuId)
		record = append(record, "")
		record = append(record, co.Edition)
		record = append(record, co.Name)
		record = append(record, "")
		record = append(record, co.Number)
		record = append(record, strings.ToUpper(co.Rarity[:1]))
		record = append(record, cond)
		record = append(record, fmt.Sprintf("%0.2f", price))
		record = append(record, fmt.Sprintf("%0.2f", directPrice))
		record = append(record, "")
		record = append(record, fmt.Sprintf("%0.2f", lowPrice))
		record = append(record, "")
		record = append(record, fmt.Sprint(qty[id]))
		record = append(record, "")
		record = append(record, "")

		err = w.Write(record)
		if err != nil {
			return err
		}

		w.Flush()
	}
	return nil
}

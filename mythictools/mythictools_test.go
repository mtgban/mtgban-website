package mythictools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

const testLink = "https://mythic.tools/user/4k9CbN/collection/list/5GFR8D"

const testPage = `<!DOCTYPE html><html><head>
<script type="application/json" id="__NUXT_DATA__">[{"share-meta-list-226931-6802958":4}]</script>
<script>window.__NUXT__={};window.__NUXT__.config={public:{MYTHIC_API_URL:"https://api",MYTHIC_API_KEY:"api-key",MYTHIC_WEB_KEY:"web-key",SLUG_1:"one",SLUG_2:"two"}}</script>
</head><body></body></html>`

type testCard struct {
	ListCardID int    `json:"list_card_id"`
	ScryfallID string `json:"scryfallid"`
	Name       string `json:"name"`
	Quantity   int    `json:"quantity"`
	Finish     string `json:"finish"`
	Condition  string `json:"condition"`
	Proxy      bool   `json:"proxy"`
}

// serve answers the page and the API, checking each API call carries a
// signature over its own timestamp.
func serve(t *testing.T, pages [][]testCard) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user/4k9CbN/collection/list/5GFR8D", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(testPage))
	})
	mux.HandleFunc("GET /user/226931/list/6802958", func(w http.ResponseWriter, r *http.Request) {
		timestamp := r.Header.Get("x-mythic-timestamp")
		sum := sha256.Sum256([]byte("one+/" + timestamp + ".web-key/+two!"))
		if timestamp == "" || r.Header.Get("x-mythic-signature") != hex.EncodeToString(sum[:]) ||
			r.Header.Get("x-api-key") != "api-key" || r.Header.Get("x-mythic-device") != "web" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 || page > len(pages) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			List struct {
				Name       string `json:"name"`
				Pagination struct {
					HasNext bool `json:"has_next"`
				} `json:"pagination"`
				Cards []testCard `json:"cards"`
			} `json:"list"`
		}
		body.List.Name = "Binder"
		body.List.Pagination.HasNext = page < len(pages)
		body.List.Cards = pages[page-1]
		json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLoadWalksEveryPage(t *testing.T) {
	srv := serve(t, [][]testCard{
		{
			{ListCardID: 1, ScryfallID: "a", Name: "Foil", Quantity: 2, Finish: "foil", Condition: "NM"},
			{ListCardID: 2, ScryfallID: "b", Name: "Proxy", Quantity: 1, Finish: "nonfoil", Condition: "NM", Proxy: true},
			{ListCardID: 3, ScryfallID: "", Name: "No id", Quantity: 1, Finish: "nonfoil", Condition: "NM"},
		},
		{
			{ListCardID: 4, ScryfallID: "c", Name: "Etched", Quantity: 1, Finish: "etched", Condition: "PL"},
			{ListCardID: 5, ScryfallID: "d", Name: "Plain", Quantity: 1, Finish: "nonfoil", Condition: "unheard of"},
		},
	})

	items, name, err := load(context.Background(), srv.URL, srv.URL, testLink, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Binder" {
		t.Errorf("name = %q", name)
	}
	want := []Item{
		{ScryfallID: "a", Name: "Foil", Quantity: 2, IsFoil: true, Condition: mtgban.NM},
		{ScryfallID: "c", Name: "Etched", Quantity: 1, IsEtched: true, Condition: mtgban.MP},
		{ScryfallID: "d", Name: "Plain", Quantity: 1},
	}
	if len(items) != len(want) {
		t.Fatalf("got %d items, want %d: %+v", len(items), len(want), items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Errorf("item %d = %+v, want %+v", i, items[i], want[i])
		}
	}
}

func TestLoadStopsAtMaxRows(t *testing.T) {
	srv := serve(t, [][]testCard{
		{{ListCardID: 1, ScryfallID: "a", Quantity: 1}, {ListCardID: 2, ScryfallID: "b", Quantity: 1}},
		{{ListCardID: 3, ScryfallID: "c", Quantity: 1}},
	})
	items, _, err := load(context.Background(), srv.URL, srv.URL, testLink, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ScryfallID != "a" {
		t.Errorf("items = %+v", items)
	}
}

// An API that ignores page and keeps saying there is more must not have its
// first page read over and over as a longer list.
func TestLoadRefusesRepeatedPage(t *testing.T) {
	same := []testCard{{ListCardID: 7, ScryfallID: "a", Quantity: 1}}
	srv := serve(t, [][]testCard{same, same, same})
	_, _, err := load(context.Background(), srv.URL, srv.URL, testLink, 0)
	if err == nil || !strings.Contains(err.Error(), "repeated page") {
		t.Errorf("err = %v, want the repeated page error", err)
	}
}

// Without the id there is nothing to compare, so has_next alone ends the walk.
func TestLoadWalksRowsWithoutListCardID(t *testing.T) {
	srv := serve(t, [][]testCard{
		{{ScryfallID: "a", Quantity: 1}},
		{{ScryfallID: "b", Quantity: 1}},
	})
	items, _, err := load(context.Background(), srv.URL, srv.URL, testLink, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Errorf("items = %+v", items)
	}
}

func TestLoadReportsAPIStatus(t *testing.T) {
	srv := serve(t, nil)
	_, _, err := load(context.Background(), srv.URL, srv.URL, testLink, 0)
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("err = %v, want the API's status", err)
	}
}

func TestParseSessionRefusesPageWithoutData(t *testing.T) {
	for name, page := range map[string]string{
		"no list":        `<script>MYTHIC_API_KEY:"a",MYTHIC_WEB_KEY:"b",SLUG_1:"c",SLUG_2:"d"</script>`,
		"no credentials": `<script>share-meta-list-1-2</script>`,
		"body text only": `<p>share-meta-list-1-2 MYTHIC_API_KEY:"a",MYTHIC_WEB_KEY:"b",SLUG_1:"c",SLUG_2:"d"</p>`,
	} {
		_, err := parseSession(strings.NewReader(page))
		if err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestParseListURL(t *testing.T) {
	user, list, err := ParseListURL(testLink)
	if err != nil || user != "4k9CbN" || list != "5GFR8D" {
		t.Fatalf("got %q %q %v", user, list, err)
	}
	for _, link := range []string{
		"https://moxfield.com/user/a/collection/list/b",
		"https://mythic.tools/user/a/collection",
		"https://mythic.tools/user/a/collection/list/",
		"https://mythic.tools/user/../collection/list/b",
		"https://mythic.tools/user/a/collection/list/%2e%2e",
		"https://mythic.tools/user/a/collection/list/b/c",
		"https://mythic.tools/user/a/deck/list/b",
	} {
		_, _, err := ParseListURL(link)
		if err == nil {
			t.Errorf("ParseListURL(%q) accepted", link)
		}
	}
}

func TestLoadLive(t *testing.T) {
	if os.Getenv("MYTHICTOOLS_LIVE") == "" {
		t.Skip("MYTHICTOOLS_LIVE not set; skipping live Mythic Tools test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	items, name, err := Load(ctx, testLink, 0)
	if err != nil {
		t.Fatal(err)
	}
	copies := 0
	for _, item := range items {
		copies += item.Quantity
	}
	if name == "" || copies == 0 {
		t.Fatalf("name=%q items=%d", name, len(items))
	}
	t.Logf("list %q with %d rows, %d copies", name, len(items), copies)
}

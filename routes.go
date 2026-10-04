package main

import (
	"log"
	"net/http"
	"os"
	"path"

	"github.com/leemcloughlin/logfile"
)

// Cache for a week as these assets either never change or have a snapshot key in the URL
func ServeFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, r.URL.Path[1:])
}

// registerRoutes serves every page, redirect and API on the default mux,
// each behind the signing it needs, and opens each page's log.
func (s *site) registerRoutes() {
	// Serve everything in known folders as a file
	http.HandleFunc("/css/", ServeFile)
	http.HandleFunc("/img/", ServeFile)
	http.HandleFunc("/js/", ServeFile)
	http.HandleFunc("/favicon.ico", ServeFile)
	http.HandleFunc("/robots.txt", ServeFile)
	// Dedicated handler: the service worker must revalidate on every deploy
	http.HandleFunc("/sw.js", ServeServiceWorker)

	// custom redirector
	http.HandleFunc("/go/", s.Redirect)
	http.HandleFunc("/http:/", UploadURLRedirect)
	http.HandleFunc("/https:/", UploadURLRedirect)
	http.HandleFunc("/card/", s.CardRedirect)
	http.HandleFunc("/sealed/", s.SealedRedirect)
	http.HandleFunc("/random", s.RandomSearch)
	http.HandleFunc("/randomsealed", s.RandomSealedSearch)
	http.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config().Discord.InviteURL, http.StatusFound)
	})

	// Public changelog sourced from the Discord announcement channel.
	http.Handle("/changelog", noSigning(http.HandlerFunc(s.Changelog)))

	// when navigating to /home it should serve the home page
	http.Handle("/", noSigning(http.HandlerFunc(s.Home)))

	// Public guide page
	http.Handle("/guide", noSigning(http.HandlerFunc(s.Guide)))

	// Public privacy policy (cookie + Amazon Associates disclosures)
	http.Handle("/privacy", noSigning(http.HandlerFunc(s.Privacy)))

	// Offline shell page, precached by the service worker
	http.Handle("/offline", noSigning(http.HandlerFunc(s.OfflinePage)))

	// Mobile/desktop view toggle
	http.HandleFunc("/toggle-mobile", toggleMobileView)

	for _, nav := range ExtraNavs {
		// Set up logging
		logFile, err := logfile.New(&logfile.LogFile{
			FileName:    path.Join(LogDir, nav.Name+".log"),
			MaxSize:     500 * 1024,
			Flags:       logfile.FileOnly,
			OldVersions: 2,
		})
		if err != nil {
			log.Printf("Failed to create logFile for %s: %s", nav.Name, err)
			LogPages[nav.Name] = log.New(os.Stderr, "", log.LstdFlags)
		} else {
			LogPages[nav.Name] = log.New(logFile, "", log.LstdFlags)
		}

		// Set up the handler
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nav.Handle(s, w, r)
		})
		handler = enforceSigning(s, handler)
		http.Handle(nav.Link, handler)

		// Add any additional endpoints to it
		for _, subPage := range nav.SubPages {
			http.Handle(subPage.Link, handler)
		}
	}

	// The upload handoff sits under /upload but is its own page: the nav
	// entry registers an exact path, so it needs naming here.
	//
	// Served without the signing middleware, which would answer a reader
	// who has no signature with the home page. This one is worth reaching
	// signed out: somebody sent here by an extension arrives knowing
	// nothing about the site, and the page can say what it is and what it
	// would take to use it. It grants nothing by being read - the rows it
	// receives are posted to /upload, which is enforced as it always was -
	// and it checks the signature itself before it agrees to receive any.
	http.Handle("/upload/handoff", noSigning(http.HandlerFunc(s.UploadHandoff)))

	http.Handle("/search/oembed", noSigning(http.HandlerFunc(s.SearchOEmbed)))
	http.Handle("/api/mtgban/search/", enforceAPISigning(http.HandlerFunc(s.SearchAPI)))
	http.Handle("/api/mtgban/", enforceAPISigning(http.HandlerFunc(s.PriceAPI)))
	http.Handle("/api/tcgplayer/", enforceSigning(s, http.HandlerFunc(s.TCGHandler)))
	http.Handle("/api/cardmarket/", enforceSigning(s, http.HandlerFunc(s.MKMHandler)))
	http.Handle("/api/search/", enforceSigning(s, http.HandlerFunc(s.SearchAPI)))
	http.Handle("/api/mtgmatcher/raw/", enforceSigning(s, http.HandlerFunc(s.RawCardAPI)))
	http.Handle("/api/suggest", noSigning(http.HandlerFunc(s.SuggestAPI)))
	http.Handle("/api/settings/modal", noSigning(http.HandlerFunc(s.SettingsModal)))
	http.Handle("/api/chart/", noSigning(http.HandlerFunc(s.ChartDataAPI)))
	http.Handle("/api/prices/", enforceSigning(s, http.HandlerFunc(s.BatchPricesAPI)))
	http.Handle("/api/userstate/", noSigning(http.HandlerFunc(UserStateAPI)))
	// Its closures read the live datastore and prices per request.
	http.Handle("/api/alerts/", noSigning(s.alerts.API()))
	http.Handle("/api/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))
	http.Handle("/api/load/datastore", noSigning(http.HandlerFunc(s.LoadDatastoreFromCloud)))
	http.Handle("/api/load/", enforceAPISigning(http.HandlerFunc(s.LoadFromCloud)))
	http.Handle("/api/palette/card/", noSigning(http.HandlerFunc(s.palette.CardMeta)))
	http.Handle("/api/palette/sealed/", noSigning(http.HandlerFunc(s.palette.Sealed)))
	http.Handle("/api/palette/sets.json", noSigning(http.HandlerFunc(s.palette.Sets)))
	http.Handle("/api/palette/stores.json", noSigning(http.HandlerFunc(s.palette.Stores)))
	// The gateway reads the store families without a signature, so this
	// cannot hang off the API page: a sub-page is served unsigned only when
	// the ACL's Any tier grants the page (see enforceSigning).
	http.Handle("/api-plans/stores.json", noSigning(http.HandlerFunc(APIStores)))
	http.Handle("/api/palette/promos.json", noSigning(http.HandlerFunc(s.palette.Promos)))
	http.Handle("/api/palette/finishes.json", noSigning(http.HandlerFunc(s.palette.Finishes)))
	http.Handle("/api/palette/rarities.json", noSigning(http.HandlerFunc(s.palette.Rarities)))
	http.Handle("/api/palette/colors.json", noSigning(http.HandlerFunc(s.palette.Colors)))
	http.Handle("/api/offline/", noSigning(http.HandlerFunc(s.offline.Handle)))

	http.Handle("/monroecards", http.RedirectHandler("/screener", http.StatusFound))

	http.HandleFunc("/auth", s.Auth)

	// /healthz: returns 200 only if dependencies are OK.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		uuids := len(s.backend().GetUUIDs())
		sellers, vendors := len(GetSellers()), len(GetVendors())
		if uuids == 0 || sellers == 0 || vendors == 0 {
			log.Printf("healthz: not ready (uuids=%d, sellers=%d, vendors=%d)", uuids, sellers, vendors)
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/internal/diskusage"
	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/mtgban-website/internal/jobs"
	"github.com/mtgban/mtgban-website/internal/sessionstore"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/simplecloud"

	"github.com/mackerelio/go-osstat/memory"
)

const (
	dispatchURL = "https://api.github.com/repos/mtgban/go-mtgban/dispatches"
	workflowURL = "https://api.github.com/repos/mtgban/go-mtgban/actions/workflows/"
	gaStatusURL = "https://api.github.com/repos/mtgban/go-mtgban/actions/runs?status="
	gaLogURL    = "https://github.com/mtgban/go-mtgban/actions/workflows/%s"
)

// bantoolWorkflow names a store's bantool workflow: EventType is the
// repository_dispatch event_type and the part of File between "bantool-"
// and ".yml"; RunName is the run's GitHub display name.
type bantoolWorkflow struct {
	EventType string
	File      string
	RunName   string
}

func newBantoolWorkflow(game mtgmatcher.Game, store string) bantoolWorkflow {
	slug := string(game)
	return bantoolWorkflow{
		EventType: slug + "-" + store,
		File:      "bantool-" + slug + "-" + store + ".yml",
		RunName:   slug + " / " + store,
	}
}

// Time when server started
var StartTime = time.Now()

var BuildCommit = func() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return ""
}()

// AdminVars are the PageVars fields only the admin page fills and reads.
type AdminVars struct {
	UsageStats *UsageDashboard

	CheckpointsText    string
	ACLText            string
	ACLSource          string
	AffiliatesText     string
	AffiliatesSource   string
	KeyOverridesText   string
	OverrideStores     []string
	OverrideFixStore   string
	OverrideFixKind    string
	OverrideWrongCard  *OverrideCard
	OverrideCandidates []OverrideCard

	Tables          [][][]string
	Jobs            []jobs.Row
	DatastoreReload dsreload.State
	LastNews        time.Time
	LastStash       time.Time
	Uptime          string
	DiskStatus      string
	MemoryStatus    string
	LatestHash      string

	SelectableField bool
	SelectableLabel string
}

func (s *site) Admin(w http.ResponseWriter, r *http.Request) {
	// The dashboard asks for the workflow status once it has rendered, so a
	// round trip to GitHub never delays the page. Answered from here rather
	// than a route of its own, to stay behind the same signing middleware.
	if r.FormValue("workflows") != "" {
		serveRunningWorkflows(w)
		return
	}

	ds := s.datastore()
	b := ds.backend
	sig := getSignatureFromCookies(r)

	page := r.FormValue("page")
	pageVars := genPageNav(s, r, "Admin", sig)
	pageVars.IsMobile = isMobileRequest(r)
	if pageVars.IsMobile {
		pageVars.Nav = filterNavForMobile(pageVars.Nav)
	}

	pageVars.LastUpdate = ds.loadedAt
	pageVars.LastNews = GetLastNewspaperUpdate()
	pageVars.LastStash = GetLastStashUpdate()

	msg := r.FormValue("msg")
	if msg != "" {
		pageVars.InfoMessage = msg
	}
	// What the result is, said in a word the page can print beside it. The
	// token is matched rather than shown, so the label is this code's to
	// write and not something a query string can put on the page.
	switch r.FormValue("html") {
	case "textfield":
		pageVars.SelectableField = true
		pageVars.SelectableLabel = "New key"
	case "invite":
		pageVars.SelectableField = true
		pageVars.SelectableLabel = "Invite link"
	}

	if s.adminActions(w, r, &pageVars) {
		return
	}

	if s.adminTools(w, r, &pageVars) {
		return
	}

	// -- Config: handle POST if submitted --
	newConfig := r.FormValue("textArea")
	if newConfig != "" {
		var config ConfigType
		err := json.Unmarshal([]byte(newConfig), &config)
		if err != nil {
			pageVars.WarningMessage = err.Error()
		} else {
			err = saveConfig(r.Context(), config)
			if err != nil {
				log.Println(err)
				pageVars.WarningMessage = err.Error()
			} else {
				pageVars.InfoMessage = "Config updated"
				// The access table, grants and affiliate data are served
				// from their own files, not this config; reload them here
				// in case the edit changed the paths that name them.
				err = loadCommonConfig(r.Context())
				if err != nil {
					pageVars.WarningMessage = err.Error()
				}
			}
		}
	}

	// -- Config: load editor text --
	// If the POST failed, keep the submitted text so the user can fix it
	if newConfig != "" && pageVars.WarningMessage != "" {
		pageVars.CleanSearchQuery = newConfig
	} else {
		text, err := configEditorText()
		if err != nil {
			if pageVars.InfoMessage == "" {
				pageVars.InfoMessage = err.Error()
			}
		} else {
			pageVars.CleanSearchQuery = text
		}
	}

	// -- Checkpoints: handle POST if submitted --
	newCheckpoints := r.FormValue("checkpointsTextArea")
	if newCheckpoints != "" {
		var parsed checkpointsFile
		if err := json.Unmarshal([]byte(newCheckpoints), &parsed); err != nil {
			pageVars.WarningMessage = "Checkpoints JSON invalid: " + err.Error()
		} else if err := saveCheckpoints(r.Context(), parsed.Events); err != nil {
			pageVars.WarningMessage = "Checkpoints save failed: " + err.Error()
		} else {
			pageVars.InfoMessage = "Checkpoints updated"
		}
	}

	// -- Checkpoints: always load current text for the editor --
	if cpText, err := currentCheckpointsJSON(); err != nil {
		if pageVars.InfoMessage == "" {
			pageVars.InfoMessage = err.Error()
		}
	} else {
		pageVars.CheckpointsText = cpText
	}

	// -- Access table: handle POST if submitted --
	newACL := r.FormValue("aclTextArea")
	if newACL != "" {
		var parsed access.Table
		err := json.Unmarshal([]byte(newACL), &parsed)
		if err == nil {
			err = validateACLTable(parsed)
		}
		if err == nil {
			err = saveACL(r.Context(), parsed)
		}
		if err != nil {
			pageVars.WarningMessage = "Access table not saved: " + err.Error()
		} else {
			pageVars.InfoMessage = "Access table updated"
		}
	}

	// -- Access table: always load current text for the editor --
	aclText, aclErr := json.MarshalIndent(ACL(), "", "    ")
	if aclErr != nil {
		if pageVars.InfoMessage == "" {
			pageVars.InfoMessage = aclErr.Error()
		}
	} else {
		pageVars.ACLText = string(aclText)
	}
	pageVars.ACLSource = Config().ACLPath
	if pageVars.ACLSource == "" {
		pageVars.ACLSource = "not configured"
	}

	// -- Affiliates: handle POST if submitted --
	newAffiliates := r.FormValue("affiliatesTextArea")
	if newAffiliates != "" {
		var parsed AffiliatesConfig
		decoder := json.NewDecoder(strings.NewReader(newAffiliates))
		// The value is a fixed three-key struct, so an unknown key is a typo
		// that would otherwise be dropped without a word.
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&parsed)
		if err == nil {
			err = saveAffiliates(r.Context(), parsed)
		}
		if err != nil {
			pageVars.WarningMessage = "Affiliates not saved: " + err.Error()
		} else {
			pageVars.InfoMessage = "Affiliates updated"
		}
	}

	// -- Affiliates: always load current text for the editor --
	affiliatesText, affErr := json.MarshalIndent(Affiliates(), "", "    ")
	if affErr != nil {
		if pageVars.InfoMessage == "" {
			pageVars.InfoMessage = affErr.Error()
		}
	} else {
		pageVars.AffiliatesText = string(affiliatesText)
	}
	pageVars.AffiliatesSource = Config().AffiliatesPath
	if pageVars.AffiliatesSource == "" {
		pageVars.AffiliatesSource = "not configured"
	}

	// -- Key overrides: handle POST if submitted --
	newOverrides := r.FormValue("keyOverridesTextArea")
	if newOverrides != "" {
		var parsed KeyOverrides
		if err := json.Unmarshal([]byte(newOverrides), &parsed); err != nil {
			pageVars.WarningMessage = "Key overrides JSON invalid: " + err.Error()
		} else if bad := validateKeyOverrides(b, parsed); len(bad) > 0 {
			pageVars.WarningMessage = "Key overrides have unknown target UUIDs: " + strings.Join(bad, "; ")
		} else {
			// Reload every shorthand touched by either the old or new set, so
			// removed overrides revert and added ones apply right away.
			affected := map[string]struct{}{}
			for shorthand := range GetKeyOverrides() {
				affected[shorthand] = struct{}{}
			}
			for shorthand := range parsed {
				affected[shorthand] = struct{}{}
			}
			if err := saveKeyOverrides(parsed); err != nil {
				pageVars.WarningMessage = "Key overrides save failed: " + err.Error()
			} else {
				s.reloadOverriddenScrapers(affected)
				pageVars.InfoMessage = "Key overrides updated"
				// Non-blocking: flag any chained remaps that slipped in.
				if chains := detectOverrideChains(parsed); len(chains) > 0 {
					pageVars.WarningMessage = "Chained overrides (ambiguous at load): " + strings.Join(chains, "; ")
				}
			}
		}
	}

	// -- Key overrides: load editor text (keep submitted text on failure) --
	if newOverrides != "" && pageVars.WarningMessage != "" {
		pageVars.KeyOverridesText = newOverrides
	} else if koText, err := currentKeyOverridesJSON(); err != nil {
		if pageVars.InfoMessage == "" {
			pageVars.InfoMessage = err.Error()
		}
	} else {
		pageVars.KeyOverridesText = koText
	}

	// -- Key overrides: store list for the builder dropdown --
	storeSet := map[string]struct{}{}
	for _, seller := range GetSellers() {
		storeSet[seller.Info().Shorthand] = struct{}{}
	}
	for _, v := range GetVendors() {
		storeSet[v.Info().Shorthand] = struct{}{}
	}
	stores := make([]string, 0, len(storeSet))
	for shorthand := range storeSet {
		stores = append(stores, shorthand)
	}
	sort.Strings(stores)
	pageVars.OverrideStores = stores

	// -- Key overrides: pre-fill the builder from a search "Fix" link. Store,
	// kind (retail/buylist) and the wrong card all come from the link; the wrong
	// card and its same-name printings are resolved here from the in-memory card
	// database and rendered straight into the page (no lookup endpoint). --
	if wrong := r.FormValue("fixwrong"); wrong != "" {
		if card, candidates := overrideFixCandidates(b, wrong); card != nil {
			pageVars.OverrideFixStore = r.FormValue("fixstore")
			pageVars.OverrideFixKind = r.FormValue("fixkind")
			pageVars.OverrideWrongCard = card
			pageVars.OverrideCandidates = candidates
		}
	}

	// now anchors every staleness check below, so one row is never compared
	// against a slightly later "now" than its neighbor.
	now := time.Now()

	// -- Dashboard: Retail Scrapers --
	var sellerTable [][]string
	for _, seller := range GetSellers() {
		key := "UNKNOWN"
		store, found := scraperStoreOf(seller.Info().Shorthand)
		if found {
			key = store
		}

		lastUpdate := ""
		if ts := seller.Info().InventoryTimestamp; !ts.IsZero() {
			lastUpdate = ts.UTC().Format(time.RFC3339)
		}
		inv := seller.Inventory()

		// A running workflow overrides this to 🔶 once the poll answers.
		status := "✅"
		if len(inv) == 0 {
			status = "🔴"
		}

		name := seller.Info().Name
		if seller.Info().SealedMode {
			name += " 📦"
		}
		if seller.Info().MetadataOnly {
			name += " 🎯"
		}

		ref := ""
		if slices.Contains(Affiliates().List, seller.Info().Shorthand) ||
			slices.Contains(Affiliates().List, key) {
			ref = "👍"
		}

		// A store published from an upload has no workflow to refresh it
		// or log it, and can be removed from here instead. One the config
		// has since claimed is a real store, whatever the registry says.
		session := ""
		if key == "UNKNOWN" && Sessions.Is(sessionstore.Retail, seller.Info().Shorthand) {
			key = "session"
			session = sessionstore.Retail
		}

		row := []string{
			name,
			seller.Info().Shorthand,
			key,
			lastUpdate,
			fmt.Sprint(len(inv)),
			ref,
			status,
			session,
			staleBadge(seller.Info().InventoryTimestamp, now),
		}
		sellerTable = append(sellerTable, row)
	}
	pageVars.Tables = append(pageVars.Tables, sellerTable)

	// -- Dashboard: Buylist Scrapers --
	var vendorTable [][]string
	for _, vendor := range GetVendors() {
		key := "UNKNOWN"
		store, found := scraperStoreOf(vendor.Info().Shorthand)
		if found {
			key = store
		}

		lastUpdate := ""
		if ts := vendor.Info().BuylistTimestamp; !ts.IsZero() {
			lastUpdate = ts.UTC().Format(time.RFC3339)
		}
		bl := vendor.Buylist()

		// A running workflow overrides this to 🔶 once the poll answers.
		status := "✅"
		if len(bl) == 0 {
			status = "🔴"
		}

		name := vendor.Info().Name
		if vendor.Info().SealedMode {
			name += " 📦"
		}
		if vendor.Info().MetadataOnly {
			name += " 🎯"
		}

		ref := ""
		if slices.Contains(Affiliates().BuylistList, vendor.Info().Shorthand) ||
			slices.Contains(Affiliates().BuylistList, key) {
			ref = "👍"
		}

		session := ""
		if key == "UNKNOWN" && Sessions.Is(sessionstore.Buylist, vendor.Info().Shorthand) {
			key = "session"
			session = sessionstore.Buylist
		}

		row := []string{
			name,
			vendor.Info().Shorthand,
			key,
			lastUpdate,
			fmt.Sprint(len(bl)),
			ref,
			status,
			session,
			staleBadge(vendor.Info().BuylistTimestamp, now),
		}
		vendorTable = append(vendorTable, row)
	}
	pageVars.Tables = append(pageVars.Tables, vendorTable)

	// -- Dashboard: Registered Pages --
	var pageTable [][]string
	for _, navName := range OrderNav {
		nav := ExtraNavs[navName]

		row := []string{
			nav.Short,
			nav.Name,
			nav.Link,
			nav.Page,
		}
		pageTable = append(pageTable, row)
	}
	pageVars.Tables = append(pageVars.Tables, pageTable)

	// -- People: quick-add a Patreon grant --
	// Reuses the config editor's persistence: the amended config is written
	// to the config source and swapped in memory, so the grant survives
	// restarts and shows in the table below immediately.
	grantEmail := strings.ToLower(strings.TrimSpace(r.FormValue("grantEmail")))
	if grantEmail != "" {
		grantTier := r.FormValue("grantTier")
		newGrant := PatreonGrant{
			Category: strings.TrimSpace(r.FormValue("grantCategory")),
			Email:    grantEmail,
			Name:     strings.TrimSpace(r.FormValue("grantName")),
			Tier:     grantTier,
		}

		var overridesErr error
		if raw := strings.TrimSpace(r.FormValue("grantOverrides")); raw != "" {
			overridesErr = json.Unmarshal([]byte(raw), &newGrant.Overrides)
		}

		duplicate := false
		for _, person := range PatreonGrants() {
			if strings.EqualFold(person.Email, grantEmail) {
				duplicate = true
				break
			}
		}
		_, tierExists := ACL()[grantTier]

		switch {
		case !strings.Contains(grantEmail, "@"):
			pageVars.WarningMessage = "invalid grant email: " + grantEmail
		case duplicate:
			pageVars.WarningMessage = grantEmail + " already has a grant"
		case !tierExists:
			pageVars.WarningMessage = "unknown tier: " + grantTier
		case overridesErr != nil:
			pageVars.WarningMessage = "invalid overrides JSON: " + overridesErr.Error()
		default:
			err := saveGrants(r.Context(), append(slices.Clone(PatreonGrants()), newGrant))
			if err != nil {
				log.Println(err)
				pageVars.WarningMessage = err.Error()
			} else {
				pageVars.InfoMessage = fmt.Sprintf("Granted %s tier to %s", newGrant.Tier, newGrant.Email)
				LogPages["Admin"].Printf("Grant added: %+v", newGrant)
			}
		}
	}

	// -- People: remove a Patreon grant --
	// Persists like the quick-add above, so the row disappears from the
	// table rendered below and stays gone after a restart.
	revokeEmail := strings.ToLower(strings.TrimSpace(r.FormValue("revokeEmail")))
	if revokeEmail != "" {
		idx := slices.IndexFunc(PatreonGrants(), func(person PatreonGrant) bool {
			return strings.EqualFold(person.Email, revokeEmail)
		})
		if idx < 0 {
			pageVars.WarningMessage = "no grant found for " + revokeEmail
		} else {
			grants := PatreonGrants()
			removed := grants[idx]

			err := saveGrants(r.Context(), slices.Delete(slices.Clone(grants), idx, idx+1))
			if err != nil {
				log.Println(err)
				pageVars.WarningMessage = err.Error()
			} else {
				pageVars.InfoMessage = fmt.Sprintf("Removed %s grant from %s", removed.Tier, removed.Email)
				LogPages["Admin"].Printf("Grant removed: %+v", removed)
			}
		}
	}

	// -- People: Patreon Grants --
	var userTable [][]string
	for i, person := range PatreonGrants() {
		overrides := ""
		if len(person.Overrides) > 0 {
			if raw, err := json.Marshal(person.Overrides); err == nil {
				overrides = string(raw)
			}
		}
		row := []string{
			fmt.Sprintf("%d", i+1),
			person.Category,
			person.Email,
			person.Name,
			person.Tier,
			overrides,
		}
		userTable = append(userTable, row)
	}
	pageVars.Tables = append(pageVars.Tables, userTable)

	// -- People: API Users --
	var apiTable [][]string
	for i, email := range apiUsers() {
		row := []string{
			fmt.Sprintf("%d", i+1),
			email,
		}
		apiTable = append(apiTable, row)
	}
	pageVars.Tables = append(pageVars.Tables, apiTable)

	// Pass current page to template for active tab
	pageVars.Page = page

	var tiers []string
	for tierName := range ACL() {
		tiers = append(tiers, tierName)
	}
	sort.Slice(tiers, func(i, j int) bool {
		return tiers[i] < tiers[j]
	})

	pageVars.Tiers = tiers
	pageVars.Uptime = uptime()
	pageVars.DiskStatus = disk()
	pageVars.MemoryStatus = mem()
	pageVars.LatestHash = BuildCommit

	pageVars.DisableChart = IsStashingInProgress()
	pageVars.Jobs = backgroundJobs.Rows()
	// Read last: ?reboot=datastore above may have just started one.
	pageVars.DatastoreReload = s.reloads.Status()

	// Only the Usage tab reads these aggregates and each one scans a 30-day
	// window, so leave them alone unless that is the tab being rendered.
	if ObservabilityDB != nil && page == "usage" {
		pageVars.UsageStats = loadUsageDashboard(r.Context(), r.FormValue("bots") == "1")
	}

	render(w, "admin.html", pageVars)
}

// adminActions runs the refresh, reload, removestore or logs action the
// request names, if any, and reports whether it answered the request. A
// logs name it does not know leaves a message for the page instead.
func (s *site) adminActions(w http.ResponseWriter, r *http.Request, pageVars *PageVars) bool {
	refresh := r.FormValue("refresh")
	if refresh != "" {
		v := url.Values{}
		_, found := currentScraperIndex().byStore[refresh]
		if !found {
			v.Set("msg", refresh+" not found")
		} else {
			err := sendGithubAction(Config().Game, refresh)
			if err != nil {
				v.Set("msg", "refresh of "+refresh+" error: "+err.Error())
			} else {
				v.Set("msg", "Scheduling a refresh for "+refresh+" in the background...")
			}
		}
		r.URL.RawQuery = v.Encode()
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return true
	}
	reload := r.FormValue("reload")
	if reload != "" {
		v := url.Values{}
		v.Set("msg", reload+" reloaded")
		err := loadScraper(DataBucket, Config().Game, reload, r.FormValue("table"), r.FormValue("tag"))
		if err != nil {
			v.Set("msg", "reload of "+reload+" error: "+err.Error())
		} else {
			s.pokeAlerts(r.FormValue("table"))
		}
		r.URL.RawQuery = v.Encode()
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return true
	}

	removeStore := r.FormValue("removestore")
	if removeStore != "" {
		v := url.Values{}
		v.Set("msg", removeStore+" removed")
		err := Sessions.Remove(r.FormValue("kind"), removeStore)
		if err != nil {
			v.Set("msg", "remove of "+removeStore+" error: "+err.Error())
		}
		r.URL.RawQuery = v.Encode()
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return true
	}

	logs := r.FormValue("logs")
	if logs != "" {
		// Check among the Page loggers
		_, found := LogPages[logs]
		if found {
			logfilePath := path.Join(LogDir, logs+".log")
			LogPages["Admin"].Println("Serving", logfilePath)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", "inline; filename="+logs+".log")

			if fileExists(logfilePath + ".1") {
				http.ServeFile(w, r, logfilePath+".1")
			}
			http.ServeFile(w, r, logfilePath)
			return true
		}

		// If it's not a Page, look if the last listing named it as a store
		_, found = currentScraperIndex().byStore[logs]
		if found {
			link := fmt.Sprintf(gaLogURL, newBantoolWorkflow(Config().Game, logs).File)
			http.Redirect(w, r, link, http.StatusFound)
			return true
		}

		// Otherwise, 404
		pageVars.InfoMessage = logs + " not found"
	}
	return false
}

// adminTools runs the server action or admin tool the request names, if
// any, and reports whether it answered with a redirect. A datastore reload
// answers on the page instead, through its message.
func (s *site) adminTools(w http.ResponseWriter, r *http.Request, pageVars *PageVars) bool {
	reboot := r.FormValue("reboot")
	doReboot := false
	var v url.Values
	switch reboot {
	case "datastore", "datastore-backup":
		dsPath := Config().DatastorePath
		if reboot == "datastore-backup" {
			// The backup may live somewhere else entirely, which used to mean
			// building a second bucket by hand. The path names where it is.
			dsPath = Config().Datastore.BackupPath
			if dsPath == "" {
				v = url.Values{}
				v.Set("msg", "No BackupPath set in config")
				doReboot = true
			}
		}
		if s.startDatastoreReload(dsPath, "admin") {
			pageVars.InfoMessage = "Reloading the datastore, this page will say when it is done..."
		} else {
			pageVars.InfoMessage = "A datastore reload is already running, this one will start when it ends"
		}

	case "config":
		v = url.Values{}
		v.Set("msg", "New config loaded!")
		doReboot = true

		err := reloadConfig()
		if err != nil {
			v.Set("msg", "Failed to reload config: "+err.Error())
		} else {
			// The access table and the grants sit beside the config now, so a
			// reload that stopped at the config would leave them as they were.
			err = loadCommonConfig(r.Context())
			if err != nil {
				v.Set("msg", "Config reloaded, but: "+err.Error())
			}
		}

	case "checkpoints":
		v = url.Values{}
		doReboot = true

		err := reloadCheckpoints()
		if err != nil {
			v.Set("msg", "Failed to reload checkpoints: "+err.Error())
		} else {
			v.Set("msg", "Chart checkpoints reloaded")
		}

	case "snapshot":
		v = url.Values{}
		v.Set("msg", "Moving data to timeseries in the background...")
		doReboot = true

		if IsStashingInProgress() {
			v.Set("msg", "Stashing is already in progress")
		} else {
			go tracked(jobStash, s.stashInTimeseries)()
		}

	case "tcgcsv":
		v = url.Values{}
		v.Set("msg", "Ingesting latest TCGCSV prices in the background...")
		doReboot = true

		if IsTCGCSVStashing() {
			v.Set("msg", "TCGCSV ingestion is already in progress")
		} else {
			go tracked(jobTCGCSVPrices, stashTCGCSVPrices)()
		}

	case "server":
		v = url.Values{}
		v.Set("msg", "Restarting the server...")
		doReboot = true

		// Let the system restart the server
		go func() {
			time.Sleep(5 * time.Second)
			log.Println("Admin requested server restart")
			os.Exit(0)
		}()

	case "newKey", "demokey":
		v = url.Values{}
		doReboot = true

		user := r.FormValue("user")
		if user == "" {
			user = DefaultAPIDemoUser
		}
		dur := r.FormValue("duration")
		// A blank duration is the picker back on its placeholder, not a request for a permanent key.
		if dur == "" {
			dur = "30"
		}
		duration, err := strconv.Atoi(dur)
		if err != nil {
			duration = 30
		}

		key, err := generateAPIKey(r.Context(), user, time.Duration(duration)*24*time.Hour)
		msg := key
		if err != nil {
			msg = "error: " + err.Error()
		}

		v.Set("msg", msg)
		v.Set("html", "textfield")

	case "invite":
		v = url.Values{}
		doReboot = true

		tier := r.FormValue("tier")

		// How long the link is good for, in days. A request that names no
		// duration - an old bookmark, a hand-written URL - gets the length a
		// login gets, which is what this tool handed out before it could be
		// asked for anything else.
		duration := DefaultSignatureDuration
		days, err := strconv.Atoi(r.FormValue("duration"))
		if err == nil && days > 0 {
			duration = time.Duration(days) * 24 * time.Hour
		}
		msg := absoluteURL(r, "/?sig="+sign(tier, nil, nil, duration))

		v.Set("msg", msg)
		v.Set("html", "invite")
	}
	if doReboot {
		r.URL.RawQuery = v.Encode()
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return true
	}
	return false
}

// usageCacheTTL bounds how stale the Usage tab may be. Everything behind it
// aggregates a 30-day window, so the numbers barely move minute to minute and
// a reload costs nothing until the copy ages out.
const usageCacheTTL = 5 * time.Minute

// UsageDashboard holds the telemetry aggregates rendered on /admin?page=usage.
type UsageDashboard struct {
	Since       time.Time
	IncludeBots bool
	Instance    string
	TopPages    []observability.PathAgg
	ByTier      []observability.TierAgg
	ByDevice    []observability.DeviceAgg
	SubViews    []observability.PathAgg
}

type usageCacheEntry struct {
	dash    *UsageDashboard
	fetched time.Time
}

// usageCache holds one entry per bots setting, the only axis the dashboard
// varies on. The lock covers the queries as well as the map, so a second
// viewer waits for the first one's answer instead of starting the same scans.
var usageCache = struct {
	mu     sync.Mutex
	byBots map[bool]usageCacheEntry
}{byBots: map[bool]usageCacheEntry{}}

// loadUsageDashboard returns the telemetry aggregates for the Usage tab,
// reusing a recent copy when there is one.
func loadUsageDashboard(ctx context.Context, includeBots bool) *UsageDashboard {
	usageCache.mu.Lock()
	defer usageCache.mu.Unlock()

	entry, found := usageCache.byBots[includeBots]
	if found && time.Since(entry.fetched) < usageCacheTTL {
		return entry.dash
	}

	since := time.Now().AddDate(0, 0, -30)
	dash := &UsageDashboard{Since: since, IncludeBots: includeBots, Instance: observabilityInstance}

	failed := false
	var err error
	dash.TopPages, err = ObservabilityDB.TopPages(ctx, since, includeBots, observabilityInstance)
	if err != nil {
		log.Println("usage: top pages:", err)
		failed = true
	}
	dash.ByTier, err = ObservabilityDB.UsageByTier(ctx, since, includeBots, observabilityInstance)
	if err != nil {
		log.Println("usage: by tier:", err)
		failed = true
	}
	dash.ByDevice, err = ObservabilityDB.DeviceSplit(ctx, since, includeBots, observabilityInstance)
	if err != nil {
		log.Println("usage: device split:", err)
		failed = true
	}
	dash.SubViews = subViewsOf(dash.TopPages)

	// A query that failed leaves its table empty, so let the next view retry
	// rather than serving the gap for the rest of the window.
	if !failed {
		usageCache.byBots[includeBots] = usageCacheEntry{dash: dash, fetched: time.Now()}
	}

	return dash
}

// subViewPrefixes are the paths the Usage tab breaks out in their own table.
var subViewPrefixes = []string{"newspaper/", "sleepers/"}

// subViewsOf narrows the per-path aggregate to the sub-view rows. The database
// used to answer this with a second query, identical to the one behind
// TopPages but for a prefix filter on path. That filter tests the grouping key
// alone, so it can be applied here to the same effect - as long as TopPages
// stays unlimited, or rows past its cut would go missing from this table.
func subViewsOf(all []observability.PathAgg) []observability.PathAgg {
	var out []observability.PathAgg
	for _, agg := range all {
		for _, prefix := range subViewPrefixes {
			if strings.HasPrefix(agg.Path, prefix) {
				out = append(out, agg)
				break
			}
		}
	}
	return out
}

func isBusyGithubAction(wf bantoolWorkflow) (bool, error) {
	totProgres, err := queryGithubAction(wf.File, "in_progress")
	if err != nil {
		return false, errors.New("cannot retrieve in_progress status")
	}
	totQueue, err := queryGithubAction(wf.File, "queued")
	if err != nil {
		return false, errors.New("cannot retrieve queued status")
	}
	if totProgres+totQueue > 0 {
		return true, nil
	}
	return false, nil
}

func queryGithubAction(file, state string) (int, error) {
	url := workflowURL + file + "/runs?status=" + state

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config().API["github_action_token"])

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return 0, errors.New("unsupported status code")
	}

	var payload struct {
		TotalCount int `json:"total_count"`
	}
	err = json.NewDecoder(resp.Body).Decode(&payload)
	if err != nil {
		return 0, err
	}
	return payload.TotalCount, nil
}

func sendGithubAction(game mtgmatcher.Game, store string) error {
	wf := newBantoolWorkflow(game, store)

	busy, err := isBusyGithubAction(wf)
	if err != nil {
		return err
	}
	if busy {
		return errors.New("job already running")
	}

	payload := strings.NewReader(`{"event_type":"` + wf.EventType + `"}`)
	req, err := http.NewRequest(http.MethodPost, dispatchURL, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config().API["github_action_token"])

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return nil
}

// serveRunningWorkflows answers the dashboard's status poll.
func serveRunningWorkflows(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	err := json.NewEncoder(w).Encode(struct {
		Running []string `json:"running"`
	}{runningWorkflows()})
	if err != nil {
		log.Println("workflow status:", err)
	}
}

// runningWorkflows lists the workflows queued or in progress. The two states
// are queried at once: they are independent, and serialized they doubled the
// wait. Empty without a token to ask with, and on failure - the dashboard
// simply leaves its rows as rendered. A state whose fetch panics is skipped
// the same way, once the panic is reported.
func runningWorkflows() []string {
	if Config().API["github_action_token"] == "" {
		return nil
	}

	states := []string{"in_progress", "queued"}
	results := make([][]string, len(states))

	var wg sync.WaitGroup
	for i, state := range states {
		wg.Go(func() {
			defer recoverJob("admin workflow fetch " + state)
			names, err := gaFetch(state)
			if err != nil {
				log.Println(err)
				return
			}
			results[i] = names
		})
	}
	wg.Wait()

	var names []string
	for _, result := range results {
		names = append(names, result...)
	}
	return names
}

// overridable in tests
var gaFetch = snapshotGithubAction

func snapshotGithubAction(state string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gaStatusURL+state, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config().API["github_action_token"])

	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, errors.New("unsupported status code")
	}

	var payload struct {
		TotalCount   int `json:"total_count"`
		WorkflowRuns []struct {
			Name string `json:"name"`
		} `json:"workflow_runs"`
	}
	err = json.NewDecoder(resp.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, payload.TotalCount)
	for _, run := range payload.WorkflowRuns {
		names = append(names, run.Name)
	}

	return names, nil
}

// Custom time.Duration format to print days as well
func uptime() string {
	since := time.Since(StartTime)
	days := int(since.Hours() / 24)
	hours := int(since.Hours()) % 24
	minutes := int(since.Minutes()) % 60
	seconds := int(since.Seconds()) % 60
	return fmt.Sprintf("%d days, %02d:%02d:%02d", days, hours, minutes, seconds)
}

func mem() string {
	memData, err := memory.Get()
	if err != nil {
		return "N/A"
	}
	return fmt.Sprintf("%.2f%% of %.2fGB", float64(memData.Used)/float64(memData.Total)*100, float64(memData.Total)/1024/1024/1024)
}

func disk() string {
	wd, err := os.Getwd()
	if err != nil {
		return "N/A"
	}
	used, total, err := diskusage.Stats(wd)
	if err != nil || total == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.2f%% of %.2fGB", float64(used)/float64(total)*100, float64(total)/1024/1024/1024)
}

const DefaultAPIDemoUser = "demo@mtgban.com"

func writeConfigFile(config ConfigType, writer io.Writer) error {
	e := json.NewEncoder(writer)
	// Avoids & -> \u0026 and similar
	e.SetEscapeHTML(false)
	e.SetIndent("", "    ")
	return e.Encode(&config)
}

// configEditorText is the live config as the admin editor shows it.
func configEditorText() (string, error) {
	var text bytes.Buffer
	err := writeConfigFile(*Config(), &text)
	return text.String(), err
}

// apiUsers lists the users that hold an API secret, sorted.
func apiUsers() []string {
	var emails []string
	for email := range Config().APIUserSecrets {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	return emails
}

// storeConfigFile writes config to the config file, giving up after
// configFileTimeout.
func storeConfigFile(ctx context.Context, config ConfigType) error {
	ctx, cancel := context.WithTimeout(ctx, configFileTimeout)
	defer cancel()
	writer, err := simplecloud.InitWriter(ctx, ConfigBucket, Config().sourcePath)
	if err != nil {
		return err
	}
	err = writeConfigFile(config, writer)
	// Close finalises the upload, so its error is the write's error too, and
	// a failure there must not be reported as a save.
	cerr := writer.Close()
	if err != nil {
		return err
	}
	return cerr
}

// saveConfig writes config to the config file and, once it is there, makes
// it the live one: the admin editor's save.
func saveConfig(ctx context.Context, config ConfigType) error {
	configMu.Lock()
	defer configMu.Unlock()

	err := storeConfigFile(ctx, config)
	if err != nil {
		return err
	}
	config.sourcePath = Config().sourcePath
	// No applyOverrides: the saved text goes live as written. With the
	// running values, the editor would re-render the old ones and the next
	// save would write them back to the file.
	finishConfig(config)
	return nil
}

func generateAPIKey(ctx context.Context, user string, duration time.Duration) (string, error) {
	if user == "" {
		return "", errors.New("missing user")
	}
	if user == DefaultAPIDemoUser && duration == 0 {
		return "", errors.New("demo user API keys must expire")
	}

	configMu.Lock()
	defer configMu.Unlock()

	key, found := Config().APIUserSecrets[user]
	if !found {
		var err error
		key, err = randomString(15)
		if err != nil {
			return "", err
		}

		if Config().APIUserSecrets == nil {
			return "", errors.New("config not loaded")
		}

		// Saved before it goes live, so a save that fails, even by
		// panicking, leaves no key behind.
		secrets := make(map[string]string, len(Config().APIUserSecrets)+1)
		for email, secret := range Config().APIUserSecrets {
			secrets[email] = secret
		}
		secrets[user] = key
		config := *Config()
		config.APIUserSecrets = secrets
		err = storeConfigFile(ctx, config)
		if err != nil {
			return "", err
		}

		liveConfig.Store(&config)
	}

	claims := apisig.Claims{
		API:    "ALL_ACCESS",
		Fields: url.Values{apisig.APIFields[0]: {"all"}, apisig.APIFields[1]: {user}},
	}
	if duration != 0 {
		claims.Expires = time.Now().Add(duration).Unix()
	}

	link := signatureLink()
	return apisig.Mint([]byte(key), link, claims), nil
}

// randomString returns l printable ASCII characters (33 through 125) read
// from crypto/rand: the result names an API secret, so it has to be
// unpredictable, not merely uniform.
func randomString(l int) (string, error) {
	out := make([]byte, 0, l)
	buf := make([]byte, 64)
	for len(out) < l {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			// 93 characters divide 255 unevenly; rejecting the tail past
			// their largest multiple keeps the draw uniform.
			if b >= 186 {
				continue
			}
			out = append(out, 33+b%93)
			if len(out) == l {
				break
			}
		}
	}
	return string(out), nil
}

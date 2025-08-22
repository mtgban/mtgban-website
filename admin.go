package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"golang.org/x/exp/slices"

	"github.com/mackerelio/go-osstat/memory"
)

const (
	mtgjsonURL = "https://mtgjson.com/api/v5/AllPrintings.json"

	dispatchURL = "https://api.github.com/repos/mtgban/go-mtgban/dispatches"
	workflowURL = "https://api.github.com/repos/mtgban/go-mtgban/actions/workflows/"
	gaStatusURL = "https://api.github.com/repos/mtgban/go-mtgban/actions/runs?status="
)

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

func Admin(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)

	page := r.FormValue("page")
	pageVars := genPageNav("Admin", sig)
	pageVars.Nav = insertNavBar("Admin", pageVars.Nav, []NavElem{
		NavElem{
			Name:   "People",
			Short:  "👥",
			Link:   "/admin?page=people",
			Active: page == "people",
			Class:  "selected",
		},
		NavElem{
			Name:   "Config",
			Short:  "🗒️",
			Link:   "/admin?page=config",
			Active: page == "config",
			Class:  "selected",
		},
	})

	var gaScrapers []string
	for _, state := range []string{"in_progress", "queued"} {
		scrapers, err := snapshotGithubAction(state)
		if err != nil {
			log.Println(err)
		}
		gaScrapers = append(gaScrapers, scrapers...)
	}

	msg := r.FormValue("msg")
	if msg != "" {
		pageVars.InfoMessage = msg
	}
	html := r.FormValue("html")
	if html == "textfield" {
		pageVars.SelectableField = true
	}

	refreshNew := r.FormValue("refresh_new")
	if refreshNew != "" {
		key, found := ScraperMap[refreshNew]
		if !found {
			pageVars.InfoMessage = refreshNew + " not found"
		}
		if key != "" {
			_, found := ScraperOptions[key]
			if !found {
				pageVars.InfoMessage = key + " not found"
			} else {
				// Strip the request parameter to avoid accidental repeats
				// and to give a chance to table to update
				r.URL.RawQuery = ""
				if ScraperOptions[key].Busy() {
					v := url.Values{
						"msg": {key + " is already being refreshed"},
					}
					r.URL.RawQuery = v.Encode()
				} else {
					err := sendGithubAction(key)
					if err != nil {
						v := url.Values{
							"msg": {key + " error: " + err.Error()},
						}
						r.URL.RawQuery = v.Encode()
					}
				}

				http.Redirect(w, r, r.URL.String(), http.StatusFound)
				return
			}
		}
	}

	logs := r.FormValue("logs")
	if logs != "" {
		_, found := LogPages[logs]
		if !found {
			pageVars.InfoMessage = logs + " not found"
		} else {
			logfilePath := path.Join(LogDir, logs+".log")
			LogPages["Admin"].Println("Serving", logfilePath)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", "inline; filename="+logs+".log")

			if fileExists(logfilePath + ".1") {
				http.ServeFile(w, r, logfilePath+".1")
			}
			http.ServeFile(w, r, logfilePath)
			return
		}
	}

	reboot := r.FormValue("reboot")
	doReboot := false
	var v url.Values
	switch reboot {
	case "mtgjson":
		v = url.Values{}
		v.Set("msg", "Reloading MTGJSON in the background...")
		doReboot = true

		go func() {
			log.Println("Retrieving the latest version of mtgjson")
			resp, err := cleanhttp.DefaultClient().Get(mtgjsonURL)
			if err != nil {
				log.Println(err)
				return
			}
			defer resp.Body.Close()

			log.Println("Loading the new mtgjson version")
			err = mtgmatcher.LoadDatastore(resp.Body)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("New mtgjson is ready")
		}()

	case "update":
		v = url.Values{}
		v.Set("msg", "Deploying...")
		doReboot = true

		go func() {
			out, err := pullCode()
			if err != nil {
				log.Println("git -", err)
				return
			}
			log.Println(out)

			out, err = build()
			if err != nil {
				log.Println("go -", err)
				return
			}
			log.Println(out)

			log.Println("Restarting")
			os.Exit(0)
		}()

	case "build", "code":
		v = url.Values{}
		doReboot = true

		var out string
		var err error
		if reboot == "build" {
			out, err = build()
		} else if reboot == "code" {
			out, err = pullCode()
		}
		if err != nil {
			log.Println(err)
			v.Set("msg", err.Error())
		} else {
			log.Println(out)
			v.Set("msg", out)
		}

	case "config":
		v = url.Values{}
		v.Set("msg", "New config loaded!")
		doReboot = true

		err := loadVars(Config.filePath, "", "")
		if err != nil {
			v.Set("msg", "Failed to reload config: "+err.Error())
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

	case "demokey":
		key, err := generateAPIKey(getBaseURL(r), DefaultAPIDemoUser, DefaultAPIDemoKeyDuration)
		if err != nil {
			log.Println(err)
			pageVars.InfoMessage = err.Error()
			break
		}
		pageVars.DemoKey = url.QueryEscape(key)

		log.Println(pageVars.DemoKey)

	case "newKey":
		v = url.Values{}
		doReboot = true

		user := r.FormValue("user")
		dur := r.FormValue("duration")
		duration, _ := strconv.Atoi(dur)

		key, err := generateAPIKey(getBaseURL(r), user, time.Duration(duration)*24*time.Hour)
		msg := key
		if err != nil {
			msg = "error: " + err.Error()
		}

		v.Set("msg", msg)
		v.Set("html", "textfield")

	case "spoof":
		v = url.Values{}
		doReboot = true

		tier := r.FormValue("tier")
		baseURL := getBaseURL(r)
		msg := baseURL + "/?sig=" + sign(baseURL, tier, nil)

		v.Set("msg", msg)
		v.Set("html", "textfield")
	}
	if doReboot {
		r.URL.RawQuery = v.Encode()
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return
	}

	switch page {
	case "people":
		pageVars.DisableLinks = true

		pageVars.Headers = [][]string{
			[]string{"", "#", "Category", "Email", "Name", "Tier"},
			[]string{"", "#", "API User"},
		}

		var userTable [][]string
		for i, person := range Config.Patreon.Grants {
			row := []string{
				fmt.Sprintf("%d", i+1),
				person.Category,
				person.Email,
				person.Name,
				person.Tier,
			}

			userTable = append(userTable, row)
		}
		pageVars.Tables = append(pageVars.Tables, userTable)

		// Sort before show
		var emails []string
		for person := range Config.ApiUserSecrets {
			emails = append(emails, person)
		}
		sort.Strings(emails)

		var apiTable [][]string
		for i, email := range emails {
			row := []string{
				fmt.Sprintf("%d", i+1),
				email,
			}

			apiTable = append(apiTable, row)
		}
		pageVars.Tables = append(pageVars.Tables, apiTable)

	case "config":
		newConfig := r.FormValue("textArea")
		if newConfig != "" {
			var config ConfigType
			configFilePath := Config.filePath

			// Test if data can be unmarshaled
			err := json.Unmarshal([]byte(newConfig), &config)
			if err != nil {
				pageVars.InfoMessage = err.Error()
				pageVars.CleanSearchQuery = newConfig
				break
			}

			// Test if file is writable
			file, err := os.Create(configFilePath)
			if err != nil {
				log.Println(err)
				pageVars.InfoMessage = err.Error()
				pageVars.CleanSearchQuery = newConfig
				break
			}
			defer file.Close()

			// Test if writing the permanent config is ok
			err = writeConfigFile(config, file)
			if err != nil {
				log.Println(err)
				pageVars.InfoMessage = err.Error()
				pageVars.CleanSearchQuery = newConfig
				break
			}

			// Only then update the running configuration
			Config = config

			// Preserve the current filepath
			Config.filePath = configFilePath

			pageVars.InfoMessage = "Config updated"
		}

		// Load the current configuration and save it in text
		var out bytes.Buffer
		err := writeConfigFile(Config, &out)
		if err != nil {
			pageVars.InfoMessage = err.Error()
		}
		pageVars.CleanSearchQuery = out.String()

	default:
		var sellerTable [][]string
		for i := range Sellers {
			if Sellers[i] == nil {
				row := []string{
					fmt.Sprintf("Error at Seller %d", i), "", "", "", "", "",
				}
				sellerTable = append(sellerTable, row)
				continue
			}

			key := "UNKNOWN"
			for name, scrapersConfig := range Config.ScraperConfig.Config {
				if slices.Contains(scrapersConfig["retail"], Sellers[i].Info().Shorthand) {
					key = name
					break
				}
			}

			lastUpdate := Sellers[i].Info().InventoryTimestamp.Format(time.Stamp)

			inv, _ := Sellers[i].Inventory()

			status := "✅"
			if slices.Contains(gaScrapers, key) {
				status = "🔶"
			} else if len(inv) == 0 {
				status = "🔴"
			}

			name := Sellers[i].Info().Name
			if Sellers[i].Info().SealedMode {
				name += " 📦"
			}
			if Sellers[i].Info().MetadataOnly {
				name += " 🎯"
			}

			ref := ""
			if slices.Contains(Config.AffiliatesList, Sellers[i].Info().Shorthand) ||
				slices.Contains(Config.AffiliatesList, key) {
				ref = "👍"
			}

			row := []string{
				name,
				Sellers[i].Info().Shorthand,
				key,
				lastUpdate,
				fmt.Sprint(len(inv)),
				ref,
				status,
			}

			sellerTable = append(sellerTable, row)
		}
		pageVars.Headers = append(pageVars.Headers, []string{
			"", "Name", "Id", "Tag", "Last Update", "Entries", "Ref", "Status",
		})
		pageVars.Tables = append(pageVars.Tables, sellerTable)

		var vendorTable [][]string
		for i := range Vendors {
			if Vendors[i] == nil {
				row := []string{
					fmt.Sprintf("Error at Vendor %d", i), "", "", "", "", "",
				}
				vendorTable = append(vendorTable, row)
				continue
			}

			key := "UNKNOWN"
			for name, scrapersConfig := range Config.ScraperConfig.Config {
				if slices.Contains(scrapersConfig["buylist"], Vendors[i].Info().Shorthand) {
					key = name
					break
				}
			}

			lastUpdate := Vendors[i].Info().BuylistTimestamp.Format(time.Stamp)

			bl, _ := Vendors[i].Buylist()

			status := "✅"
			if slices.Contains(gaScrapers, key) {
				status = "🔶"
			} else if len(bl) == 0 {
				status = "🔴"
			}

			name := Vendors[i].Info().Name
			if Vendors[i].Info().SealedMode {
				name += " 📦"
			}
			if Vendors[i].Info().MetadataOnly {
				name += " 🎯"
			}

			ref := ""
			if slices.Contains(Config.AffiliatesBuylistList, Vendors[i].Info().Shorthand) ||
				slices.Contains(Config.AffiliatesBuylistList, key) {
				ref = "👍"
			}

			row := []string{
				name,
				Vendors[i].Info().Shorthand,
				key,
				lastUpdate,
				fmt.Sprint(len(bl)),
				ref,
				status,
			}

			vendorTable = append(vendorTable, row)
		}
		pageVars.Headers = append(pageVars.Headers, []string{
			"", "Name", "Id", "Tag", "Last Update", "Entries", "Ref", "Status",
		})
		pageVars.Tables = append(pageVars.Tables, vendorTable)

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
		pageVars.Headers = append(pageVars.Headers, []string{
			"", "Icon", "Logs", "Link", "Template",
		})
		pageVars.Tables = append(pageVars.Tables, pageTable)
	}

	var tiers []string
	for tierName := range Config.ACL {
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
	pageVars.CurrentTime = time.Now()

	render(w, "admin.html", pageVars)
}

func isBusyGithubAction(key string) (bool, error) {
	totProgres, err := queryGithubAction(key, "in_progress")
	if err != nil {
		return false, errors.New("cannot retrieve in_progress status")
	}
	totQueue, err := queryGithubAction(key, "queued")
	if err != nil {
		return false, errors.New("cannot retrieve queued status")
	}
	if totProgres+totQueue > 0 {
		return true, nil
	}
	return false, nil
}

func queryGithubAction(key, state string) (int, error) {
	url := workflowURL + "bantool-" + strings.Replace(key, "_", "-", -1) + ".yml/runs?status=" + state

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config.Api["github_action_token"])

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

func sendGithubAction(key string) error {
	_, found := ScraperOptions[key]
	if !found {
		return errors.New("key not found")
	}

	busy, err := isBusyGithubAction(key)
	if err != nil {
		return err
	}
	if busy {
		return errors.New("job already running")
	}

	payload := strings.NewReader(`{"event_type":"` + key + `"}`)
	req, err := http.NewRequest(http.MethodPost, dispatchURL, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config.Api["github_action_token"])

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

func snapshotGithubAction(state string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gaStatusURL+state, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+Config.Api["github_action_token"])

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

func pullCode() (string, error) {
	gitExecPath, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	log.Println("Found git at", gitExecPath)

	var out bytes.Buffer

	for _, cmds := range [][]string{
		[]string{"fetch"}, []string{"reset", "--hard", "origin/master"},
	} {
		cmd := exec.Command(gitExecPath, cmds...)
		cmd.Stdout = &out

		log.Println("Running git", strings.Join(cmds, " "))
		err = cmd.Run()
		if err != nil {
			return "", err
		}
	}

	return out.String(), nil
}

func build() (string, error) {
	goExecPath, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	log.Println("Found go at", goExecPath)

	var out bytes.Buffer
	cmd := exec.Command(goExecPath, "build")
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	if out.Len() == 0 {
		return "Build successful", nil
	}

	return "", errors.New(out.String())
}

// Custom time.Duration format to print days as well
func uptime() string {
	since := time.Since(startTime)
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

const (
	DefaultAPIDemoKeyDuration = 30 * 24 * time.Hour
	DefaultAPIDemoUser        = "demo@mtgban.com"
)

var apiUsersMutex sync.RWMutex

func writeConfigFile(config ConfigType, writer io.Writer) error {
	e := json.NewEncoder(writer)
	// Avoids & -> \u0026 and similar
	e.SetEscapeHTML(false)
	e.SetIndent("", "    ")
	return e.Encode(&config)
}

func generateAPIKey(link, user string, duration time.Duration) (string, error) {
	if user == "" {
		return "", errors.New("missing user")
	}

	apiUsersMutex.RLock()
	key, found := Config.ApiUserSecrets[user]
	apiUsersMutex.RUnlock()

	if !found {
		key = randomString(15)

		if Config.ApiUserSecrets == nil {
			return "", errors.New("config not loaded")
		}

		apiUsersMutex.Lock()
		Config.ApiUserSecrets[user] = key
		apiUsersMutex.Unlock()

		file, err := os.Create(Config.filePath)
		if err != nil {
			return "", err
		}
		defer file.Close()

		err = writeConfigFile(Config, file)
		if err != nil {
			return "", err
		}
	}

	v := url.Values{}
	v.Set("API", "ALL_ACCESS")
	v.Set("APImode", "all")
	v.Set("UserEmail", user)

	var exp string
	if duration != 0 {
		expires := time.Now().Add(duration)
		exp = fmt.Sprintf("%d", expires.Unix())
		v.Set("Expires", exp)
	}

	data := fmt.Sprintf("GET%s%s%s", exp, link, v.Encode())
	sig := signHMACSHA1Base64([]byte(key), []byte(data))

	v.Set("Signature", sig)
	return base64.StdEncoding.EncodeToString([]byte(v.Encode())), nil
}

// 32-126 are the printable characters in ashii, 33 excludes space
func randomString(l int) string {
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(33 + rand.Intn(126-33))
	}
	return string(bytes)
}

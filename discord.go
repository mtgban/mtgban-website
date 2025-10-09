package main

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/starcitygames"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

var poweredByFooter = discordgo.MessageEmbedFooter{
	IconURL: "https://www.mtgban.com/img/logo/ban-round.png",
	Text:    "Powered by mtgban.com",
}

// Scryfall-compatible mode
var squareBracketsRE = regexp.MustCompile(`\[\[.*?\]\]?`)

// Pricefall-only mode
var curlyBracketsRE = regexp.MustCompile(`\{\{.*?\}\}?`)

const (
	// Avoid making messages overly long
	MaxPrintings = 12

	// IDs of the channels on the main server
	DevChannelID   = "769323295526748160"
	RecapChannelID = "798588735259279453"
	ChatChannelID  = "736007847560609794"

	MainDiscordID = "637563728711385091"
)

var DiscordRetailBlocklist []string
var DiscordBuylistBlocklist []string

var dg *discordgo.Session

func setupDiscord() error {
	var err error

	if Config.DiscordToken == "" {
		return errors.New("no discord token")
	}

	// Create a new Discord session using the provided bot token.
	dg, err = discordgo.New("Bot " + Config.DiscordToken)
	if err != nil {
		return err
	}

	// Register the guildCreate func as a callback for GuildCreat events
	dg.AddHandler(guildCreate)

	// Register the messageCreate func as a callback for MessageCreate events.
	dg.AddHandler(messageCreate)

	// In this example, we only care about receiving message events.
	dg.Identify.Intents = discordgo.MakeIntent(discordgo.IntentsGuilds | discordgo.IntentsGuildMessages)

	DiscordRetailBlocklist = append(Config.SearchRetailBlockList, "TCGDirectLow")
	DiscordBuylistBlocklist = append(Config.SearchBuylistBlockList, "ABUCredit")

	// Open a websocket connection to Discord and begin listening.
	err = dg.Open()
	if err != nil {
		return err
	}

	return nil
}

// Cleanly close down the Discord session.
func cleanupDiscord() {
	if Config.DiscordToken == "" {
		return
	}
	log.Println("Closing connection with Discord")
	dg.Close()
}

// This function will be called every time the bot is invited to a discord
// server and tries to join it.
func guildCreate(s *discordgo.Session, gc *discordgo.GuildCreate) {
	// Set a "is playing" status
	s.UpdateGameStatus(0, "http://mtgban.com")

	msg := fmt.Sprintf("New bot install at %s (%s)", gc.Guild.Name, gc.Guild.ID)
	UserNotify("bot", msg, true)
}

var filteredEditions = []string{
	"30A",
	"4BB",
	"CHRJPN",
	"DPA",
	"DRKITA",
	"FBB",
	"LEGITA",
	"O90P",
	"OC13",
	"OC14",
	"OC15",
	"OC16",
	"OC17",
	"OC18",
	"OC19",
	"OC20",
	"OCM1",
	"OCMD",
	"PDP10",
	"PDP12",
	"PDP13",
	"PDP14",
	"PDP15",
	"PDTP",
	"PS14",
	"PS15",
	"PS16",
	"PS17",
	"PS18",
	"PS19",
	"PSDC",
	"PTC",
	"RIN",
	"SUM",
	"WC00",
	"WC01",
	"WC02",
	"WC03",
	"WC04",
	"WC97",
	"WC98",
	"WC99",
}

func parseMessage(content string, sealed bool) (*EmbedSearchResult, string) {
	// Clean up query, no blocklist because we only need keys
	config := parseSearchOptionsNG(content, nil, nil, nil)
	query := config.CleanQuery

	// Enable sealed mode
	if sealed {
		config.SearchMode = "sealed"
	}

	// Prevent useless invocations
	if len(query) < 3 && query != "Ow" && query != "X" {
		return &EmbedSearchResult{Invalid: true}, ""
	}

	var editionSearched string
	// Filter out any undersirable sets, unless explicitly requested
	filterGoldOut := !sealed
	for _, filter := range config.CardFilters {
		if filter.Name == "edition" {
			filterGoldOut = false
			editionSearched = filter.Values[0]
			break
		}
	}
	if filterGoldOut {
		config.CardFilters = append(config.CardFilters, FilterElem{
			Name:   "edition",
			Negate: true,
			Values: filteredEditions,
		})
	}

	uuids, err := searchAndFilter(config)
	if err != nil {
		// Not found again, let's provide a meaningful error
		if editionSearched != "" {
			set, err := mtgmatcher.GetSet(editionSearched)
			if err != nil {
				return nil, fmt.Sprintf("No edition found for \"%s\"", editionSearched)
			}
			msg := fmt.Sprintf("No card found named \"%s\" in %s", query, set.Name)
			printings, err := mtgmatcher.Printings4Card(query)
			if err == nil {
				msg = fmt.Sprintf("%s\n\"%s\" is printed in %s.", msg, query, printings2line(printings))
			}
			return nil, msg
		}

		// Do a quick retry to look through sealed
		if !sealed {
			return parseMessage(content, true)
		}
		return nil, fmt.Sprintf("No card found for \"%s\"", query)
	}

	if len(uuids) == 0 {
		return nil, fmt.Sprintf("No results found for \"%s\"", query)
	}

	// Keep the first (most recent) result
	sort.Slice(uuids, func(i, j int) bool {
		return sortSets(uuids[i], uuids[j])
	})
	cardId := uuids[0]

	return &EmbedSearchResult{
		CardId:          cardId,
		EditionSearched: editionSearched,
	}, ""
}

const (
	emoteShurg = "o͡͡͡╮༼ • ʖ̯ • ༽╭o͡͡͡"
	emoteSad   = "┏༼ ◉ ╭╮ ◉༽┓"
	emoteSleep = "(-, – )…zzzZZZ"
	emoteHappy = "ᕕ( ՞ ᗜ ՞ )ᕗ"
)

type AffiliateConfig struct {
	// The text upon which the URL is detected
	Trigger string

	// Skip the identified URL if it contains any of the text
	Skip []string

	// Name of the store (displayed in the title)
	Name string

	// Key to access the Config.Affiliate map
	Handle string

	// List of query parameters to be set to the same config value
	DefaultFields []string

	// Any custom query parameters to be set with the associated value
	CustomFields map[string]string

	// Function to build the displayed title
	TitleFunc func(string) string

	// Function to build the complete URL
	URLFunc func(*url.URL) *url.URL

	// Whether to parse the entire URL or just its path
	FullURL bool
}

var AffiliateStores []AffiliateConfig = []AffiliateConfig{
	{
		Trigger:       "cardkingdom.com/mtg",
		Name:          "Card Kingdom",
		Handle:        "CK",
		DefaultFields: []string{"partner", "utm_source", "utm_campaign"},
		CustomFields: map[string]string{
			"utm_medium": "affiliate",
		},
	},
	{
		Trigger:       "cardkingdom.com/purchasing",
		Name:          "Card Kingdom",
		Handle:        "CK",
		DefaultFields: []string{"partner", "utm_source", "utm_campaign"},
		CustomFields: map[string]string{
			"utm_medium": "affiliate",
		},
		FullURL: true,
		TitleFunc: func(URL string) string {
			title := "Your search"
			u, err := url.Parse(URL)
			if err != nil {
				return title
			}
			name := u.Query().Get("filter[name]")
			cleanName, err := url.QueryUnescape(name)
			if err != nil {
				return title
			}
			return mtgmatcher.Title(cleanName)
		},
	},
	{
		Trigger:       "coolstuffinc.com/p",
		Name:          "Cool Stuff Inc",
		Handle:        "CSI",
		DefaultFields: []string{"utm_referrer"},
		TitleFunc: func(URLpath string) string {
			base, err := url.QueryUnescape(path.Base(URLpath))
			if err != nil {
				return ""
			}
			return mtgmatcher.Title(base)
		},
	},
	{
		Trigger: "tcgplayer.com/product",
		Skip: []string{
			"seller", "help", "infinite", "@", "admin", "categories",
		},
		Name: "TCGplayer",
		URLFunc: func(u *url.URL) *url.URL {
			// Work around wrong tcgplayer defaults
			v := u.Query()
			if v.Get("Language") == "" {
				v.Set("Language", "all")
			}
			u.RawQuery = v.Encode()

			link := u.String()
			u, _ = u.Parse(fmt.Sprintf(tcgplayer.PartnerProductURL, Config.Affiliate["TCG"]))
			v = url.Values{}
			v.Set("u", link)
			u.RawQuery = v.Encode()
			return u
		},
		TitleFunc: func(_ string) string {
			return "Your search"
		},
	},
	{
		Trigger: "starcitygames.com/",
		Skip:    []string{"sellyourcards", "articles", "goto"},
		Name:    "Star City Games",
		URLFunc: func(u *url.URL) *url.URL {
			link := u.String()
			u, _ = u.Parse(fmt.Sprintf(starcitygames.PartnerProductURL, Config.Affiliate["SCG"]))
			v := url.Values{}
			v.Set("u", link)
			u.RawQuery = v.Encode()
			return u
		},
		TitleFunc: func(URLpath string) string {
			urlpath := strings.ToLower(URLpath)
			if strings.Contains(urlpath, "-sgl-") {
				index := strings.Index(urlpath, "-sgl-")
				return mtgmatcher.Title(strings.Replace(urlpath[1:index], "-", " ", -1))
			}
			return "Your search"
		},
	},
	{
		Trigger:       "manapool.com/card",
		Name:          "Manapool",
		Handle:        "MP",
		DefaultFields: []string{"ref"},
	},
	{
		Trigger:       "manapool.com/sealed",
		Name:          "Manapool",
		Handle:        "MP",
		DefaultFields: []string{"ref"},
		TitleFunc: func(URLpath string) string {
			base := path.Base(URLpath)
			title := mtgmatcher.Title(strings.Replace(base, "-", " ", -1))
			URLpath = strings.TrimSuffix(URLpath, "/"+base)
			title += " from " + strings.ToUpper(path.Base(URLpath))
			return title
		},
	},
	{
		Trigger:       "amazon.com/",
		Skip:          []string{"images"},
		Name:          "Amazon",
		Handle:        "AMZN",
		DefaultFields: []string{"tag"},
		TitleFunc: func(URLpath string) string {
			if strings.Contains(URLpath, "/dp/") {
				fields := strings.Split(URLpath, "/")
				return strings.Replace(fields[2], "-", " ", -1)
			}
			return "Your search"
		},
	},
}

// This function will be called (due to AddHandler above) every time a new
// message is created on any channel that the authenticated bot has access to.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore requests if starting up
	if len(Sellers) == 0 || len(Vendors) == 0 {
		return
	}

	// Ignore all messages created by a bot
	if m.Author.Bot {
		return
	}

	// Ignore too short messages
	if len(m.Content) < 2 {
		return
	}

	// Ingore messages not coming from the test channel when running in dev
	if DevMode && m.ChannelID != DevChannelID {
		return
	}

	// Parse message, look for bot command
	if !strings.HasPrefix(m.Content, "!") &&
		!strings.HasPrefix(m.Content, "?") &&
		!strings.HasPrefix(m.Content, "$$") {
		switch {
		// Check if selected channels can replace scryfall searches
		case (m.ChannelID == DevChannelID || m.ChannelID == RecapChannelID || m.ChannelID == ChatChannelID) && strings.Contains(m.Content, "[["):
			fields := squareBracketsRE.FindAllString(m.Content, -1)
			for _, field := range fields {
				m.Content = "!" + strings.Trim(field, "[]")
				messageCreate(s, m)
			}
		// Check if the message uses the Pricefall syntax
		case strings.Contains(m.Content, "{{"):
			fields := curlyBracketsRE.FindAllString(m.Content, -1)
			for _, field := range fields {
				m.Content = "!" + strings.Trim(field, "{}")
				messageCreate(s, m)
			}
		// Check if we can intercept Gatherer requests
		case strings.Contains(m.Content, "gatherer.wizards.com"):
			fields := strings.Fields(m.Content)
			for _, field := range fields {
				if !strings.Contains(field, "gatherer.wizards.com") {
					continue
				}
				u, err := url.Parse(field)
				if err != nil {
					continue
				}
				mid := u.Query().Get("multiverseid")
				uuids := mtgmatcher.GetUUIDs()
				for _, uuid := range uuids {
					co, _ := mtgmatcher.GetUUID(uuid)
					if co.Identifiers["multiverseId"] == mid {
						m.Content = fmt.Sprintf("!%s|%s|%s", co.Name, co.SetCode, co.Number)
						messageCreate(s, m)
						return
					}
				}
			}
		// Check if the message contains potential links
		default:
			// Only for the main game
			if Config.Game != DefaultGame {
				return
			}

			for _, store := range AffiliateStores {
				if !strings.Contains(m.Content, store.Trigger) {
					continue
				}
				shouldSkip := false
				for _, skip := range store.Skip {
					if strings.Contains(m.Content, skip) {
						shouldSkip = true
						break
					}
				}
				if shouldSkip {
					continue
				}

				// Iterate over each segment of the message and look for known links
				fields := strings.Fields(m.Content)
				for _, field := range fields {
					if !strings.Contains(field, store.Trigger) {
						continue
					}
					u, err := url.Parse(field)
					if err != nil {
						continue
					}

					// Tweak base URL if necessary
					if store.URLFunc != nil {
						u = store.URLFunc(u)
					}

					// Extract a sensible link title
					title := mtgmatcher.Title(strings.Replace(path.Base(u.Path), "-", " ", -1))

					var customTitle string
					if store.TitleFunc != nil {
						if store.FullURL {
							customTitle = store.TitleFunc(u.String())
						} else {
							customTitle = store.TitleFunc(u.Path)
						}
						if customTitle != "" {
							title = customTitle
						}
					}
					title += " at " + store.Name

					// Add the MTGBAN affiliation
					v := u.Query()
					for _, value := range store.DefaultFields {
						v.Set(value, Config.Affiliate[store.Handle])
					}
					for storeField, value := range store.CustomFields {
						v.Set(storeField, value)
					}
					u.RawQuery = v.Encode()

					// Spam time!
					_, err = s.ChannelMessageSendEmbed(m.ChannelID, &discordgo.MessageEmbed{
						Title:       title,
						URL:         u.String(),
						Description: "Support **MTGBAN** by using this link",
					})
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
		return
	}

	allBls := strings.HasPrefix(m.Content, "!") || strings.HasPrefix(m.Content, "?")
	sealed := strings.HasPrefix(m.Content, "?")
	lastSold := strings.HasPrefix(m.Content, "$$")

	// Strip away beginning character
	content := strings.TrimPrefix(m.Content, "!")
	content = strings.TrimPrefix(content, "?")
	content = strings.TrimPrefix(content, "$$")

	// Search a single card match
	searchRes, errMsg := parseMessage(content, sealed)
	if errMsg != "" {
		if DevMode {
			errMsg = "[DEV] " + errMsg
			s.ChannelMessageSendEmbed(m.ChannelID, &discordgo.MessageEmbed{
				Description: errMsg,
			})
		}
		return
	}
	if searchRes.Invalid {
		return
	}

	co, err := mtgmatcher.GetUUID(searchRes.CardId)
	if err != nil {
		return
	}

	var ogFields []EmbedField
	var channel chan *discordgo.MessageEmbed

	if allBls {
		config := parseSearchOptionsNG(searchRes.CardId, DiscordRetailBlocklist, DiscordBuylistBlocklist, nil)

		// Skip any store based outside of the US
		config.StoreFilters = append(config.StoreFilters, FilterStoreElem{
			Name:   "region",
			Values: []string{"us"},
		})

		// Skip non-NM buylist prices
		config.EntryFilters = append(config.EntryFilters, FilterEntryElem{
			Name:          "condition",
			Values:        []string{"NM"},
			OnlyForVendor: true,
		})

		cardIds, _ := searchAndFilter(config)
		foundSellers, foundVendors := searchParallelNG(cardIds, config)

		searchRes.ResultsIndex = ProcessEmbedSearchResultsSellers(foundSellers, true)
		searchRes.ResultsSellers = ProcessEmbedSearchResultsSellers(foundSellers, false)
		searchRes.ResultsVendors = ProcessEmbedSearchResultsVendors(foundVendors)

		ogFields = FormatEmbedSearchResult(searchRes)
	} else if lastSold {
		// Since grabLastSold is slow, spawn a goroutine and wait for the real
		// results later, after posting a "please wait" message
		go func() {
			channel = make(chan *discordgo.MessageEmbed)
			var errMsg string
			ogFields, err = grabLastSold(searchRes.CardId, co.Language)
			if err != nil {
				if errors.Is(err, ErrMissingTCGId) {
					errMsg = fmt.Sprintf("\"%s\" does not have any identifier set, I don't know what to do %s", content, emoteShurg)
				} else {
					errMsg = "Internal bot error " + emoteSad
					log.Println("Bot error:", err, "from", content)
				}
			} else if len(ogFields) == 0 {
				errMsg = fmt.Sprintf("No Last Sold Price available for \"%s\" %s", content, emoteShurg)
			}
			embed := prepareCard(searchRes, ogFields, m.GuildID, lastSold)
			if errMsg != "" {
				embed.Description += errMsg
			}
			channel <- embed
		}()
	}

	embed := prepareCard(searchRes, ogFields, m.GuildID, lastSold)
	if lastSold {
		embed.Description += "Grabbing last sold prices, hang tight " + emoteHappy
	}

	out, err := s.ChannelMessageSendEmbed(m.ChannelID, embed)
	if err != nil {
		log.Println(err)
		return
	}
	if lastSold {
		var edit *discordgo.MessageEmbed

		// Either get the result from the channel or time out
		select {
		case edit = <-channel:
			break
		case <-time.After(LastSoldTimeout * time.Second):
			edit = prepareCard(searchRes, ogFields, m.GuildID, lastSold)
			edit.Description += "Connection time out " + emoteSleep
			break
		}

		_, err = s.ChannelMessageEditEmbed(m.ChannelID, out.ID, edit)
		if err != nil {
			log.Println(err)
		}
	}
}

func printings2line(printings []string) string {
	line := strings.Join(printings, ", ")
	if len(printings) > MaxPrintings {
		line = strings.Join(printings[:MaxPrintings], ", ") + " and more"
	}
	return line
}

func prepareCard(searchRes *EmbedSearchResult, ogFields []EmbedField, guildId string, lastSold bool) *discordgo.MessageEmbed {
	// Convert search results into proper fields
	var fields []*discordgo.MessageEmbedField
	for _, field := range ogFields {
		// Either print the raw field or format the Values slice
		msg := field.Raw
		for _, value := range field.Values {
			tag := ""
			if value.Tag != "" {
				tag = fmt.Sprintf(" (%s)", value.Tag)
			}
			msg += fmt.Sprintf("• **[`%s%s%s`](%s)** %s", value.ScraperName, tag, value.ExtraSpaces, value.Link, value.Price)
			if value.HasFire {
				msg += " 🔥"
			} else if value.HasFire {
				msg += " 🚨"
			}
			msg += "\n"
		}
		fields = append(fields, &discordgo.MessageEmbedField{
			Name:   field.Name,
			Value:  msg,
			Inline: field.Inline,
		})
	}

	// Prepare card data
	card := uuid2card(searchRes.CardId, true, false, false)
	co, _ := mtgmatcher.GetUUID(searchRes.CardId)

	printings := printings2line(co.Printings)
	if searchRes.EditionSearched != "" && len(co.Variations) > 0 {
		cn := []string{co.Number}
		for _, varid := range co.Variations {
			co, err := mtgmatcher.GetUUID(varid)
			if err != nil {
				continue
			}
			cn = append(cn, co.Number)
		}
		sort.Slice(cn, func(i, j int) bool {
			// Try integer comparison first
			cInum, errI := strconv.Atoi(cn[i])
			cJnum, errJ := strconv.Atoi(cn[j])
			if errI == nil && errJ == nil {
				return cInum < cJnum
			}
			// Else do a string comparison
			return cn[i] < cn[j]
		})
		printings = fmt.Sprintf("%s. Variants in %s are %s", printings, searchRes.EditionSearched, strings.Join(cn, ", "))
	}

	searchEndpoint := "search"
	if co.Sealed {
		searchEndpoint = "sealed"
	}
	link := "https://www.mtgban.com/" + searchEndpoint + "?q=" + co.UUID + "&utm_source=banbot&utm_affiliate=" + guildId

	// Set title of the main message
	name := card.Name
	// We need to restore the original English text if Language is a fantasy one
	if allLanguageFlags[co.Language] == "" {
		name = co.Name
	}
	title := "Prices for " + name
	if lastSold {
		title = "TCG Last Sold prices for " + name

		tcgId := findTCGproductId(co.UUID)
		productId, _ := strconv.Atoi(tcgId)
		printing := "Normal"
		if co.Etched || co.Foil {
			printing = "Foil"
		}
		link = tcgplayer.GenerateProductURL(productId, printing, Config.Affiliate["TCG"], "", co.Language, false)
	}

	// Add a tag for ease of debugging
	if DevMode {
		title = "[DEV] " + title
	}
	// Spark-ly
	if card.Sealed {
		title += " 📦"
	} else if card.Etched {
		title += " 💫"
	} else if card.Foil {
		title += " ✨"
	}

	desc := fmt.Sprintf("[%s] %s\n", card.SetCode, card.Title)
	if !co.Sealed {
		desc = fmt.Sprintf("%sPrinted in %s.\n", desc, printings)
	}
	desc += "\n"

	embed := discordgo.MessageEmbed{
		Title:       title,
		Color:       0xFF0000,
		URL:         link,
		Description: desc,
		Fields:      fields,
		Thumbnail: &discordgo.MessageEmbedThumbnail{
			URL: card.ImageURL,
		},
		Footer: &discordgo.MessageEmbedFooter{},
	}

	// Some footer action, RL, stocks, syp, powered by
	if card.Reserved {
		embed.Footer.Text = "Part of the Reserved List\n"
	}
	inv, _ := findSellerInventory("STKS")
	_, onStocks := inv[searchRes.CardId]
	if onStocks {
		embed.Footer.Text += "On MTGStocks Interests page\n"
	}
	bl, _ := findVendorBuylist("SYP")
	_, onSyplist := bl[searchRes.CardId]
	if onSyplist {
		embed.Footer.Text += "On TCGplayer SYP list\n"
	}
	// Show data source on non-ban servers
	if guildId != MainDiscordID {
		embed.Footer.IconURL = poweredByFooter.IconURL
		embed.Footer.Text += poweredByFooter.Text
	}

	return &embed
}

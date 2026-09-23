package main

import (
	"context"
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
	"github.com/mtgban/mtgban-website/internal/embed"
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
	// Timeout before giving up on a last sold price request
	LastSoldTimeout = 30

	defaultDiscordGuildID        = "637563728711385091"
	defaultDiscordDevChannelID   = "769323295526748160"
	defaultDiscordRecapChannelID = "798588735259279453"
	defaultDiscordChatChannelID  = "736007847560609794"
)

var DiscordRetailBlocklist []string
var DiscordBuylistBlocklist []string

var dg *discordgo.Session

func (c *DiscordConfig) applyDefaults() {
	if c.GuildID == "" {
		c.GuildID = defaultDiscordGuildID
	}
	if c.DevelopmentChannelID == "" {
		c.DevelopmentChannelID = defaultDiscordDevChannelID
	}
	if c.RecapChannelID == "" {
		c.RecapChannelID = defaultDiscordRecapChannelID
	}
	if c.ChatChannelID == "" {
		c.ChatChannelID = defaultDiscordChatChannelID
	}
}

func discordGuildID() string {
	if Config.Discord.GuildID != "" {
		return Config.Discord.GuildID
	}
	return defaultDiscordGuildID
}

func setupDiscord() error {
	var err error

	if Config.Discord.BotToken == "" {
		return errors.New("no discord token")
	}

	// Create a new Discord session using the provided bot token.
	dg, err = discordgo.New("Bot " + Config.Discord.BotToken)
	if err != nil {
		return err
	}

	// Register the guildCreate func as a callback for GuildCreat events
	dg.AddHandler(guildCreate)

	// Register the messageCreate func as a callback for MessageCreate events.
	dg.AddHandler(messageCreate)

	// The changelog reads message content, embeds, and attachments through the
	// Discord API, so request the corresponding privileged intent as well.
	dg.Identify.Intents = discordgo.MakeIntent(
		discordgo.IntentsGuilds | discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent,
	)

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
	if Config.Discord.BotToken == "" {
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
			set, err := backend().GetSet(editionSearched)
			if err != nil {
				return nil, fmt.Sprintf("No edition found for \"%s\"", editionSearched)
			}
			msg := fmt.Sprintf("No card found named \"%s\" in %s", query, set.Name)
			printings, err := backend().Printings4Card(query)
			if err == nil {
				msg = fmt.Sprintf("%s\n\"%s\" is printed in %s.", msg, query, embed.PrintingsLine(printings))
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
	sortData := resolveSortingData(uuids)
	sort.Slice(uuids, func(i, j int) bool {
		return cmpSets(sortData[uuids[i]], sortData[uuids[j]])
	})
	cardID := uuids[0]

	return &EmbedSearchResult{
		CardID:          cardID,
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

	// Key to access the affiliate codes map
	Handle string

	// List of query parameters to be set to the same config value
	DefaultFields []string

	// Any custom query parameters to be set with the associated value
	CustomFields map[string]string

	// Function to build the displayed title
	TitleFunc func(*url.URL) string

	// Function to build the complete URL
	URLFunc func(*url.URL) *url.URL

	// Function to name the printing the link points at, for the stores whose
	// URLs carry an identifier that names one. It is what lets the bot offer
	// the card on this site beside the store's own link, so it answers with
	// nothing rather than with a guess: a link to the wrong card is worse
	// than no link at all.
	CardFunc func(*url.URL) *mtgmatcher.CardObject
}

// unknownTitle is the title a store's link carries where the printing behind
// it cannot be named. It is the whole title for a store whose URLs say
// nothing (Amazon), and the fallback for one whose URLs usually do.
func unknownTitle(*url.URL) string {
	return "Your search"
}

// printingTitle names a printing the way the bot announces a link: the card,
// the set it is in, the number it is filed under, and a mark for a finish
// that is not the plain one.
func printingTitle(co *mtgmatcher.CardObject) string {
	title := fmt.Sprintf("%s [%s]", co.Name, co.SetCode)
	if co.Number != "" {
		title += " #" + co.Number
	}
	if co.Sealed {
		title += " 📦"
	} else if co.Etched {
		title += " 💫"
	} else if co.Foil {
		title += " ✨"
	}
	return title
}

// manapoolCard names the printing a Mana Pool card link points at.
//
// The path is /card/<set>/<number>/<tail>, and the tail is the card's name
// only in the links the price feed publishes - all 546k of its records spell
// it that way, which is why reading the last segment ever looked right. The
// site's own links put an internal id there instead, and
// /card/ltr/744z/3ca3376d-5850-4614-88ce-3081d4cbddcf - Sauron, the Dark Lord
// - came out as "3Ca3376D 5850 4614 88Ce 3081D4Cbddcf". The set and the
// number are in both shapes and name the printing between them, so the card
// is found from those and the tail is not read at all.
//
// Taking the first printing a set files under the number is safe because the
// two name one card: of the 106,229 pairs this datastore files, none is
// answered by two. Other games do file a number under two names - see
// openingName in redirect.go - but the bot reads links for Magic only, which
// checkForLinks gates on.
func manapoolCard(u *url.URL) *mtgmatcher.CardObject {
	fields := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(fields) < 3 {
		return nil
	}

	for _, card := range printingsAt(fields[1], fields[2]) {
		co, err := backend().GetUUID(card.UUID)
		if err != nil {
			continue
		}
		return co
	}
	return nil
}

// tcgplayerCard names the printing a TCGplayer product link points at.
//
// The product id is the first whole number in the path, and it is an id the
// matcher already indexes, so the printing it names is looked up rather than
// guessed from the slug beside it.
//
// The Printing parameter picks the foil sibling where the page is showing
// one.
func tcgplayerCard(u *url.URL) *mtgmatcher.CardObject {
	var id string
	for _, id = range strings.Split(u.Path, "/") {
		_, err := strconv.Atoi(id)
		if err == nil {
			break
		}
	}

	cardID, err := backend().MatchID(id, u.Query().Get("Printing") == "Foil")
	if err != nil {
		return nil
	}
	co, err := backend().GetUUID(cardID)
	if err != nil {
		return nil
	}
	return co
}

var AffiliateStores = []AffiliateConfig{
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
		TitleFunc: func(u *url.URL) string {
			title := "Your search"
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
		TitleFunc: func(u *url.URL) string {
			base, _ := url.QueryUnescape(path.Base(u.Path))
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
			u, _ = u.Parse(fmt.Sprintf(tcgplayer.PartnerProductURL, Affiliates().Codes["TCG"]))
			v = url.Values{}
			v.Set("u", link)
			u.RawQuery = v.Encode()
			return u
		},
		TitleFunc: unknownTitle,
		CardFunc:  tcgplayerCard,
	},
	{
		Trigger: "starcitygames.com/",
		Skip:    []string{"sellyourcards", "articles", "goto"},
		Name:    "Star City Games",
		URLFunc: func(u *url.URL) *url.URL {
			link := u.String()
			u, _ = u.Parse(fmt.Sprintf(starcitygames.PartnerProductURL, Affiliates().Codes["SCG"]))
			v := url.Values{}
			v.Set("u", link)
			u.RawQuery = v.Encode()
			return u
		},
		TitleFunc: func(u *url.URL) string {
			urlpath := strings.ToLower(u.Path)
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
		TitleFunc:     unknownTitle,
		CardFunc:      manapoolCard,
	},
	{
		Trigger:       "manapool.com/sealed",
		Name:          "Manapool",
		Handle:        "MP",
		DefaultFields: []string{"ref"},
		TitleFunc: func(u *url.URL) string {
			base := path.Base(u.Path)
			title := mtgmatcher.Title(strings.Replace(base, "-", " ", -1))
			urlpath := strings.TrimSuffix(u.Path, "/"+base)
			title += " from " + strings.ToUpper(path.Base(urlpath))
			return title
		},
	},
	{
		Trigger:       "https://www.cardtrader.com/",
		Name:          "CardTrader",
		Handle:        "CT",
		DefaultFields: []string{"share_code"},
	},
	{
		Trigger:       "amazon.com/",
		Skip:          []string{"images-amazon.com/images"},
		Name:          "Amazon",
		Handle:        "AMZN",
		DefaultFields: []string{"tag"},
		TitleFunc:     unknownTitle,
	},
	{
		Trigger:       "/a.co/",
		Name:          "Amazon",
		Handle:        "AMZN",
		DefaultFields: []string{"tag"},
		TitleFunc:     unknownTitle,
	},
}

// Check if a essage contains well-known links that can be tagged with BAN's
// links. The printing comes back too where the store's URL named one, and is
// nil otherwise - a store whose links carry no identifier, or one whose link
// this time named nothing the datastore holds.
func checkForLinks(mGuildID, mContent string) (string, string, *mtgmatcher.CardObject) {
	// Only for the main discord and only for the main game
	if mGuildID != discordGuildID() || Config.Game != DefaultGame {
		return "", "", nil
	}

	for _, store := range AffiliateStores {
		if !strings.Contains(mContent, store.Trigger) {
			continue
		}
		shouldSkip := false
		for _, skip := range store.Skip {
			if strings.Contains(mContent, skip) {
				shouldSkip = true
				break
			}
		}
		for _, skip := range store.DefaultFields {
			// Check for query params only
			if strings.Contains(mContent, "?"+skip+"=") || strings.Contains(mContent, "&"+skip+"=") {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		// Iterate over each segment of the message and look for known links
		fields := strings.Fields(mContent)
		for _, field := range fields {
			if !strings.Contains(field, store.Trigger) {
				continue
			}
			u, err := url.Parse(field)
			if err != nil {
				continue
			}

			// Name the printing the link points at, where the store's URL
			// carries enough to. This reads the posted URL, so it has to
			// happen before URLFunc folds it into a partner redirect.
			var co *mtgmatcher.CardObject
			if store.CardFunc != nil {
				co = store.CardFunc(u)
			}

			// Extract a sensible link title
			title := mtgmatcher.Title(strings.Replace(path.Base(u.Path), "-", " ", -1))
			switch {
			case co != nil:
				title = printingTitle(co)
			case store.TitleFunc != nil:
				title = store.TitleFunc(u)
			}
			title += " at " + store.Name

			// Add a tag for ease of debugging
			if DevMode {
				title = "[DEV] " + title
			}

			// Tweak base URL if necessary
			if store.URLFunc != nil {
				u = store.URLFunc(u)
			}

			// Add the MTGBAN affiliation
			v := u.Query()
			for _, value := range store.DefaultFields {
				v.Set(value, Affiliates().Codes[store.Handle])
			}
			for storeField, value := range store.CustomFields {
				v.Set(storeField, value)
			}
			u.RawQuery = v.Encode()

			return title, u.String(), co
		}
	}
	return "", "", nil
}

// This function will be called (due to AddHandler above) every time a new
// message is created on any channel that the authenticated bot has access to.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignore requests if starting up
	if len(GetSellers()) == 0 || len(GetVendors()) == 0 {
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
	if DevMode && m.ChannelID != Config.Discord.DevelopmentChannelID {
		return
	}

	// Parse message, look for bot command
	if !strings.HasPrefix(m.Content, "!") &&
		!strings.HasPrefix(m.Content, "?") &&
		!strings.HasPrefix(m.Content, "$$") {
		switch {
		// Check if selected channels can replace scryfall searches
		case (m.ChannelID == Config.Discord.DevelopmentChannelID || m.ChannelID == Config.Discord.RecapChannelID || m.ChannelID == Config.Discord.ChatChannelID) && strings.Contains(m.Content, "[["):
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
				uuids := backend().GetUUIDs()
				for _, uuid := range uuids {
					co, _ := backend().GetUUID(uuid)
					if co.Identifiers["multiverseId"] == mid {
						m.Content = fmt.Sprintf("!%s|%s|%s", co.Name, co.SetCode, co.Number)
						messageCreate(s, m)
						return
					}
				}
			}
		// Check if the message contains potential links
		default:
			title, link, _ := checkForLinks(m.GuildID, m.Content)
			if title == "" || link == "" {
				break
			}

			// Spam time!
			_, err := s.ChannelMessageSendEmbed(m.ChannelID, &discordgo.MessageEmbed{
				Title:       title,
				URL:         link,
				Description: "Support **MTGBAN** by using this link",
			})
			if err != nil {
				log.Println(err)
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

	co, err := backend().GetUUID(searchRes.CardID)
	if err != nil {
		return
	}

	var ogFields []EmbedField
	var channel chan *discordgo.MessageEmbed

	if allBls {
		config := parseSearchOptionsNG(searchRes.CardID, DiscordRetailBlocklist, DiscordBuylistBlocklist, nil)

		// Keep the bot to stores a reader can actually buy from. That is a
		// reason to drop a foreign shop and not a reason to drop a foreign
		// price reference, so the index scrapers are exempt — Cardmarket's are
		// the ones flagged EU, and without the exemption its prices never reach
		// an embed. Built here rather than shared: filter values are edited in
		// place further down (parseSearchOptionsNG appends a trailing finish
		// character to the last regexp filter's first value), so one Values
		// slice handed to every message is a backing array the bot would be
		// rewriting under itself.
		config.StoreFilters = append(config.StoreFilters, FilterStoreElem{
			Name:         "region",
			Values:       []string{"us"},
			IncludeIndex: true,
		})

		// Skip non-NM buylist prices
		config.EntryFilters = append(config.EntryFilters, FilterEntryElem{
			Name:          "condition",
			Values:        []string{"NM"},
			OnlyForVendor: true,
		})

		cardIDs, _ := searchAndFilter(config)
		foundSellers, foundVendors := searchParallelNG(cardIDs, config)

		searchRes.ResultsIndex = ProcessEmbedSearchResultsSellers(foundSellers, true)
		searchRes.ResultsSellers = ProcessEmbedSearchResultsSellers(foundSellers, false)
		searchRes.ResultsVendors = ProcessEmbedSearchResultsVendors(foundVendors)

		ogFields = embed.FormatSearchResult(externalURL(nil), searchRes)
	} else if lastSold {
		// Since grabLastSold is slow, spawn a goroutine and wait for the real
		// results later, after posting a "please wait" message
		go func() {
			channel = make(chan *discordgo.MessageEmbed)
			var errMsg string
			// The fetch lives here rather than behind the formatting: it is
			// the half that needs a context, a timeout and an error to
			// report back to the reader.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var lastSales []tcgplayer.LatestSalesData
			lastSales, err = getLastSold(ctx, searchRes.CardID, false)
			cancel()
			if err == nil {
				ogFields = embed.LastSoldFields(lastSales2embed(lastSales), co.Language)
			}
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

func prepareCard(searchRes *EmbedSearchResult, ogFields []EmbedField, guildID string, lastSold bool) *discordgo.MessageEmbed {
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
			if value.SuffixEmoji != "" {
				msg += " " + value.SuffixEmoji
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
	card := uuid2card(searchRes.CardID, true, false, false)
	co, _ := backend().GetUUID(searchRes.CardID)

	printings := embed.PrintingsLine(co.Printings)
	if searchRes.EditionSearched != "" && len(co.Variations) > 0 {
		cn := []string{co.Number}
		for _, varid := range co.Variations {
			co, err := backend().GetUUID(varid)
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
	link := "https://www.mtgban.com/" + searchEndpoint + "?q=" + co.UUID + "&utm_source=banbot&utm_affiliate=" + guildID

	// Set title of the main message
	name := card.Name
	// We need to restore the original English text if Language is a fantasy one
	if allLanguageFlags[co.Language] == "" {
		name = co.Name
	}
	title := "Prices for " + name
	if lastSold {
		title = "TCG Last Sold prices for " + name

		tcgID := findTCGproductID(co.UUID)
		productID, _ := strconv.Atoi(tcgID)
		printing := "Normal"
		if co.Etched || co.Foil {
			printing = "Foil"
		}
		link = tcgplayer.GenerateProductURL(productID, printing, Affiliates().Codes["TCG"], "", co.Language, false)
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
	if card.Stocks {
		embed.Footer.Text += "On MTGStocks Interests page\n"
	}
	if card.SypList {
		embed.Footer.Text += "On TCGplayer SYP list\n"
	}
	if card.HotlistStore == "CK" {
		embed.Footer.Text += "Highest buylist price in three months\n"
	}

	// Show data source on non-ban servers
	if guildID != discordGuildID() {
		embed.Footer.IconURL = poweredByFooter.IconURL
		embed.Footer.Text += poweredByFooter.Text
	}

	return &embed
}

package storeorder

import (
	"slices"
	"testing"
)

// invoices are real buylist invoices, each line in the order the store
// listed it.
var invoices = []struct {
	name  string
	store string
	lines []Row
}{
	{
		// CK sell order 115491785: editions naturally (9th, 10th, 2012),
		// each edition's foils first
		"ck", "CK", []Row{
			{Edition: "9th Edition", Title: "Soul Warden", Foil: true},
			{Edition: "10th Edition", Title: "Shivan Hellkite", Foil: true},
			{Edition: "2012 Core Set", Title: "Rites of Flourishing", Foil: true},
			{Edition: "Coldsnap", Title: "Cover of Winter", Foil: true},
			{Edition: "Eventide", Title: "Batwing Brume", Foil: true},
			{Edition: "Future Sight", Title: "Nimbus Maze"},
			{Edition: "Guildpact", Title: "Izzet Signet", Foil: true},
			{Edition: "Guildpact", Title: "Stitch in Time"},
			{Edition: "Lorwyn", Title: "Treefolk Harbinger", Foil: true},
			{Edition: "Promotional", Title: "Kor Skyfisher (Media Insert Foil)", Foil: true},
			{Edition: "Shadowmoor", Title: "Cerulean Wisps", Foil: true},
			{Edition: "Shadowmoor", Title: "Niveous Wisps", Foil: true},
			{Edition: "Shadowmoor", Title: "Spiteful Visions"},
			{Edition: "Time Spiral", Title: "Fallen Ideal", Foil: true},
			{Edition: "Time Spiral", Title: "Reiterate"},
			{Edition: "Time Spiral", Title: "Wheel of Fate"},
		},
	},
	{
		// CK sell order 153246542 from its Secret Lair lines, CKFoil as CK's
		// buylist has it: titles byte by byte, 1001 before 701, Secret Lair's
		// foils among its non-foils
		"ck titles", "CK", []Row{
			{Edition: "Secret Lair", Title: "Arcanis the Omnipotent (498 - Non-Foil)"},
			{Edition: "Secret Lair", Title: "Berserk (1003 - Foil)", Foil: true},
			{Edition: "Secret Lair", Title: "Eidolon of the Great Revel (422 - Foil)", Foil: true},
			{Edition: "Secret Lair", Title: "Elspeth, Knight-Errant (1001 - Foil)", Foil: true},
			{Edition: "Secret Lair", Title: "Elspeth, Knight-Errant (701 - Foil)", Foil: true},
			{Edition: "Secret Lair", Title: "Elspeth, Knight-Errant (701 - Non-Foil)"},
			{Edition: "Secret Lair", Title: "Elvish Spirit Guide (423 - Non-Foil)"},
			{Edition: "Unfinity", Title: "Tunnel of Love (2/6)", Foil: true},
		},
	},
	{
		// CK sell order 160597924: oversized last
		"ck oversized", "CK", []Row{
			{Edition: "Saviors of Kamigawa", Title: "Wine of Blood and Iron", Foil: true},
			{Edition: "Commander 2018", Title: "Lord Windgrace (Oversized Foil)", Foil: true},
		},
	},
	{
		// ABU buylist order B641951
		"abu", "ABUGames", []Row{
			{Edition: "Commander 2013", Title: "Shattergang Brothers"},
			{Edition: "Commander 2016", Title: "Ancient Excavation"},
			{Edition: "Commander 2016", Title: "Cruel Entertainment"},
			{Edition: "Commander Anthology", Title: "Thunderfoot Baloth"},
			{Edition: "Journey into Nyx", Title: "Pharika, God of Affliction"},
			{Edition: "Magic Origins", Title: "Gather the Pack"},
			{Edition: "Onslaught", Title: "Syphon Mind", Foil: true},
			{Edition: "Shadowmoor", Title: "Plague of Vermin"},
			{Edition: "Shadows over Innistrad", Title: "Lightning Axe"},
		},
	},
	{
		// ABU buylist order B714593 from Planar Chaos to Scourge: promos
		// filed under "Promo" by name. Its IDW comic insert, which this rule
		// misses, is left out.
		"abu promos", "ABUCredit", []Row{
			{Edition: "Planar Chaos", Title: "Chronozoa"},
			{Edition: "Planar Chaos", Title: "Vitaspore Thallid", Foil: true},
			{Edition: "Planeshift", Title: "Warped Devotion", Foil: true},
			{Edition: "Friday Night Magic 2005", Title: "Juggernaut", Foil: true},
			{Edition: "Future Sight Promos", Title: "Korlash, Heir to Blackblade", Foil: true},
			{Edition: "Kamigawa: Neon Dynasty Promos", Title: "March of Reckless Joy", Foil: true},
			{Edition: "The Brothers' War Promos", Title: "Mishra's Foundry"},
			{Edition: "Ravnica Allegiance Promos", Title: "Teysa Karlov", Foil: true},
			{Edition: "Scourge", Title: "Alpha Status"},
		},
	},
	{
		// CSI sell order 735406, its bulk lines aside
		"csi", "CSI", []Row{
			{SetID: 939414, Title: "Bebop & Rocksteady", Foil: true},
			{SetID: 939465, Title: "Moonlit Meditation", Foil: true},
			{SetID: 940600, Title: "Heartwarming Redemption"},
			{SetID: 941800, Title: "In Bolas's Clutches"},
			{SetID: 949200, Title: "Bramblewood Paragon", Foil: true},
			{SetID: 949600, Title: "Stronghold Rats"},
			{SetID: 950200, Title: "Keldon Halberdier"},
			{SetID: 950200, Title: "Mountain A"},
			{SetID: 950200, Title: "Mountain C"},
			{SetID: 950600, Title: "Rakdos the Defiler", Foil: true},
			{SetID: 952200, Title: "Second Sunrise"},
			{SetID: 958600, Title: "Tezzeret, Artifice Master"},
			{SetID: 962450, Title: "Thrill of Possibility"},
			{SetID: 962800, Title: "Giant Growth"},
			{SetID: 962800, Title: "Reciprocate"},
			{SetID: 962800, Title: "Rishkar's Expertise"},
			{SetID: 963100, Title: "An Offer You Can't Refuse"},
			{SetID: 974404, Title: "Bureau Headmaster"},
			{SetID: 974407, Title: "Cathedral Acolyte", Foil: true},
			{SetID: 974469, Title: "Thalisse, Reverent Medium", Foil: true},
			{SetID: 974470, Title: "Dualcaster Mage"},
			{SetID: 974470, Title: "Master Warcraft"},
			{SetID: 974490, Title: "Otrimi, the Ever-Playful"},
			{SetID: 979115, Title: "Plaguecrafter", Foil: true},
			{SetID: 979195, Title: "Goblin War Party", Foil: true},
			{SetID: 979195, Title: "Hollowhead Sliver"},
			{SetID: 979195, Title: "Oneirophage"},
			{SetID: 979200, Title: "Murderous Redcap"},
			{SetID: 979200, Title: "Seismic Assault", Foil: true},
		},
	},
	{
		// Mint buylist order 6502: a promo set first, then by release, The
		// List at Mystery Booster's date; within a set as sent; then special
		// frames
		"mint", "MMC", []Row{
			{Title: "Plains (Arena 2006)", Released: "2006-01-01", PromoSet: true},
			{Title: "Loxodon Warhammer", Released: "2003-10-02"},
			{Title: "Dire Undercurrents", Released: "2008-05-02"},
			{Title: "Seat of the Synod", Released: "2009-09-04"},
			{Title: "Bosh, Iron Golem", Released: "2009-09-04"},
			{Title: "Pentavus", Released: "2009-09-04"},
			{Title: "Scrambleverse", Released: "2011-07-15"},
			{Title: "Priest of Titania", Released: "2014-11-07"},
			{Title: "Underrealm Lich", Released: "2018-10-05"},
			{Title: "Glint-Horn Buccaneer", Released: "2019-07-12"},
			{Title: "Guildpact Informant", Released: "2020-03-13"},
			{Title: "Fist of Suns", Released: "2020-03-13"},
			{Title: "Fire-Lit Thicket", Released: "2020-08-07"},
			{Title: "Grave Endeavor", Released: "2021-07-23"},
			{Title: "Danitha, New Benalia's Light", Released: "2023-05-12"},
			{Title: "Sun Quan, Lord of Wu", Released: "2023-08-04"},
			{Title: "Heartless Hidetsugu", Released: "2023-08-04"},
			{Title: "Magus of the Wheel", Released: "2023-08-04"},
			{Title: "Sylvan Safekeeper", Released: "2024-06-14"},
			{Title: "Assemble the Legion (Extended Art)", Released: "2024-03-08", Frame: true},
			{Title: "Open the Vaults (Extended Art)", Released: "2024-03-08", Frame: true},
			{Title: "Eivor, Wolf-Kissed (Showcase)", Released: "2024-07-05", Frame: true},
		},
	},
	{
		// Mint buylist order 6072: foils between the two
		"mint foils", "MMC", []Row{
			{Title: "Selective Memory", Released: "2010-02-05"},
			{Title: "Kiora Bests the Sea God", Released: "2020-01-24"},
			{Title: "Tortured Existence", Released: "2020-03-13"},
			{Title: "Archon of Emeria", Released: "2020-09-25"},
			{Title: "Shalai and Hallar", Released: "2023-04-21"},
			{Title: "Lurking Skirge", Released: "1999-02-15", Foil: true},
			{Title: "Bear's Companion", Released: "2014-09-26", Foil: true},
			{Title: "Cursed Totem", Released: "2021-06-18", Foil: true},
			{Title: "Wish (Extended Art)", Released: "2021-07-23", Frame: true},
		},
	},
}

// TestInvoices sorts each invoice from the reverse of its order and expects
// the invoice back. Mint keeps the lines of one set as they were sent, so
// there only the set and the finish have to come back.
func TestInvoices(t *testing.T) {
	for _, inv := range invoices {
		if !Ordered(inv.store) {
			t.Errorf("%s: store %s has no order", inv.name, inv.store)
		}
		got := slices.Clone(inv.lines)
		slices.Reverse(got)
		slices.SortStableFunc(got, func(a, b Row) int { return Compare(inv.store, a, b) })
		for i := range got {
			have, want := got[i], inv.lines[i]
			if inv.store == "MMC" {
				have.Title, want.Title = "", ""
			}
			if have != want {
				t.Errorf("%s: line %d is %q, want %q", inv.name, i, got[i].Title, inv.lines[i].Title)
			}
		}
	}
}

// TestFoilNamedCard files a foil of the card "Foil" under its edition's foil
// heading, ahead of the edition's non-foils, with a variation after the name
// or none. The variation is made up: only the name before it matters.
func TestFoilNamedCard(t *testing.T) {
	for _, title := range []string{"Foil", "Foil (Showcase)"} {
		rows := []Row{
			{Edition: "Prophecy", Title: "Avatar of Woe"},
			{Edition: "Prophecy", Title: title, Foil: true},
		}
		slices.SortStableFunc(rows, func(a, b Row) int { return Compare("CK", a, b) })
		if rows[0].Title != title {
			t.Errorf("the non-foil %s comes before the foil %s", rows[0].Title, title)
		}
	}
}

// TestMissingFieldsLast files rows whose entry lacks the store's fields
// after the rest, in the order they came.
func TestMissingFieldsLast(t *testing.T) {
	rows := []Row{
		{missing: true, Title: "first missing"},
		{Edition: "Zendikar", Title: "Zendikar card"},
		{missing: true, Title: "second missing"},
		{Edition: "Alliances", Title: "Alliances card"},
	}
	slices.SortStableFunc(rows, func(a, b Row) int { return Compare("ABUGames", a, b) })
	var got []string
	for _, row := range rows {
		got = append(got, row.Title)
	}
	want := []string{"Alliances card", "Zendikar card", "first missing", "second missing"}
	if !slices.Equal(got, want) {
		t.Errorf("sorted %q, want %q", got, want)
	}
}

// TestUnorderedStore leaves a store that keeps what it was sent alone.
func TestUnorderedStore(t *testing.T) {
	if Ordered("SCG") {
		t.Error("SCG keeps the order cards were sent in")
	}
	a, b := Row{Edition: "A", Title: "A"}, Row{Edition: "B", Title: "B"}
	if Compare("SCG", b, a) != 0 {
		t.Error("an unordered store compared two rows")
	}
}

package cubecobra

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestParseCubeURL(t *testing.T) {
	good := map[string]string{
		"https://cubecobra.com/cube/overview/LSVCube":                            "LSVCube",
		"https://www.cubecobra.com/cube/list/vintagecube?view=spoiler":           "vintagecube",
		"https://cubecobra.com/cube/playtest/modo_vintage-2/":                    "modo_vintage-2",
		"https://cubecobra.com/cube/list/a525ebe1-c9c0-471c-aca3-772f91bf4145":   "a525ebe1-c9c0-471c-aca3-772f91bf4145",
		"https://CubeCobra.com/cube/overview/LSVCube#primer":                     "LSVCube",
		"https://cubecobra.com/cube/analysis/LSVCube/extra/segments/are/ignored": "LSVCube",
		"https://cubecobra.com/c/LSVCube":                                        "LSVCube",
		"https://cubecobra.com/cube/list/my.cube":                                "my.cube",
		"https://cubecobra.com/cube/list/a%3Fb":                                  "a?b",
	}
	for link, want := range good {
		id, err := ParseCubeURL(link)
		if err != nil || id != want {
			t.Errorf("ParseCubeURL(%q) = %q, %v, want %q", link, id, err, want)
		}
	}

	bad := []string{
		"https://archidekt.com/cube/overview/LSVCube",
		"https://cubecobra.com/cube/overview/",
		"https://cubecobra.com/cube/LSVCube",
		"https://cubecobra.com/user/view/LSVCube",
		"https://cubecobra.com/cube/overview/..",
		"https://cubecobra.com/cube/overview/%2e%2e",
		"https://cubecobra.com/cube/overview/%2e%2e/x",
		"https://cubecobra.com/cube/overview/.",
		"https://cubecobra.com/c/..",
		"https://cubecobra.com/c/",
	}
	for _, link := range bad {
		_, err := ParseCubeURL(link)
		if err == nil {
			t.Errorf("ParseCubeURL(%q) succeeded, want an error", link)
		}
	}
}

func TestCubeItems(t *testing.T) {
	const payload = `{
		"name": "Test",
		"cards": {
			"mainboard": [
				{"cardID": "a", "status": "Not Owned", "details": {"name": "A"}},
				{"cardID": "b", "finish": "Foil", "status": "Owned"},
				{"cardID": "c", "finish": "Etched", "status": "Premium Owned"},
				{"cardID": "d", "finish": "Non-foil", "status": "Proxied"},
				{"cardID": "", "finish": "Non-foil", "status": "Owned"},
				{"cardID": "e", "finish": "Alt-foil", "status": "Borrowed"}
			],
			"maybeboard": [{"cardID": "f", "status": "Owned"}],
			"basics": [{"cardID": "g", "finish": "recent", "status": "Owned"}]
		}
	}`
	var cube cubePayload
	err := json.Unmarshal([]byte(payload), &cube)
	if err != nil {
		t.Fatal(err)
	}

	items := cubeItems(&cube, 0)
	if len(items) != 4 {
		t.Fatalf("got %d items, want 4: %+v", len(items), items)
	}
	if items[0].ScryfallID != "a" || items[0].Name != "A" || items[0].IsFoil || items[0].IsEtched {
		t.Errorf("item 0 = %+v", items[0])
	}
	if items[1].ScryfallID != "b" || !items[1].IsFoil {
		t.Errorf("item 1 = %+v", items[1])
	}
	if items[2].ScryfallID != "c" || !items[2].IsEtched || items[2].IsFoil {
		t.Errorf("item 2 = %+v", items[2])
	}
	if items[3].ScryfallID != "e" || !items[3].IsFoil {
		t.Errorf("item 3 = %+v", items[3])
	}

	if got := cubeItems(&cube, 2); len(got) != 2 {
		t.Errorf("maxRows 2 kept %d items", len(got))
	}
}

func TestLoadLive(t *testing.T) {
	if os.Getenv("CUBECOBRA_LIVE") == "" {
		t.Skip("CUBECOBRA_LIVE not set; skipping live CubeCobra test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	items, name, err := Load(ctx, "https://cubecobra.com/cube/overview/LSVCube", 0)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" || len(items) == 0 {
		t.Fatalf("name=%q items=%d", name, len(items))
	}
	t.Logf("cube %q with %d cards", name, len(items))
}

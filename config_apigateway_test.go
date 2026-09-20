package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAPIGatewayConfigDecodes(t *testing.T) {
	var c ConfigType
	if err := json.Unmarshal([]byte(`{"api_gateway":{"url":"https://api.example/","games":["magic","pokemon"]}}`), &c); err != nil {
		t.Fatal(err)
	}
	applyAPIGatewayDefaults(&c.APIGateway, "magic")
	if c.APIGateway.URL != "https://api.example" {
		t.Errorf("url %q, want the trailing slash trimmed", c.APIGateway.URL)
	}
	if want := []string{"magic", "pokemon"}; !reflect.DeepEqual(c.APIGateway.Games, want) {
		t.Errorf("games %v want %v", c.APIGateway.Games, want)
	}
}

func TestAPIGatewayConfigDefaults(t *testing.T) {
	var c APIGatewayConfig
	applyAPIGatewayDefaults(&c, "pokemon")
	if c.URL != DefaultAPIGatewayURL || !reflect.DeepEqual(c.Games, []string{"magic", "pokemon"}) {
		t.Errorf("defaults %+v", c)
	}

	var empty APIGatewayConfig
	applyAPIGatewayDefaults(&empty, "")
	if !reflect.DeepEqual(empty.Games, []string{DefaultGame}) {
		t.Errorf("empty game: %+v", empty)
	}

	relative := APIGatewayConfig{URL: "api.example.com"}
	applyAPIGatewayDefaults(&relative, "magic")
	if relative.URL != DefaultAPIGatewayURL {
		t.Errorf("relative url %q, want the fallback", relative.URL)
	}
}

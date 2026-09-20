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
	applyAPIGatewayDefaults(&c.APIGateway)
	if c.APIGateway.URL != "https://api.example" {
		t.Errorf("url %q, want the trailing slash trimmed", c.APIGateway.URL)
	}
	if want := []string{"magic", "pokemon"}; !reflect.DeepEqual(c.APIGateway.Games, want) {
		t.Errorf("games %v want %v", c.APIGateway.Games, want)
	}
}

func TestAPIGatewayConfigDefaults(t *testing.T) {
	var c APIGatewayConfig
	applyAPIGatewayDefaults(&c)
	if c.URL != DefaultAPIGatewayURL || !reflect.DeepEqual(c.Games, []string{DefaultGame}) {
		t.Errorf("defaults %+v", c)
	}
}

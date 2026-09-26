package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminToolsLinkTheGatewayAdmin(t *testing.T) {
	savedDev, savedSig, savedCfg := DevMode, SigCheck, Config.APIGateway
	t.Cleanup(func() { DevMode, SigCheck, Config.APIGateway = savedDev, savedSig, savedCfg })
	DevMode, SigCheck = true, false
	Config.APIGateway = APIGatewayConfig{URL: "https://api.example", Games: []string{"magic"}}
	req := httptest.NewRequest(http.MethodGet, "/admin?page=tools", nil)
	req.Host = "mtgban.com"
	rec := httptest.NewRecorder()
	Admin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="https://api.example/admin"`) {
		t.Error("tools page does not link the gateway admin")
	}
	if strings.Contains(body, "Generate Demo Key") || strings.Contains(body, `value="demokey"`) {
		t.Error("the demo key card is still there")
	}
}

func TestAdminNewKeyDefaultsABlankDuration(t *testing.T) {
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = true, false

	const user = "ops@example.com"
	apiUsersMutex.Lock()
	if Config.APIUserSecrets == nil {
		Config.APIUserSecrets = map[string]string{}
	}
	Config.APIUserSecrets[user] = goldenSecret
	apiUsersMutex.Unlock()
	t.Cleanup(func() {
		apiUsersMutex.Lock()
		delete(Config.APIUserSecrets, user)
		apiUsersMutex.Unlock()
	})

	req := httptest.NewRequest(http.MethodGet, "/admin?page=tools&reboot=newKey&user="+user+"&duration=", nil)
	req.Host = "mtgban.com"
	rec := httptest.NewRecorder()
	Admin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	key := loc.Query().Get("msg")
	if strings.HasPrefix(key, "error: ") {
		t.Fatalf("newKey failed: %s", key)
	}
	blob, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("minted key is not base64: %v", err)
	}
	claims, err := url.ParseQuery(string(blob))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Get("Expires") == "" {
		t.Errorf("a blank duration minted a permanent key: %v", claims)
	}
}

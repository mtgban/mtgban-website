package config

import (
	"context"
	"encoding/json"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/mtgban/go-mtgban/mtgban"
)

// Config struct holds the application's configuration
type AppConfig struct {
	Port                   string            `json:"port"`
	DBAddress              string            `json:"db_address"`
	RedisAddr              string            `json:"redis_addr"`
	DiscordHook            string            `json:"discord_hook"`
	DiscordNotifHook       string            `json:"discord_notif_hook"`
	DiscordInviteLink      string            `json:"discord_invite_link"`
	SellersFilePath        string            `json:"sellers_path"`
	VendorsFilePath        string            `json:"vendors_path"`
	Affiliate              map[string]string `json:"affiliate"`
	AffiliatesList         []string          `json:"affiliates_list"`
	Api                    map[string]string `json:"api"`
	DiscordToken           string            `json:"discord_token"`
	DiscordAllowList       []string          `json:"discord_allowlist"`
	DevSellers             []string          `json:"dev_sellers"`
	ArbitDefaultSellers    []string          `json:"arbit_default_sellers"`
	ArbitBlockVendors      []string          `json:"arbit_block_vendors"`
	SearchRetailBlockList  []string          `json:"search_block_list"`
	SearchBuylistBlockList []string          `json:"search_buylist_block_list"`
	SleepersBlockList      []string          `json:"sleepers_block_list"`
	GlobalAllowList        []string          `json:"global_allow_list"`
	GlobalProbeList        []string          `json:"global_probe_list"`
	Patreon                struct {
		Secret map[string]string `json:"secret"`
		Emails map[string]string `json:"emails"`
	} `json:"patreon"`
	ApiUserSecrets    map[string]string `json:"api_user_secrets"`
	GoogleCredentials string            `json:"google_credentials"`

	ACL map[string]map[string]map[string]string `json:"acl"`

	FreeEnable   bool   `json:"free_enable"`
	FreeLevel    string `json:"free_level"`
	FreeHostname string `json:"free_hostname"`

	Uploader struct {
		ServiceAccount string `json:"service_account"`
		BucketName     string `json:"bucket_name"`
		ProjectID      string `json:"project_id"`
		DatasetID      string `json:"dataset_id"`
	} `json:"uploader"`

	Scrapers map[string][]struct {
		HasRedis   bool   `json:"has_redis,omitempty"`
		RedisIndex int    `json:"redis_index,omitempty"`
		TableName  string `json:"table_name"`
		mtgban.ScraperInfo
	} `json:"scrapers"`
}

var config AppConfig

// Load from google secret manager, managed identity handles the auth
func LoadConfigFromSecretManager(secretname string) (*AppConfig, error) {
	ctx := context.Background()

	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	defer c.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretname,
	}

	resp, err := c.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	secretData := resp.Payload.Data

	err = json.Unmarshal(secretData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	return &config, nil
}

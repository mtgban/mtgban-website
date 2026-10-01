package main

import (
	"errors"
	"log"
	"strings"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

type discordAlertSender struct{}

// Send opens (or reuses) the DM channel and posts the embed.
func (discordAlertSender) Send(discordUserID string, embed *discordgo.MessageEmbed) error {
	if dg == nil {
		return errors.New("discord session not connected")
	}
	ch, err := dg.UserChannelCreate(discordUserID)
	if err != nil {
		return err
	}
	_, err = dg.ChannelMessageSendEmbed(ch.ID, embed)
	return err
}

type logAlertSender struct{}

func (logAlertSender) Send(discordUserID string, embed *discordgo.MessageEmbed) error {
	log.Printf("alerts: would DM %s: %s\n%s", discordUserID, embed.Title, embed.Description)
	return nil
}

// liveAlertSender is the Discord sender, or the log in dev unless send
// (-alerts-send) asks for real DMs.
func liveAlertSender(send bool) alerts.Sender {
	if DevMode && !send {
		return logAlertSender{}
	}
	return discordAlertSender{}
}

// alertSiteURL is the origin links in a DM point at; a background job has
// no request to read a host from. Empty means links are left out.
func alertSiteURL() string {
	cfg := Config()
	u := strings.TrimRight(cfg.SiteURL, "/")
	if u != "" {
		return u
	}
	if DevMode {
		return "http://localhost:" + cfg.Port
	}
	if cfg.Game != "" && cfg.Game != DefaultGame {
		// The default host is the Magic site; another game must not link there.
		return ""
	}
	return DefaultExternalURL
}

// alertStoreLabel is the store name, or its shorthand when it is not loaded.
func alertStoreLabel(shorthand string) string {
	name := scraperName(shorthand)
	if name != "" {
		return name
	}
	return shorthand
}

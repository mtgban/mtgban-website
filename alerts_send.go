package main

import (
	"errors"
	"log"

	"github.com/bwmarrin/discordgo"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// discordAlertSender DMs through the bot session; channels is the DM
// channel id by user, filled as the run goes, since discordgo caches none
// and each run builds its own sender on one goroutine.
type discordAlertSender struct {
	channels map[string]string
}

// Send opens the DM channel, once per user per run, and posts the embed.
func (s *discordAlertSender) Send(discordUserID string, embed *discordgo.MessageEmbed) error {
	if dg == nil {
		return errors.New("discord session not connected")
	}
	id, ok := s.channels[discordUserID]
	if !ok {
		ch, err := dg.UserChannelCreate(discordUserID)
		if err != nil {
			return err
		}
		id = ch.ID
		s.channels[discordUserID] = id
	}
	_, err := dg.ChannelMessageSendEmbed(id, embed)
	return err
}

type logAlertSender struct{}

func (logAlertSender) Send(discordUserID string, embed *discordgo.MessageEmbed) error {
	log.Printf("alerts: would DM %s: %s\n%s", discordUserID, embed.Title, embed.Description)
	return nil
}

// liveAlertSender is the Discord sender, or the log in dev unless send
// (-alerts-send) asks for real DMs.
func liveAlertSender(send bool) alerts.DiscordSender {
	if DevMode && !send {
		return logAlertSender{}
	}
	return &discordAlertSender{channels: map[string]string{}}
}

// alertStoreLabel is the store name, or its shorthand when it is not loaded.
func alertStoreLabel(shorthand string) string {
	name := scraperName(shorthand)
	if name != "" {
		return name
	}
	return shorthand
}

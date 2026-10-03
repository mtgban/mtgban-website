package alerts

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
)

// Discord embed description limits: how many store or card lines a list
// shows before summarizing the rest, and the hard cap on the whole body.
const (
	embedMaxLines       = 15
	embedMaxDescription = 4000
	// embedCutWindow is how far back a cut looks for a line break.
	embedCutWindow = 200
)

// DefaultSendPace is the gap a run leaves between its DMs.
const DefaultSendPace = 250 * time.Millisecond

// DiscordSender delivers one alert message to one Discord user.
type DiscordSender interface {
	Send(discordUserID string, embed *discordgo.MessageEmbed) error
}

// notifier is a deliverer that also carries the park notice DM.
type notifier interface {
	notify(discordUserID string, embed *discordgo.MessageEmbed) error
}

// discordDeliverer sends one DM per firing, pacing every DM it sends.
type discordDeliverer struct {
	sender DiscordSender
	pace   time.Duration
	sent   bool
}

// NewDiscordDeliverer delivers through s, pace apart; build one per run,
// so the first DM of a run goes out at once.
func NewDiscordDeliverer(s DiscordSender, pace time.Duration) Deliverer {
	return &discordDeliverer{sender: s, pace: pace}
}

func (d *discordDeliverer) Kind() ChannelKind { return ChannelDiscord }

// Deliver DMs each firing to the channel's Discord id.
func (d *discordDeliverer) Deliver(_ context.Context, dg Digest, ch Channel, label func(string) string) []Delivery {
	out := make([]Delivery, 0, len(dg.Firings))
	for _, f := range dg.Firings {
		err := d.notify(ch.Address, renderDiscord(f, label))
		out = append(out, Delivery{AlertID: f.Alert.ID, Err: err})
	}
	return out
}

// notify sends one DM, waiting pace after the one before it.
func (d *discordDeliverer) notify(discordUserID string, embed *discordgo.MessageEmbed) error {
	if d.sent && d.pace > 0 {
		time.Sleep(d.pace)
	}
	d.sent = true
	return d.sender.Send(discordUserID, embed)
}

// isDMPermanent is Discord blaming the recipient: DMs refused (50007) or
// an unknown user (10013). A status alone may be the bot's own fault.
func isDMPermanent(err error) bool {
	var rest *discordgo.RESTError
	if !errors.As(err, &rest) || rest.Message == nil {
		return false
	}
	switch rest.Message.Code {
	case discordgo.ErrCodeCannotSendMessagesToThisUser, discordgo.ErrCodeUnknownUser:
		return true
	}
	return false
}

// undeliverableReason is the user-facing error for a permanent send failure.
func undeliverableReason(err error) string {
	reason := "Discord rejected the DM"
	var rest *discordgo.RESTError
	if !errors.As(err, &rest) || rest.Message == nil {
		return reason
	}
	if rest.Message.Code == discordgo.ErrCodeCannotSendMessagesToThisUser {
		reason = "Discord refused the DM: join the MTGBAN server and allow DMs from members"
	}
	if rest.Message.Message != "" {
		reason += " (Discord: " + rest.Message.Message + ")"
	}
	return reason
}

func money(v float64) string { return fmt.Sprintf("$%.2f", v) }

var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, `*`, `\*`, `_`, `\_`, `~`, `\~`, `|`, `\|`,
	`[`, `\[`, `]`, `\]`, `(`, `\(`, `)`, `\)`, "`", "\\`",
)

// escapeMarkdown keeps Discord from reading card text as formatting.
func escapeMarkdown(s string) string { return markdownEscaper.Replace(s) }

// alertLine names what an alert watches, finish, condition and side
// included, so twins on one collector number stay apart.
func alertLine(c Card, condition string, side Side) string {
	return fmt.Sprintf("%s %s #%s, %s, %s %s\n", escapeMarkdown(c.Name), escapeMarkdown(c.Set), escapeMarkdown(c.Number), c.Finish, condition, side)
}

func thresholdLabel(t Threshold, reference float64, above bool) string {
	if t.Kind == KindPct {
		return fmt.Sprintf("%s (%.0f%% of reference)", money(t.Resolve(reference, above)), t.Value)
	}
	return money(t.Value)
}

// renderDiscord is the DM for one firing: what crossed, at which stores,
// with a buy or sell link for each through the site's redirect when the
// firing's origin is set. label names a store from its shorthand.
func renderDiscord(f Firing, label func(shorthand string) string) *discordgo.MessageEmbed {
	a, d, siteURL := f.Alert, f.Decision, f.Origin
	kind := "r"
	verb := "Buy"
	if a.Side == SideBuylist {
		kind, verb = "b", "Sell"
	}
	var b strings.Builder
	b.WriteString(alertLine(a.Card, a.Condition, a.Side))
	lines := func(heading string, hits []Quote) {
		fmt.Fprintf(&b, "\n**%s**\n", heading)
		shown := hits
		if len(shown) > embedMaxLines {
			shown = shown[:embedMaxLines]
		}
		for _, q := range shown {
			if siteURL == "" {
				fmt.Fprintf(&b, "%s: %s\n", label(q.Store), money(q.Price))
				continue
			}
			fmt.Fprintf(&b, "%s: %s [%s](%s/go/%s/%s/%s)\n", label(q.Store), money(q.Price), verb, siteURL, kind, url.PathEscape(q.Store), url.PathEscape(a.CardID))
		}
		more := len(hits) - len(shown)
		if more > 0 {
			fmt.Fprintf(&b, "and %d more stores\n", more)
		}
	}
	if d.FireAbove {
		lines("Crossed above "+thresholdLabel(a.Above, a.ReferencePrice, true), d.AboveHits)
	}
	if d.FireBelow {
		lines("Crossed below "+thresholdLabel(a.Below, a.ReferencePrice, false), d.BelowHits)
	}
	fmt.Fprintf(&b, "\nreference %s", money(a.ReferencePrice))
	if a.CreatedPrice != nil {
		fmt.Fprintf(&b, ", %s when the alert was set", money(*a.CreatedPrice))
	}
	manageLink := ""
	embedURL := ""
	if siteURL != "" {
		manageLink = fmt.Sprintf("[Manage alerts](%s/alerts)", siteURL)
		embedURL = siteURL + "/alerts"
		fmt.Fprintf(&b, "\n%s", manageLink)
	}

	desc := b.String()
	if utf8.RuneCountInString(desc) > embedMaxDescription {
		desc = truncateEmbedDescription(desc, manageLink, embedMaxDescription)
	}
	return &discordgo.MessageEmbed{
		Title:       "Price alert: " + a.Card.Name,
		URL:         embedURL,
		Description: desc,
	}
}

// parkedEmbed is the one DM a user gets when a run parks their alerts:
// why, which cards, and a link to the alerts page on the site the newest
// of them was saved on.
func parkedEmbed(parked []Moved, reason string) *discordgo.MessageEmbed {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", reason)
	shown := parked
	if len(shown) > embedMaxLines {
		shown = shown[:embedMaxLines]
	}
	for _, m := range shown {
		b.WriteString(alertLine(m.Card, m.Condition, m.Side))
	}
	more := len(parked) - len(shown)
	if more > 0 {
		fmt.Fprintf(&b, "and %d more\n", more)
	}
	manageLink := ""
	embedURL := ""
	origin := parked[0].Origin
	if origin != "" {
		manageLink = fmt.Sprintf("[Manage alerts](%s/alerts)", origin)
		embedURL = origin + "/alerts"
		fmt.Fprintf(&b, "\n%s", manageLink)
	}
	desc := b.String()
	if utf8.RuneCountInString(desc) > embedMaxDescription {
		desc = truncateEmbedDescription(desc, manageLink, embedMaxDescription)
	}
	return &discordgo.MessageEmbed{
		Title:       "Price alerts parked",
		URL:         embedURL,
		Description: desc,
	}
}

// truncateEmbedDescription cuts s to limit runes total, at a line break
// when one is near, keeping the manage-alerts link (if any) at the end.
func truncateEmbedDescription(s, link string, limit int) string {
	suffix := ""
	if link != "" {
		suffix = "\n" + link
	}
	keep := limit - utf8.RuneCountInString(suffix)
	if keep < 0 {
		keep = 0
	}
	runes := []rune(s)
	if keep > len(runes) {
		keep = len(runes)
	}
	for i := keep - 1; i > 0 && i >= keep-embedCutWindow; i-- {
		if runes[i] == '\n' {
			keep = i
			break
		}
	}
	return string(runes[:keep]) + suffix
}

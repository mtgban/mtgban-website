// Package pledge turns a Patreon login into a reader and the site tier their
// pledge, or a grant, entitles them to: who Patreon says the reader is, which
// tier title its membership answer names, and which of the site's tiers that
// is. It holds no state of its own; the caller hands it hooks for the grant
// list and the admin log, the way internal/access and internal/sessionstore
// reach theirs.
package pledge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/patreon"
)

// Hooks is how a Resolver reaches the host's own state. Every field is
// required, the same as internal/access.Hooks.
type Hooks struct {
	// Log returns the admin log. It is called at each use, so a log the host
	// replaces later is the one written to.
	Log func() *log.Logger

	// GrantFor returns the grant that names email, if the grant list has one.
	GrantFor func(email string) (access.Grant, bool)
}

// Resolver looks a Patreon login up and sorts the reader into a tier. It
// holds nothing but its hooks, so it is safe for concurrent use.
type Resolver struct {
	hooks Hooks
}

// New returns a Resolver that reads the grant list and writes the admin log
// through the given hooks.
func New(hooks Hooks) *Resolver {
	if hooks.Log == nil || hooks.GrantFor == nil {
		panic("pledge: New needs Log and GrantFor")
	}
	return &Resolver{hooks: hooks}
}

// User is what a Patreon login tells the site about the reader.
type User struct {
	UserID        string
	MembershipID  string
	FullName      string
	Email         string
	EmailVerified bool
	DiscordID     string
	// DiscordKnown is true when this login's Patreon answer had an opinion
	// (linked or explicitly unlinked) on the Discord id.
	DiscordKnown bool
}

// UserFromData maps a decoded Patreon identity answer to what the
// site keeps. Pure, so it's testable without a Patreon client.
func UserFromData(userData *patreon.UserData) *User {
	// Look for the membership id of the user and this account
	membershipID := ""
	for _, memberData := range userData.Data.Relationships.Memberships.Data {
		if memberData.Type == "member" {
			membershipID = memberData.ID
			break
		}
	}

	discordID, discordKnown := userData.DiscordUserID()

	return &User{
		UserID:        userData.Data.IDV1,
		MembershipID:  membershipID,
		FullName:      userData.Data.Attributes.FullName,
		Email:         strings.ToLower(userData.Data.Attributes.Email),
		EmailVerified: userData.Data.Attributes.IsEmailVerified,
		DiscordID:     discordID,
		DiscordKnown:  discordKnown,
	}
}

// UserIDs asks Patreon who the client's token belongs to. An answer that
// carries errors is refused.
func (res *Resolver) UserIDs(ctx context.Context, client *patreon.Client) (*User, error) {
	userData, err := client.GetUserData(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve user data: %w", err)
	}

	res.hooks.Log().Printf("getUserIds: email=%q name=%q memberships=%d",
		userData.Data.Attributes.Email, userData.Data.Attributes.FullName,
		len(userData.Data.Relationships.Memberships.Data))
	if len(userData.Errors) > 0 {
		return nil, fmt.Errorf("user data error: %q", userData.Errors)
	}

	return UserFromData(userData), nil
}

// The two ways UserTier finds no tier title in an answer that otherwise
// decodes: a pledge entitling no tier, or only Patreon's free tier, and one
// entitling a tier the answer does not name.
var (
	errNoEntitledTier = errors.New("no entitled tier")
	errUntitledTier   = errors.New("empty tier title")
)

// UserTier is the title of the tier a membership currently entitles, as
// Patreon's answer names it. It is not yet a site tier; Resolve maps it.
func (res *Resolver) UserTier(ctx context.Context, client *patreon.Client, userID string) (string, error) {
	membershipData, err := client.GetMembershipData(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("cannot decode membership data: %w", err)
	}

	res.hooks.Log().Println("getUserTier:", membershipData)
	if len(membershipData.Errors) > 0 {
		return "", fmt.Errorf("user data error: %q", membershipData.Errors)
	}

	// Look for the tier id of the user, past a tier the answer says costs
	// nothing: a free membership pledges nothing, whatever its title
	tierID := ""
	tiers, free := 0, 0
	for _, tierData := range membershipData.Data.Relationships.CurrentlyEntitledTiers.Data {
		if tierData.Type != "tier" {
			continue
		}
		tiers++
		if freeTier(membershipData, tierData.ID) {
			free++
			continue
		}
		if tierID == "" {
			tierID = tierData.ID
		}
	}
	if tiers > 0 && free == tiers {
		return "", errNoEntitledTier
	}

	// Get a human-readable name for the tier
	tierTitle := ""
	for _, tierData := range membershipData.Included {
		if tierData.Type == "tier" && tierID == tierData.ID {
			tierTitle = tierData.Attributes.Title
		}
	}

	if tierTitle == "" {
		if len(membershipData.Data.Relationships.CurrentlyEntitledTiers.Data) == 0 {
			return "", errNoEntitledTier
		}
		return "", errUntitledTier
	}

	return tierTitle, nil
}

// freeTier says whether the membership answer names the tier id as one that
// costs nothing. A tier whose cost the answer leaves out is not free.
func freeTier(membershipData *patreon.MembershipData, id string) bool {
	for _, tierData := range membershipData.Included {
		if tierData.Type == "tier" && tierData.ID == id {
			amount := tierData.Attributes.AmountCents
			return amount != nil && *amount == 0
		}
	}
	return false
}

// DidNotAnswer tells a lookup Patreon never answered, for the request
// failing, the deadline running out, Patreon failing or refusing it (5xx,
// 429, 401, 403) or an answer that does not decode, from one whose answer
// named no tier.
func DidNotAnswer(ctx context.Context, err error) bool {
	var netErr *url.Error
	var statusErr *patreon.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			return true
		}
		return statusErr.StatusCode >= 500
	}
	return err != nil && (errors.As(err, &netErr) || errors.Is(err, patreon.ErrUnreadable) || ctx.Err() != nil)
}

// Verdict is what the tier lookup says about a reader's pledge.
type Verdict int

// The verdicts a Resolve reaches.
const (
	// Unknown is no usable answer, from Patreon or in its shape. It
	// must never be read as a cancellation.
	Unknown Verdict = iota
	Entitled
	// NotEntitled is Patreon answering that nothing is pledged.
	NotEntitled
)

// String spells the verdict the way the admin log shows it.
func (v Verdict) String() string {
	switch v {
	case Entitled:
		return "entitled"
	case NotEntitled:
		return "not entitled"
	}
	return "unknown"
}

// Resolve is the site tier of a reader Patreon just identified, with the
// overrides of the grant behind it, if any, and whether a grant named the
// tier; overrides come back only with Entitled. A grant naming a tier
// decides it without Patreon's membership answer; otherwise the answer
// does, and only a reader with no membership, or one entitling no tier, is
// NotEntitled. An identity naming nobody is Unknown, and so is any
// refusal of a membership the identity named, a 404 included: a verdict
// that is unknown never extends a session, so it can keep one alive only
// until its signature runs out on its own. err is what made an Unknown
// verdict.
func (res *Resolver) Resolve(ctx context.Context, client *patreon.Client, user *User) (tier string, overrides map[string]map[string]string, granted bool, verdict Verdict, err error) {
	if user.UserID == "" || user.Email == "" {
		return "", nil, false, Unknown, errors.New("identity answer names no user")
	}

	// If user is in the allowed list, load the tier from here
	grant, found := res.hooks.GrantFor(user.Email)
	if found {
		overrides = grant.Overrides
		res.hooks.Log().Printf("Granted %s (%s) %s tier for %s", grant.Name, grant.Email, grant.Tier, grant.Category)
		if grant.Tier != "" {
			return grant.Tier, overrides, true, Entitled, nil
		}
	}

	if user.MembershipID == "" {
		return "", nil, false, NotEntitled, nil
	}

	// Else, load the tier from the API
	title, err := res.UserTier(ctx, client, user.MembershipID)
	if err != nil {
		res.hooks.Log().Println("getUserTier error", err)
	}
	if errors.Is(err, errNoEntitledTier) {
		return "", nil, false, NotEntitled, nil
	}
	if err != nil {
		return "", nil, false, Unknown, err
	}

	switch title {
	case "PIONEER", "PIONEER (Early Adopters)", "STANDARD":
		tier = "Pioneer"
	case "MODERN", "MODERN (Early Adopters)":
		tier = "Modern"
	case "LEGACY", "LEGACY (Early Adopters)":
		tier = "Legacy"
	case "VINTAGE", "VINTAGE (Early Adopters)", "TYPE ONE":
		tier = "Vintage"
	default:
		// A tier Patreon renamed or added is not a cancelled pledge
		res.hooks.Log().Printf("resolveTier: unexpected tier title %q", title)
		return "", nil, false, Unknown, fmt.Errorf("unexpected tier title %q", title)
	}
	return tier, overrides, false, Entitled, nil
}

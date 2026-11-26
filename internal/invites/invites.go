// Package invites holds the rules of the admin's invite links: the shape
// of a code, the bounds of what an admin may mint, which tiers, pages and
// options an invite may sign, and the state an invite is in
// (docs/adr/0011-invite-links.md). It reads no database and no request;
// the site fills its values and stores what it decides.
package invites

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mtgban/mtgban-website/internal/access"
)

// alphabet is lowercase letters and digits without 0 o 1 l i, which are
// misread for each other.
const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// CodeLen is a code's length: about 40 bits from 31 symbols.
const CodeLen = 8

// What an admin may mint, and what the form starts on.
const (
	MinUses           = 1
	MaxUses           = 25
	DefaultUses       = 1
	MinOpenFor        = time.Hour
	MaxOpenFor        = 30 * 24 * time.Hour
	DefaultOpenFor    = 7 * 24 * time.Hour
	MinAccessDays     = 1
	MaxAccessDays     = 31
	DefaultAccessDays = 7
	MaxNote           = 200
)

// NewCode draws a code, every symbol equally likely.
func NewCode() (string, error) {
	// The largest multiple of len(alphabet) a byte holds: bytes past it
	// are drawn again, so no symbol comes up more often than another.
	const limit = 256 - 256%len(alphabet)
	code := make([]byte, 0, CodeLen)
	var buf [16]byte
	for len(code) < CodeLen {
		_, err := rand.Read(buf[:])
		if err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit || len(code) == CodeLen {
				continue
			}
			code = append(code, alphabet[int(b)%len(alphabet)])
		}
	}
	return string(code), nil
}

// Normalize is a code as typed, in the case codes are drawn in.
func Normalize(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// ValidCode reports whether code has the shape NewCode draws, so a page
// can refuse anything else before asking the store.
func ValidCode(code string) bool {
	if len(code) != CodeLen {
		return false
	}
	for i := 0; i < len(code); i++ {
		if strings.IndexByte(alphabet, code[i]) < 0 {
			return false
		}
	}
	return true
}

// nonceLen is 16 random bytes as unpadded base64url.
const nonceLen = 22

// NewNonce is the accept form's own token, which lets a repeated press be
// told from a second acceptance.
func NewNonce() (string, error) {
	var buf [16]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ValidNonce reports whether nonce has the shape NewNonce makes.
func ValidNonce(nonce string) bool {
	if len(nonce) != nonceLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil
}

// Spec is one invite as an admin asks for it.
type Spec struct {
	Tier       string
	Overrides  map[string]map[string]string
	MaxUses    int
	OpenFor    time.Duration
	AccessDays int
	Note       string
}

// Rules is what an invite may sign, against the access table in force.
type Rules struct {
	Table access.Table
	// Pages are the pages an invite may open, in the order the form lists
	// them; a tier opening any other is not one an invite may sign.
	Pages []string
	// Options are the options an invite may set, in the form's order.
	Options []string
	// Open is the table's entry for every reader, which is not a tier.
	Open string
}

// AllowedTiers are the tiers an invite may sign, sorted.
func (r Rules) AllowedTiers() []string {
	var tiers []string
	for tier, features := range r.Table {
		if tier == r.Open {
			continue
		}
		allowed := true
		for page := range features {
			if !slices.Contains(r.Pages, page) {
				allowed = false
				break
			}
		}
		if allowed {
			tiers = append(tiers, tier)
		}
	}
	slices.Sort(tiers)
	return tiers
}

// Feature is a page an invite may open and the options it may set there.
type Feature struct {
	Page    string
	Options []string
}

// Features lists every page and option any tier in the table sets, less
// those an invite may not sign.
func (r Rules) Features() []Feature {
	var out []Feature
	for _, page := range r.Pages {
		opened := false
		var options []string
		for _, features := range r.Table {
			set, found := features[page]
			if !found {
				continue
			}
			opened = true
			for key := range set {
				if slices.Contains(r.Options, key) && !slices.Contains(options, key) {
					options = append(options, key)
				}
			}
		}
		if !opened {
			continue
		}
		slices.SortFunc(options, func(a, b string) int {
			return slices.Index(r.Options, a) - slices.Index(r.Options, b)
		})
		out = append(out, Feature{Page: page, Options: options})
	}
	return out
}

// Overrides keeps what posted sets beyond the tier: a page the tier does
// not open, with what it sets there, and on a page it does, the options
// whose values differ. A blank value sets nothing.
func (r Rules) Overrides(tier string, posted map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	base := r.Table[tier]
	for page, options := range posted {
		have, opened := base[page]
		diff := map[string]string{}
		for key, val := range options {
			if val == "" {
				continue
			}
			current, set := have[key]
			if !set || current != val {
				diff[key] = val
			}
		}
		if !opened || len(diff) > 0 {
			out[page] = diff
		}
	}
	return out
}

// Check says what is wrong with spec, or nil when it can be minted.
func (r Rules) Check(spec Spec) error {
	if !slices.Contains(r.AllowedTiers(), spec.Tier) {
		return fmt.Errorf("tier %q cannot be invited to", spec.Tier)
	}
	for page, options := range spec.Overrides {
		if !slices.Contains(r.Pages, page) {
			return fmt.Errorf("an invite cannot open %s", page)
		}
		for key, val := range options {
			if !slices.Contains(r.Options, key) {
				return fmt.Errorf("an invite cannot set %s", key)
			}
			if val == "" {
				return fmt.Errorf("%s.%s is empty", page, key)
			}
		}
	}
	switch {
	case spec.MaxUses < MinUses || spec.MaxUses > MaxUses:
		return fmt.Errorf("uses must be %d to %d", MinUses, MaxUses)
	case spec.OpenFor < MinOpenFor || spec.OpenFor > MaxOpenFor:
		return errors.New("an invite stays open from an hour to 30 days")
	case spec.AccessDays < MinAccessDays || spec.AccessDays > MaxAccessDays:
		return fmt.Errorf("access lasts %d to %d days", MinAccessDays, MaxAccessDays)
	case utf8.RuneCountInString(spec.Note) > MaxNote:
		return fmt.Errorf("the note is over %d characters", MaxNote)
	}
	return nil
}

// The states an invite can be in.
const (
	StateOpen    = "open"
	StateUsedUp  = "used up"
	StateExpired = "expired"
	StateRevoked = "revoked"
	// StateBroken is an invite whose tier an invite may no longer sign.
	StateBroken = "broken"
)

// Life is what an invite's state is read from.
type Life struct {
	Tier       string
	Uses       int
	MaxUses    int
	AccessDays int
	OpenUntil  time.Time
	// RevokedAt is zero while the invite is not revoked.
	RevokedAt time.Time
}

// State is the invite's state at now, given the tiers allowed now.
func (l Life) State(now time.Time, allowed []string) string {
	switch {
	case !l.RevokedAt.IsZero():
		return StateRevoked
	case l.Uses >= l.MaxUses:
		return StateUsedUp
	case !now.Before(l.OpenUntil):
		return StateExpired
	case !slices.Contains(allowed, l.Tier):
		return StateBroken
	}
	return StateOpen
}

// LastAccessEnds is the latest any signature from the invite can last: the
// last moment it could be accepted, plus its access.
func (l Life) LastAccessEnds() time.Time {
	closed := l.OpenUntil
	if !l.RevokedAt.IsZero() && l.RevokedAt.Before(closed) {
		closed = l.RevokedAt
	}
	return closed.Add(time.Duration(l.AccessDays) * 24 * time.Hour)
}

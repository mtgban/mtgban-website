package offline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

const wmMinPrice = 0.25

// Watermark perturbs a deterministic per user selection of prices by one
// cent so leaked payloads are attributable. Perturbation only, no fake rows.
func Watermark(secret []byte, email string, p *SetPayload) {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("offline-watermark:" + strings.ToLower(email)))
	seed := mac.Sum(nil)

	// One keyed HMAC reused for every mark; Reset restores the keyed state.
	m := hmac.New(sha256.New, seed)
	var sum []byte
	mark := func(section, uuid, store, tag string, price float64) float64 {
		if price < wmMinPrice {
			return price
		}
		m.Reset()
		m.Write([]byte(section + "|" + uuid + "|" + store + "|" + tag))
		sum = m.Sum(sum[:0])
		h := binary.BigEndian.Uint64(sum[:8])
		if h%128 != 0 {
			return price
		}
		if (h>>8)&1 == 1 {
			return price + 0.01
		}
		return price - 0.01
	}

	walk := func(name string, section map[string]map[string]*PriceEntry) {
		for uuid, byStore := range section {
			for store, e := range byStore {
				for tag, v := range e.Conditions {
					e.Conditions[tag] = mark(name, uuid, store, tag, v)
				}
				base := e.Cond
				if e.Regular > 0 {
					tag := base
					if tag == "" {
						tag = "@r"
					}
					e.Regular = mark(name, uuid, store, tag, e.Regular)
				}
				if e.Foil > 0 {
					tag := "@f"
					if base != "" {
						tag = base + "_foil"
					}
					e.Foil = mark(name, uuid, store, tag, e.Foil)
				}
				if e.Etched > 0 {
					tag := "@e"
					if base != "" {
						tag = base + "_etched"
					}
					e.Etched = mark(name, uuid, store, tag, e.Etched)
				}
				if e.Sealed > 0 {
					e.Sealed = mark(name, uuid, store, "@s", e.Sealed)
				}
			}
		}
	}
	walk("retail", p.Retail)
	walk("buylist", p.Buylist)
}

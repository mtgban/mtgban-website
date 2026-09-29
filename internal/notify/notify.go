// Package notify delivers one-line messages to Discord webhooks.
package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
)

// maxContent is the most content a Discord message may carry; Discord
// refuses a longer one outright. It counts characters, which a cut at this
// many bytes stays within however they are counted.
const maxContent = 2000

type payload struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}

// Post delivers message to the Discord webhook at hook, shown under the kind
// username. When dev is set the message is prefixed with "[DEV] " so test
// traffic stays recognizable. A message longer than Discord accepts is cut to
// fit. Failures, a post Discord refuses among them, are logged and dropped —
// notifications are fire-and-forget. The log never quotes hook, whose path
// carries the webhook's token.
func Post(hook, kind, message string, dev bool) {
	var p payload
	p.Username = kind
	if dev {
		p.Content = "[DEV] "
	}
	p.Content += message
	if len(p.Content) > maxContent {
		// A cut through a rune leaves its first bytes, which ToValidUTF8 drops.
		p.Content = strings.ToValidUTF8(p.Content[:maxContent], "")
	}

	reqBody, err := json.Marshal(&p)
	if err != nil {
		log.Println(err)
		return
	}

	resp, err := cleanhttp.DefaultClient().Post(hook, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		// A *url.Error's text quotes the URL it was posting to.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		log.Printf("notify: %s post failed: %s", kind, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Printf("notify: %s post refused: %s", kind, resp.Status)
	}
}

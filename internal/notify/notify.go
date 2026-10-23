// Package notify delivers one-line messages to Discord webhooks.
package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
)

// client posts every message. Pooled, so the Discord connection is reused
// across posts, and timed out, so a stalled Discord cannot hold a goroutine
// (and a staleness check's lock) for longer than this.
var client = &http.Client{
	Transport: cleanhttp.DefaultPooledTransport(),
	Timeout:   15 * time.Second,
}

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
	_ = Send(hook, kind, message, dev)
}

// Send is Post for a caller that tries again later: it also returns why
// the message did not go through, which it logs either way.
func Send(hook, kind, message string, dev bool) error {
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
		return err
	}

	resp, err := client.Post(hook, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		// A *url.Error's text quotes the URL it was posting to.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		log.Printf("notify: %s post failed: %s", kind, err)
		return err
	}
	// Read to the end, or the pooled connection is dropped: a refusal
	// carries a body.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Printf("notify: %s post refused: %s", kind, resp.Status)
		return fmt.Errorf("notify: %s post refused: %s", kind, resp.Status)
	}
	return nil
}

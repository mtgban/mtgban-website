// Package notify delivers one-line messages to Discord webhooks.
package notify

import (
	"bytes"
	"encoding/json"
	"log"

	"github.com/hashicorp/go-cleanhttp"
)

type payload struct {
	Username string `json:"username"`
	Content  string `json:"content"`
}

// Post delivers message to the Discord webhook at hook, shown under the kind
// username. When dev is set the message is prefixed with "[DEV] " so test
// traffic stays recognizable. Failures are logged and dropped — notifications
// are fire-and-forget.
func Post(hook, kind, message string, dev bool) {
	var p payload
	p.Username = kind
	if dev {
		p.Content = "[DEV] "
	}
	p.Content += message

	reqBody, err := json.Marshal(&p)
	if err != nil {
		log.Println(err)
		return
	}

	resp, err := cleanhttp.DefaultClient().Post(hook, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Println(err)
		return
	}
	resp.Body.Close()
}

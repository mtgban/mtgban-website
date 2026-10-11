package mailer

import (
	"errors"
	"fmt"
	"net/textproto"
)

// SendError is a provider's refusal; Permanent means retrying cannot help.
type SendError struct {
	Status    int
	Permanent bool
	Msg       string
}

func (e *SendError) Error() string { return fmt.Sprintf("mailer: %d %s", e.Status, e.Msg) }

// PermanentSendError reports a refusal the caller should treat like a bounce.
func PermanentSendError(err error) bool {
	var se *SendError
	return errors.As(err, &se) && se.Permanent
}

// Refused reports a send the provider definitely did not take: a
// permanent refusal, or a 4xx other than 409 or 429. A transport error, a
// timeout, a 5xx, a 429, or a 409 for a retry whose first attempt is still
// in flight may come with the mail accepted.
func Refused(err error) bool {
	var se *SendError
	if !errors.As(err, &se) {
		return false
	}
	return se.Permanent || se.Status >= 400 && se.Status < 500 && se.Status != 409 && se.Status != 429
}

// smtpError turns a 5xx reply into a permanent SendError, leaving others as they are.
func smtpError(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return &SendError{Status: te.Code, Permanent: true, Msg: te.Msg}
	}
	return err
}

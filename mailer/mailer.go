// Package mailer sends mail for the site and the API gateway: one
// interface, SMTP (STARTTLS or implicit TLS), Resend over HTTP, and a
// logging mailer for tests.
package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Message is one mail: a text body, an optional HTML twin and extra headers.
type Message struct {
	To, Subject, Text, HTML string
	// Headers are added after Date, for example List-Unsubscribe.
	Headers map[string]string
}

// Mailer sends one message and returns the provider's id, "" when it has none.
type Mailer interface {
	Send(ctx context.Context, m Message) (string, error)
}

// sendFallbackTimeout bounds Send when ctx carries no deadline; tests lower
// it to keep an unresponsive-server scenario fast.
var sendFallbackTimeout = 30 * time.Second

// SMTP sends through one server with PLAIN auth, over STARTTLS or implicit TLS.
type SMTP struct {
	Host string
	Port int
	// ImplicitTLS dials straight into TLS instead of upgrading with
	// STARTTLS; FromEnv sets it for port 465.
	ImplicitTLS bool
	// RootCAs overrides the system trust store for both TLS modes; nil
	// verifies against it, which is what production wants.
	RootCAs *x509.CertPool
	User    string
	Pass    string
	// From is the header value, for example "MTGBAN <no-reply@mtgban.com>";
	// the header keeps the display name but MAIL FROM uses the bare address.
	From string
}

// Send implements Mailer.
func (s *SMTP) Send(ctx context.Context, m Message) (string, error) {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return "", fmt.Errorf("mailer: from: %w", err)
	}
	rcpt, err := mail.ParseAddress(m.To)
	if err != nil {
		return "", fmt.Errorf("mailer: to: %w", err)
	}
	// One deadline bounds both the dial (handshake included, for
	// ImplicitTLS) and the SMTP exchange that follows it.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(sendFallbackTimeout)
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	tlsConfig := &tls.Config{ServerName: s.Host, RootCAs: s.RootCAs}
	var conn net.Conn
	if s.ImplicitTLS {
		dialer := tls.Dialer{Config: tlsConfig}
		conn, err = dialer.DialContext(dialCtx, "tcp", addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("mailer: dial: %w", err)
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("mailer: %w", err)
	}
	defer func() { _ = c.Close() }()
	if !s.ImplicitTLS {
		if err := c.StartTLS(tlsConfig); err != nil {
			return "", fmt.Errorf("mailer: starttls: %w", err)
		}
	}
	if s.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.User, s.Pass, s.Host)); err != nil {
			return "", fmt.Errorf("mailer: auth: %w", err)
		}
	}
	// A refused sender is this site's problem, never the recipient's: it stays
	// transient however permanent the server's code.
	err = c.Mail(from.Address)
	if err != nil {
		return "", fmt.Errorf("mailer: mail from: %w", err)
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return "", fmt.Errorf("mailer: rcpt: %w", smtpError(err))
	}
	w, err := c.Data()
	if err != nil {
		return "", fmt.Errorf("mailer: data: %w", err)
	}
	if _, err := w.Write(Multipart(from.String(), rcpt.Address, m)); err != nil {
		return "", fmt.Errorf("mailer: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("mailer: send: %w", smtpError(err))
	}
	// The server has queued the mail; a failed QUIT must not make the caller resend it.
	_ = c.Quit()
	return "", nil
}

// Multipart renders an RFC 5322 message with text and, when m.HTML is set, an HTML alternative.
func Multipart(from, to string, m Message) []byte {
	var b bytes.Buffer
	boundary := "ban-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n",
		from, to, mime.QEncoding.Encode("utf-8", m.Subject), time.Now().Format(time.RFC1123Z))
	for _, k := range slices.Sorted(maps.Keys(m.Headers)) {
		v := m.Headers[k]
		// A header carrying \r or \n could inject extra header lines.
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	part := func(ctype, body string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		qp := quotedprintable.NewWriter(&b)
		_, _ = qp.Write([]byte(body))
		_ = qp.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// Log writes mail to Out instead of sending it, for development and tests.
type Log struct {
	Out io.Writer
}

// logSeq numbers logged mails, so each gets its own id.
var logSeq atomic.Uint64

// Send implements Mailer; the id is unique per call, as a provider's would be.
func (l *Log) Send(_ context.Context, m Message) (string, error) {
	_, err := fmt.Fprintf(l.Out, "mail to %s: %s\n%s\n", m.To, m.Subject, m.Text)
	return fmt.Sprintf("log-%d-%d", time.Now().UnixNano(), logSeq.Add(1)), err
}

// FromEnv builds the SMTP mailer from MAIL_SMTP_HOST, MAIL_SMTP_PORT (587,
// implicit TLS on 465), MAIL_SMTP_USER, and MAIL_SMTP_PASS. No host: nil, nil, use Log.
func FromEnv(from string) (*SMTP, error) {
	host := os.Getenv("MAIL_SMTP_HOST")
	if host == "" {
		return nil, nil
	}
	port := 587
	if p := os.Getenv("MAIL_SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return nil, errors.New("MAIL_SMTP_PORT must be a port number")
		}
		port = n
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("mail.from: %w", err)
	}
	return &SMTP{
		Host:        host,
		Port:        port,
		ImplicitTLS: port == 465,
		User:        os.Getenv("MAIL_SMTP_USER"),
		Pass:        os.Getenv("MAIL_SMTP_PASS"),
		From:        from,
	}, nil
}

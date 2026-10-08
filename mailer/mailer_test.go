package mailer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMultipartHasBothPartsAndHeaders(t *testing.T) {
	m := Message{To: "ann@example.com", Subject: "Your link", Text: "plain body", HTML: "<p>html body</p>",
		Headers: map[string]string{"List-Unsubscribe": "<https://x/u?t=1>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}}
	msg := string(Multipart("MTGBAN <no-reply@mtgban.com>", "ann@example.com", m))
	for _, want := range []string{"From: MTGBAN <no-reply@mtgban.com>\r\n", "To: ann@example.com\r\n", "Subject: Your link\r\n",
		"List-Unsubscribe: <https://x/u?t=1>\r\n", "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
		"MIME-Version: 1.0\r\n", "Content-Type: text/plain; charset=utf-8", "plain body", "Content-Type: text/html; charset=utf-8", "<p>html body</p>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if i, j := strings.Index(msg, "List-Unsubscribe:"), strings.Index(msg, "MIME-Version"); i > j {
		t.Error("extra headers must come before MIME-Version")
	}
	textOnly := string(Multipart("a@b.c", "d@e.f", Message{Subject: "s", Text: "just text"}))
	if strings.Contains(textOnly, "text/html") {
		t.Error("empty html still produced an html part")
	}
}

func TestLogMailerWritesTheTextAndReturnsAnID(t *testing.T) {
	var buf bytes.Buffer
	l := &Log{Out: &buf}
	id, err := l.Send(context.Background(), Message{To: "ann@example.com", Subject: "Hi", Text: "body", HTML: "<p>x</p>"})
	if err != nil || !strings.HasPrefix(id, "log-") {
		t.Fatalf("id %q err %v", id, err)
	}
	if next, _ := l.Send(context.Background(), Message{To: "ann@example.com", Subject: "Hi", Text: "body"}); next == id {
		t.Fatalf("two sends share the id %q", id)
	}
	if got := buf.String(); !strings.Contains(got, "mail to ann@example.com: Hi\nbody\n") || strings.Contains(got, "<p>") {
		t.Errorf("log wrote %q", got)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("MAIL_SMTP_HOST", "")
	if m, err := FromEnv("MTGBAN <no-reply@mtgban.com>"); m != nil || err != nil {
		t.Errorf("unset host: %+v %v", m, err)
	}
	t.Setenv("MAIL_SMTP_HOST", "smtp.example.com")
	t.Setenv("MAIL_SMTP_PORT", "")
	t.Setenv("MAIL_SMTP_USER", "u")
	t.Setenv("MAIL_SMTP_PASS", "p")
	m, err := FromEnv("MTGBAN <no-reply@mtgban.com>")
	if err != nil || m.Port != 587 || m.ImplicitTLS || m.User != "u" || m.From != "MTGBAN <no-reply@mtgban.com>" {
		t.Errorf("%+v %v", m, err)
	}
	t.Setenv("MAIL_SMTP_PORT", "abc")
	if _, err := FromEnv("x <a@b.c>"); err == nil {
		t.Error("bad port accepted")
	}
	t.Setenv("MAIL_SMTP_PORT", "465")
	if _, err := FromEnv("not an address"); err == nil {
		t.Error("bad from accepted")
	}
	m, err = FromEnv("MTGBAN <no-reply@mtgban.com>")
	if err != nil || m.Port != 465 || !m.ImplicitTLS {
		t.Errorf("port 465 should select implicit TLS: %+v %v", m, err)
	}
}

// testCert returns a self-signed certificate for 127.0.0.1, valid for the
// test, and a pool trusting it the way a pinned test RootCAs would.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// serveOneSMTP speaks just enough SMTP on conn, for Send to complete, and
// sends the DATA body on msgs; starttls offers and honors STARTTLS, and
// replies answers QUIT, and MAIL FROM where it names one in place of 250.
func serveOneSMTP(t *testing.T, conn net.Conn, cert tls.Certificate, starttls bool, replies map[string]string, msgs chan<- string) {
	t.Helper()
	tp := textproto.NewConn(conn)
	defer tp.Close()
	_ = tp.PrintfLine("220 test.invalid ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			_ = tp.PrintfLine("250-test.invalid")
			if starttls {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case strings.HasPrefix(upper, "STARTTLS"):
			_ = tp.PrintfLine("220 go ahead")
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tlsConn.Handshake(); err != nil {
				t.Errorf("fake server: tls handshake: %v", err)
				return
			}
			conn = tlsConn
			tp = textproto.NewConn(conn)
		case strings.HasPrefix(upper, "AUTH"):
			_ = tp.PrintfLine("235 authenticated")
		case strings.HasPrefix(upper, "MAIL FROM"):
			reply := replies["MAIL FROM"]
			if reply == "" {
				reply = "250 OK"
			}
			_ = tp.PrintfLine("%s", reply)
		case strings.HasPrefix(upper, "RCPT TO"):
			_ = tp.PrintfLine("250 OK")
		case upper == "DATA":
			_ = tp.PrintfLine("354 go ahead")
			var body strings.Builder
			for {
				l, err := tp.ReadLine()
				if err != nil {
					return
				}
				if l == "." {
					break
				}
				body.WriteString(l)
				body.WriteString("\n")
			}
			msgs <- body.String()
			_ = tp.PrintfLine("250 queued")
		case upper == "QUIT":
			_ = tp.PrintfLine("%s", replies["QUIT"])
			return
		default:
			_ = tp.PrintfLine("500 unrecognized")
		}
	}
}

func hostPort(t *testing.T, addr net.Addr) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return host, n
}

func TestSendImplicitTLS(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	msgs := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveOneSMTP(t, conn, cert, false, map[string]string{"QUIT": "221 bye"}, msgs)
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, ImplicitTLS: true, RootCAs: pool, User: "u", Pass: "p", From: "MTGBAN <no-reply@mtgban.com>"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	id, err := s.Send(ctx, Message{To: "ann@example.com", Subject: "Your link", Text: "visit https://x/y"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Errorf("smtp returned id %q", id)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Send took %s, want well under the 5s deadline", elapsed)
	}
	select {
	case body := <-msgs:
		if !strings.Contains(body, "https://x/y") {
			t.Errorf("server received %q", body)
		}
	default:
		t.Fatal("server never received a message")
	}
}

func TestSendSTARTTLS(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	msgs := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveOneSMTP(t, conn, cert, true, map[string]string{"QUIT": "221 bye"}, msgs)
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, RootCAs: pool, User: "u", Pass: "p", From: "MTGBAN <no-reply@mtgban.com>"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	id, err := s.Send(ctx, Message{To: "ann@example.com", Subject: "Your link", Text: "visit https://x/y"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Errorf("smtp returned id %q", id)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Send took %s, want well under the 5s deadline", elapsed)
	}
	select {
	case body := <-msgs:
		if !strings.Contains(body, "https://x/y") {
			t.Errorf("server received %q", body)
		}
	default:
		t.Fatal("server never received a message")
	}
}

func TestSendSucceedsWhenQuitFailsAfterData(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	msgs := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveOneSMTP(t, conn, cert, false, map[string]string{"QUIT": "421 closing"}, msgs)
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, ImplicitTLS: true, RootCAs: pool, From: "MTGBAN <no-reply@mtgban.com>"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.Send(ctx, Message{To: "ann@example.com", Subject: "s", Text: "t"})
	if err != nil {
		t.Fatalf("Send = %v after the server queued the mail, want nil", err)
	}
	select {
	case <-msgs:
	default:
		t.Fatal("server never received a message")
	}
}

// TestSendSTARTTLSHangsAgainstImplicitTLSListener documents bug #41: a
// STARTTLS-only sender hangs to the deadline against a port 465 style server.
func TestSendSTARTTLSHangsAgainstImplicitTLSListener(t *testing.T) {
	cert, _ := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Write([]byte("220 test.invalid ESMTP\r\n"))
		_, _ = conn.Read(buf)
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, From: "MTGBAN <no-reply@mtgban.com>"}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = s.Send(ctx, Message{To: "ann@example.com", Subject: "subject", Text: "text"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected a STARTTLS sender to fail against an implicit TLS listener")
	}
	if elapsed < 2*time.Second || elapsed > 4*time.Second {
		t.Errorf("elapsed=%s, want it to run to the ~2s deadline", elapsed)
	}
	t.Logf("elapsed=%s err=%v", elapsed, err)
}

// TestSendBoundsDialWhenContextHasNoDeadline guards fix round 1: the
// implicit-TLS dial (handshake included) must be bounded by the computed
// fallback deadline even when ctx itself carries none, matching production
// callers (request contexts, the unbounded daily reminders context).
func TestSendBoundsDialWhenContextHasNoDeadline(t *testing.T) {
	orig := sendFallbackTimeout
	sendFallbackTimeout = 300 * time.Millisecond
	t.Cleanup(func() { sendFallbackTimeout = orig })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-t.Context().Done() // accept and never respond, until the test ends.
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, ImplicitTLS: true, From: "MTGBAN <no-reply@mtgban.com>"}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Send(context.Background(), Message{To: "ann@example.com", Subject: "subject", Text: "text"})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Send to fail against a server that never answers")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("elapsed=%s, want it bounded near the shortened fallback timeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return within the bounded guard window")
	}
}

func TestPermanentSendError(t *testing.T) {
	if PermanentSendError(nil) || PermanentSendError(errors.New("dial tcp: timeout")) {
		t.Error("plain errors are not permanent")
	}
	perm := fmt.Errorf("mailer: rcpt: %w", &SendError{Status: 550, Permanent: true, Msg: "no such user"})
	if !PermanentSendError(perm) {
		t.Error("a wrapped 5xx rejection is permanent")
	}
	if PermanentSendError(&SendError{Status: 429, Msg: "slow down"}) {
		t.Error("429 is not permanent")
	}
	if got := perm.Error(); !strings.Contains(got, "550") || !strings.Contains(got, "no such user") {
		t.Errorf("message %q", got)
	}
}

// A server refusing our sender says nothing about the recipient: the error
// stays transient, so a caller does not park the address for it.
func TestSendKeepsASenderRefusalTransient(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveOneSMTP(t, conn, cert, true, map[string]string{"QUIT": "221 bye", "MAIL FROM": "530 authentication required"}, make(chan string, 1))
	}()
	host, port := hostPort(t, ln.Addr())
	s := &SMTP{Host: host, Port: port, RootCAs: pool, From: "MTGBAN <no-reply@mtgban.com>"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = s.Send(ctx, Message{To: "ann@example.com", Subject: "s", Text: "t"})
	if err == nil || PermanentSendError(err) {
		t.Fatalf("err %v, permanent %v; want a transient error", err, PermanentSendError(err))
	}
}

package main

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"
)

// panicQuietWindow is how long after a posted panic report the panics that
// follow are only logged: a handler that panics on every request pings the
// channel once a window, not once a request.
const panicQuietWindow = 10 * time.Minute

// panicReportMu guards when the last panic report was posted and how many
// panics were only logged since. reportPanic holds it throughout, so each
// panic's lines stay together in the log.
var (
	panicReportMu   sync.Mutex
	lastPanicReport time.Time
	quietPanics     int
)

// reportPanic logs a recovered panic and posts it to the server webhook as
// three messages: what panicked (an @here), the top of the stack, and
// source, the line saying where it happened. For panicQuietWindow after a
// report posts, the panics that follow log the same three lines without
// posting them, and the next report says how many there were.
func reportPanic(errPanic any, source string) {
	panicReportMu.Lock()
	defer panicReportMu.Unlock()
	log.Println("panic occurred:", errPanic)

	// Restrict stack size to fit into discord message
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	if len(buf) > 1024 {
		buf = buf[:1024]
	}

	msg := fmt.Sprint(errPanic)
	if time.Since(lastPanicReport) < panicQuietWindow {
		quietPanics++
		log.Println(msg)
		log.Println(string(buf))
		log.Println(source)
		return
	}
	if quietPanics > 0 {
		msg += fmt.Sprintf(" (unposted panics since the last report: %d)", quietPanics)
	}
	lastPanicReport, quietPanics = time.Now(), 0
	ServerNotify("panic", msg, true)
	ServerNotify("panic", string(buf))
	ServerNotify("panic", source)
}

// recoverJob reports and recovers a panic that nothing else would recover,
// and that would otherwise end the process. Defer it directly, as the first
// statement of the function whose panics it should stop: a goroutine's, or
// one run of a long-lived loop. Deferred inside a closure instead, its
// recover returns nil and stops nothing.
func recoverJob(job string) {
	errPanic := recover()
	if errPanic != nil {
		reportPanic(errPanic, "source job: "+job)
	}
}

// recovered wraps fn to run under recoverJob, for code that is handed a
// job to run on a goroutine of its own, such as a cron schedule or a loop
// that runs one per signal.
func recovered(job string, fn func()) func() {
	return func() {
		defer recoverJob(job)
		fn()
	}
}

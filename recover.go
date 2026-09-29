package main

import (
	"cmp"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

// panicQuietWindow is how long after a posted panic report the panics that
// follow from the same place are only logged: a handler that panics on every
// request pings the channel once a window, not once a request.
const panicQuietWindow = 10 * time.Minute

// maxPostedStack is how much of a panic's stack its report posts, to fit in
// a Discord message. The log keeps all of it.
const maxPostedStack = 1024

// panicWindow is one panic site's quiet window: when its last report was
// posted, and how many of its panics were only logged since.
type panicWindow struct {
	posted time.Time
	quiet  int
}

// panicReportMu guards panicWindows, keyed by panicSite. reportPanic holds
// it throughout, so each panic's lines stay together in the log.
var (
	panicReportMu sync.Mutex
	panicWindows  = map[string]panicWindow{}
)

// reportPanic logs a recovered panic, its whole stack and source, the line
// saying where it happened, and posts them to the server webhook as three
// messages: what panicked (an @here), the top of the stack, and source. For
// panicQuietWindow after a report posts, the panics raised at the same place
// are only logged, and its next report says how many there were.
func reportPanic(errPanic any, source string) {
	buf := make([]byte, 1<<16)
	stack := buf[:runtime.Stack(buf, false)]
	site := cmp.Or(panicSite(), source)

	panicReportMu.Lock()
	defer panicReportMu.Unlock()
	log.Println("panic occurred:", errPanic)
	log.Println(string(stack))
	log.Println(source)

	// An expired window with no panic to count reads as no window at all, so
	// the map keeps only the sites that panicked lately.
	for key, window := range panicWindows {
		if window.quiet == 0 && time.Since(window.posted) >= panicQuietWindow {
			delete(panicWindows, key)
		}
	}
	window := panicWindows[site]
	if time.Since(window.posted) < panicQuietWindow {
		window.quiet++
		panicWindows[site] = window
		return
	}
	msg := fmt.Sprint(errPanic)
	if window.quiet > 0 {
		msg += fmt.Sprintf(" (unposted panics since the last report: %d)", window.quiet)
	}
	panicWindows[site] = panicWindow{posted: time.Now()}
	serverPost("panic", msg, true)
	serverPost("panic", string(stack[:min(len(stack), maxPostedStack)]), false)
	serverPost("panic", source, false)
}

// panicSite names the line that raised the panic being recovered: the first
// frame below runtime.gopanic that is not the runtime's own. It is "" when
// no panic is unwinding, as when reportPanic is called directly.
func panicSite() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	unwinding := false
	for {
		frame, more := frames.Next()
		if unwinding && !strings.HasPrefix(frame.Function, "runtime.") {
			return fmt.Sprintf("%s:%d", frame.File, frame.Line)
		}
		if frame.Function == "runtime.gopanic" {
			unwinding = true
		}
		if !more {
			return ""
		}
	}
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

// tracked is recovered for one of the site's background jobs: it also
// records each run, and a panic, in backgroundJobs under name.
func tracked(name string, fn func()) func() {
	return func() {
		finish := backgroundJobs.Start(name)
		defer func() {
			errPanic := recover()
			if errPanic != nil {
				reportPanic(errPanic, "source job: "+name)
			}
			finish(errPanic)
		}()
		fn()
	}
}

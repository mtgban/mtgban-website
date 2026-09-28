package main

import (
	"fmt"
	"log"
	"runtime"
)

// reportPanic logs a recovered panic and posts it to the server webhook as
// three messages: what panicked (an @here), the top of the stack, and
// source, the line saying where it happened.
func reportPanic(errPanic any, source string) {
	log.Println("panic occurred:", errPanic)

	// Restrict stack size to fit into discord message
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	if len(buf) > 1024 {
		buf = buf[:1024]
	}

	msg := fmt.Sprint(errPanic)
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

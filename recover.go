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

package dsreload

import (
	"io"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// Load builds a replacement without changing the installed datastore, then
// publishes it atomically. Failed loads leave the old backend in place. Each
// matcher operation captures one immutable backend; this does not pin entire
// HTTP requests or publish the website's derived caches as one transaction.
func Load(game string, reader io.Reader) error {
	backend, err := mtgmatcher.Open(game, reader)
	if err != nil {
		return err
	}
	mtgmatcher.SetGlobalDatastore(backend)
	return nil
}

package dsreload

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const publicationGame = "publication-test"

func init() {
	mtgmatcher.RegisterGame(publicationGame, func(reader io.Reader) (*mtgmatcher.Backend, error) {
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		id := string(data)
		if id != "first" && id != "second" {
			return nil, errors.New("invalid test datastore")
		}
		return &mtgmatcher.Backend{
			AllUUIDs:            []string{id},
			UUIDs:               map[string]*mtgmatcher.CardObject{id: {Card: mtgmatcher.Card{UUID: id}}},
			ExternalIdentifiers: map[string]map[string]string{mtgmatcher.IDSpaceTCGplayer: {"123": id}},
		}, nil
	})
}

func preservePublication(t *testing.T) {
	t.Helper()
	previous := mtgmatcher.GlobalDatastore()
	t.Cleanup(func() { mtgmatcher.SetGlobalDatastore(previous) })
	if err := Load(publicationGame, strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationWaitsForSuccessfulLoad(t *testing.T) {
	preservePublication(t)
	pinned := mtgmatcher.GlobalDatastore()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() { done <- Load(publicationGame, reader) }()
	if _, err := writer.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := mtgmatcher.GetUUID("first"); err != nil {
		t.Fatal("unfinished load replaced the backend:", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := mtgmatcher.GetUUID("second"); err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.GetUUID("first"); err != nil {
		t.Fatal("captured backend changed:", err)
	}
	if err := Load(publicationGame, strings.NewReader("invalid")); err == nil {
		t.Fatal("invalid load succeeded")
	}
	if _, err := mtgmatcher.GetUUID("second"); err != nil {
		t.Fatal("failed load replaced backend:", err)
	}
}

func TestPublicationConcurrentReaders(t *testing.T) {
	preservePublication(t)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Go(func() {
			for i := 0; i < 500; i++ {
				if worker == 0 {
					id := "first"
					if i%2 == 0 {
						id = "second"
					}
					if err := Load(publicationGame, strings.NewReader(id)); err != nil {
						t.Error(err)
					}
					continue
				}
				b := mtgmatcher.GlobalDatastore()
				ids := b.GetUUIDs()
				if len(ids) != 1 {
					t.Errorf("incomplete snapshot: %v", ids)
					continue
				}
				if _, err := b.GetUUID(ids[0]); err != nil {
					t.Errorf("mixed snapshot: %v", err)
				}
				id, err := mtgmatcher.MatchID("123")
				if err != nil || (id != "first" && id != "second") {
					t.Errorf("global lookup: %q, %v", id, err)
				}
			}
		})
	}
	wg.Wait()
}

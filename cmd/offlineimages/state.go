package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"

	"github.com/Backblaze/blazer/b2"
	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// isNotExist reports whether err means the object does not exist yet.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || b2.IsNotExist(err)
}

// loadBucketJSON decodes one JSON document; only a missing document is a
// first run, any other failure is fatal so mirror state cannot silently reset.
func loadBucketJSON(ctx context.Context, bucket simplecloud.Reader, base, name string, out any) error {
	reader, err := simplecloud.InitReader(ctx, bucket, imgmirror.JoinPath(base, name))
	if err != nil {
		if isNotExist(err) {
			log.Printf("%s missing, starting empty", name)
			return nil
		}
		return err
	}
	defer reader.Close()
	// B2 opens lazily, so a missing object surfaces here on first read.
	if err := json.NewDecoder(reader).Decode(out); err != nil {
		if isNotExist(err) {
			log.Printf("%s missing, starting empty", name)
			return nil
		}
		return err
	}
	return nil
}

func saveBucketJSON(ctx context.Context, bucket simplecloud.Writer, base, name string, value any) error {
	writer, err := simplecloud.InitWriter(ctx, bucket, imgmirror.JoinPath(base, name))
	if err != nil {
		return err
	}
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}

func loadState(ctx context.Context, bucket simplecloud.Reader, base string) (imgmirror.State, error) {
	state := imgmirror.State{}
	if err := loadBucketJSON(ctx, bucket, base, "mirror-state.json", &state); err != nil {
		return nil, err
	}
	return state, nil
}

func saveState(ctx context.Context, bucket simplecloud.Writer, base string, state imgmirror.State) error {
	return saveBucketJSON(ctx, bucket, base, "mirror-state.json", state)
}

func loadManifest(ctx context.Context, bucket simplecloud.Reader, base string) (imgmirror.Manifest, error) {
	manifest := imgmirror.Manifest{}
	if err := loadBucketJSON(ctx, bucket, base, "images-manifest.json", &manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func saveManifest(ctx context.Context, bucket simplecloud.Writer, base string, manifest imgmirror.Manifest) error {
	return saveBucketJSON(ctx, bucket, base, "images-manifest.json", manifest)
}

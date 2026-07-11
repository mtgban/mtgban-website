package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// loadBucketJSON decodes one JSON document; a missing document is a first run.
func loadBucketJSON(ctx context.Context, bucket simplecloud.Reader, base, name string, out any) error {
	reader, err := simplecloud.InitReader(ctx, bucket, imgmirror.JoinPath(base, name))
	if err != nil {
		log.Printf("%s unavailable, starting empty: %v", name, err)
		return nil
	}
	defer reader.Close()
	return json.NewDecoder(reader).Decode(out)
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

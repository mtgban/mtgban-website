package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// rebuildBundles rebuilds every stale per set zip and updates the images
// manifest, merging over sets outside this run's scope. Failures are per set:
// surviving sets still land in the manifest.
func rebuildBundles(ctx context.Context, bucket simplecloud.ReadWriter, base string, state imgmirror.State, want map[string]imgmirror.Card, manifest imgmirror.Manifest) error {
	setDigests := imgmirror.SetDigests(state, want)
	rebuild := imgmirror.BundlesToRebuild(manifest, setDigests)
	if len(rebuild) == 0 {
		log.Println("all bundles up to date")
		return nil
	}
	if manifest == nil {
		manifest = imgmirror.Manifest{}
	}

	var failed []string
	for _, code := range rebuild {
		info, err := rebuildOne(ctx, bucket, base, state, code, setDigests[code])
		if err != nil {
			log.Printf("bundle %s: %v", code, err)
			failed = append(failed, code)
			continue
		}
		manifest[code] = info
		log.Printf("bundle %s-%s.zip: %d images, %d bytes", code, info.Hash, info.Count, info.Bytes)
	}

	if err := saveManifest(ctx, bucket, base, manifest); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("bundle rebuild failed for %d of %d sets: %s", len(failed), len(rebuild), strings.Join(failed, ", "))
	}
	return nil
}

// rebuildOne builds and uploads one set's zip and returns its manifest entry.
func rebuildOne(ctx context.Context, bucket simplecloud.ReadWriter, base string, state imgmirror.State, code string, digests map[string]string) (imgmirror.ImageInfo, error) {
	entries := make([]imgmirror.BundleEntry, 0, len(digests))
	for uuid := range digests {
		name := state[uuid].EntryName(uuid)
		reader, err := simplecloud.InitReader(ctx, bucket, imgmirror.JoinPath(base, "images", name))
		if err != nil {
			return imgmirror.ImageInfo{}, err
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return imgmirror.ImageInfo{}, err
		}
		entries = append(entries, imgmirror.BundleEntry{Name: name, Data: data})
	}

	zipData, err := imgmirror.BuildBundle(entries)
	if err != nil {
		return imgmirror.ImageInfo{}, err
	}
	hash := imgmirror.BundleHash(digests)
	writer, err := simplecloud.InitWriter(ctx, bucket, imgmirror.JoinPath(base, "bundles", code+"-"+hash+".zip"))
	if err != nil {
		return imgmirror.ImageInfo{}, err
	}
	if _, err := writer.Write(zipData); err != nil {
		writer.Close()
		return imgmirror.ImageInfo{}, err
	}
	if err := writer.Close(); err != nil {
		return imgmirror.ImageInfo{}, err
	}
	return imgmirror.ImageInfo{Hash: hash, Count: len(entries), Bytes: int64(len(zipData))}, nil
}

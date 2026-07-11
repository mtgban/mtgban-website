package main

import (
	"context"
	"io"
	"log"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

// rebuildBundles rebuilds every stale per set zip and updates the images
// manifest, merging over sets outside this run's scope.
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

	for _, code := range rebuild {
		digests := setDigests[code]
		entries := make([]imgmirror.BundleEntry, 0, len(digests))
		for uuid := range digests {
			name := state[uuid].EntryName(uuid)
			reader, err := simplecloud.InitReader(ctx, bucket, imgmirror.JoinPath(base, "images", name))
			if err != nil {
				return err
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				return err
			}
			entries = append(entries, imgmirror.BundleEntry{Name: name, Data: data})
		}

		zipData, err := imgmirror.BuildBundle(entries)
		if err != nil {
			return err
		}
		hash := imgmirror.BundleHash(digests)
		writer, err := simplecloud.InitWriter(ctx, bucket, imgmirror.JoinPath(base, "bundles", code+"-"+hash+".zip"))
		if err != nil {
			return err
		}
		if _, err := writer.Write(zipData); err != nil {
			writer.Close()
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}

		manifest[code] = imgmirror.ImageInfo{Hash: hash, Count: len(entries), Bytes: int64(len(zipData))}
		log.Printf("bundle %s-%s.zip: %d images, %d bytes", code, hash, len(entries), len(zipData))
	}

	return saveManifest(ctx, bucket, base, manifest)
}

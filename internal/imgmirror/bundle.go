package imgmirror

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/mtgban/simplecloud"
)

// rebuildBundles rebuilds every stale per set zip and updates the images
// manifest, merging over sets outside this run's scope. Failures are per set:
// surviving sets still land in the manifest.
func rebuildBundles(ctx context.Context, bucket simplecloud.ReadWriter, base string, state State, want map[string]Card, manifest Manifest) (int, error) {
	setDigests := SetDigests(state, want)
	rebuild := BundlesToRebuild(manifest, setDigests)
	if len(rebuild) == 0 {
		log.Println("all bundles up to date")
		return 0, nil
	}
	if manifest == nil {
		manifest = Manifest{}
	}

	rebuilt := 0
	var failed []string
	for _, code := range rebuild {
		info, err := rebuildOne(ctx, bucket, base, state, code, setDigests[code])
		if err != nil {
			log.Printf("bundle %s: %v", code, err)
			failed = append(failed, code)
			continue
		}
		manifest[code] = info
		rebuilt++
		log.Printf("bundle %s-%s.zip: %d images, %d bytes", code, info.Hash, info.Count, info.Bytes)
	}

	if err := saveManifest(ctx, bucket, base, manifest); err != nil {
		return rebuilt, err
	}
	if len(failed) > 0 {
		return rebuilt, fmt.Errorf("bundle rebuild failed for %d of %d sets: %s", len(failed), len(rebuild), strings.Join(failed, ", "))
	}
	return rebuilt, nil
}

// rebuildOne builds and uploads one set's zip and returns its manifest entry.
func rebuildOne(ctx context.Context, bucket simplecloud.ReadWriter, base string, state State, code string, digests map[string]string) (ImageInfo, error) {
	entries := make([]BundleEntry, 0, len(digests))
	for uuid := range digests {
		name := state[uuid].EntryName(uuid)
		reader, err := simplecloud.InitReader(ctx, bucket, JoinPath(base, "images", name))
		if err != nil {
			return ImageInfo{}, err
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return ImageInfo{}, err
		}
		entries = append(entries, BundleEntry{Name: name, Data: data})
	}

	zipData, err := BuildBundle(entries)
	if err != nil {
		return ImageInfo{}, err
	}
	hash := BundleHash(digests)
	writer, err := simplecloud.InitWriter(ctx, bucket, JoinPath(base, "bundles", code+"-"+hash+".zip"))
	if err != nil {
		return ImageInfo{}, err
	}
	if _, err := writer.Write(zipData); err != nil {
		writer.Close()
		return ImageInfo{}, err
	}
	if err := writer.Close(); err != nil {
		return ImageInfo{}, err
	}
	return ImageInfo{Hash: hash, Count: len(entries), Bytes: int64(len(zipData))}, nil
}

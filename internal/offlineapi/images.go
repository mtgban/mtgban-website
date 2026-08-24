package offlineapi

import (
	"context"
	"log"
)

// refreshImagesManifest reloads the worker-written images manifest. It is the
// only thing this server does with the image tree: the bytes themselves are
// read by clients straight from the bucket, authorized by serveBucketAuth.
func (s *Service) refreshImagesManifest() {
	if !s.deps.ImagesPathConfigured() {
		return
	}
	if err := s.imagesStore.Load(context.Background()); err != nil {
		log.Println("offline: images manifest load failed:", err)
	}
}

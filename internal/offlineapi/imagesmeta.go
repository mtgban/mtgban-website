package offlineapi

import (
	"net/url"
	"path"
)

// ImageInfo is one set's entry in images-manifest.json.
type ImageInfo struct {
	Hash  string `json:"h"`
	Count int    `json:"n"`
	Bytes int64  `json:"b"`
}

// ImagesManifest is the images-manifest.json document, keyed by set code.
type ImagesManifest map[string]ImageInfo

// JoinBucketPath appends elements to a bucket base path, preserving the
// scheme and host of remote bases. One letter schemes are Windows drive paths.
func JoinBucketPath(base string, elems ...string) string {
	return joinBucketPath(base, elems...)
}

func joinBucketPath(base string, elems ...string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || len(u.Scheme) == 1 {
		return path.Join(append([]string{base}, elems...)...)
	}
	u.Path = path.Join(append([]string{u.Path}, elems...)...)
	return u.String()
}

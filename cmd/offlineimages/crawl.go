package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/mtgban/mtgban-website/internal/imgmirror"
	"github.com/mtgban/simplecloud"
)

const (
	fetchUserAgent = "mtgban-offline-mirror/1.0 (+https://www.mtgban.com)"
	fetchRetries   = 6
	stateSaveEvery = 200
	// 100ms spacing per domain keeps every source at or under 10 req/s.
	requestInterval = 100 * time.Millisecond
)

type crawler struct {
	bucket  simplecloud.ReadWriter
	base    string
	client  *http.Client
	limit   *imgmirror.Limiter
	backoff func(int) time.Duration
	cwebp   string

	mu       sync.Mutex
	saveMu   sync.Mutex // serializes saveState writes across concurrent domains
	state    imgmirror.State
	done     int
	failures int
	warnOnce sync.Once
}

func newCrawler(bucket simplecloud.ReadWriter, base string, state imgmirror.State) *crawler {
	cwebp, err := exec.LookPath("cwebp")
	if err != nil {
		cwebp = ""
	}
	return &crawler{
		bucket:  bucket,
		base:    base,
		client:  &http.Client{Timeout: 60 * time.Second},
		limit:   &imgmirror.Limiter{Interval: requestInterval},
		backoff: imgmirror.Backoff,
		cwebp:   cwebp,
		state:   state,
	}
}

// fetchAll downloads every queued image, one goroutine per source domain,
// so each domain sees sequential rate limited traffic.
func (c *crawler) fetchAll(ctx context.Context, uuids []string, want map[string]imgmirror.Card) error {
	queues := map[string][]string{}
	for _, uuid := range uuids {
		u, err := url.Parse(want[uuid].URL)
		if err != nil {
			log.Printf("%s: bad image URL %q", uuid, want[uuid].URL)
			c.mu.Lock()
			c.failures++
			c.mu.Unlock()
			continue
		}
		queues[u.Host] = append(queues[u.Host], uuid)
	}

	var wg sync.WaitGroup
	for domain, queue := range queues {
		wg.Add(1)
		go func(domain string, queue []string) {
			defer wg.Done()
			for _, uuid := range queue {
				if err := c.fetchOne(ctx, domain, uuid, want[uuid]); err != nil {
					log.Printf("%s: %v", uuid, err)
					c.mu.Lock()
					c.failures++
					c.mu.Unlock()
				}
			}
		}(domain, queue)
	}
	wg.Wait()

	if err := c.saveStateSnapshot(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	failures := c.failures
	c.mu.Unlock()
	log.Printf("fetched %d images, %d failures", c.done, failures)
	if failures > 0 {
		return fmt.Errorf("%d fetches failed", failures)
	}
	return nil
}

func (c *crawler) fetchOne(ctx context.Context, domain, uuid string, card imgmirror.Card) error {
	data, err := c.download(ctx, domain, card.URL)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	stored, ext := data, "jpg"
	if webp, err := c.transcode(data); err != nil {
		c.warnOnce.Do(func() {
			log.Println("cwebp unavailable or failing, storing original JPEGs:", err)
		})
	} else {
		stored, ext = webp, "webp"
	}

	objPath := imgmirror.JoinPath(c.base, "images", uuid+"."+ext)
	writer, err := simplecloud.InitWriter(ctx, c.bucket, objPath)
	if err != nil {
		return err
	}
	if _, err := writer.Write(stored); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	entry := imgmirror.StateEntry{
		Digest:    digest,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Source:    card.URL,
	}
	if ext == "jpg" {
		entry.Ext = "jpg"
	}

	c.mu.Lock()
	c.state[uuid] = entry
	c.done++
	save := c.done%stateSaveEvery == 0
	c.mu.Unlock()

	// Periodic saves keep an interrupted crawl resumable.
	if save {
		if err := c.saveStateSnapshot(ctx); err != nil {
			log.Println("state save failed:", err)
		}
	}
	return nil
}

// download GETs the image with per domain spacing and backoff on 429/5xx.
func (c *crawler) download(ctx context.Context, domain, srcURL string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		time.Sleep(c.limit.Reserve(domain, time.Now()))

		req, err := http.NewRequestWithContext(ctx, "GET", srcURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", fetchUserAgent)

		resp, err := c.client.Do(req)
		if err != nil {
			if attempt >= fetchRetries {
				return nil, err
			}
			time.Sleep(c.backoff(attempt))
			continue
		}

		switch {
		case resp.StatusCode == http.StatusOK:
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			return data, err
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			resp.Body.Close()
			if attempt >= fetchRetries {
				return nil, fmt.Errorf("giving up after %d attempts: HTTP %d", attempt+1, resp.StatusCode)
			}
			delay := c.backoff(attempt)
			if s := resp.Header.Get("Retry-After"); s != "" {
				if secs, err := strconv.Atoi(s); err == nil {
					ra := time.Duration(secs) * time.Second
					if ra > 5*time.Minute {
						ra = 5 * time.Minute
					}
					if ra > delay {
						delay = ra
					}
				}
			}
			time.Sleep(delay)
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
}

// transcode shells out to cwebp -q 80 via temp files.
func (c *crawler) transcode(jpeg []byte) ([]byte, error) {
	if c.cwebp == "" {
		return nil, fmt.Errorf("cwebp not on PATH")
	}
	in, err := os.CreateTemp("", "mirror-*.jpg")
	if err != nil {
		return nil, err
	}
	defer os.Remove(in.Name())
	if _, err := in.Write(jpeg); err != nil {
		in.Close()
		return nil, err
	}
	in.Close()

	outName := in.Name() + ".webp"
	defer os.Remove(outName)
	cmd := exec.Command(c.cwebp, "-quiet", "-q", "80", in.Name(), "-o", outName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cwebp: %v: %s", err, out)
	}
	return os.ReadFile(outName)
}

func (c *crawler) saveStateSnapshot(ctx context.Context) error {
	c.mu.Lock()
	snapshot := make(imgmirror.State, len(c.state))
	for k, v := range c.state {
		snapshot[k] = v
	}
	c.mu.Unlock()
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	return saveState(ctx, c.bucket, c.base, snapshot)
}

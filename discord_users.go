package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"golang.org/x/sync/singleflight"
)

// discordLookup asks Discord for a user through the bot; a seam for tests.
var discordLookup = func(ctx context.Context, id string) (*discordgo.User, error) {
	if dg == nil {
		return nil, errors.New("discord session not connected")
	}
	// discordgo sleeps on a rate limit without looking at ctx, so never retry.
	return dg.User(id, discordgo.WithContext(ctx), discordgo.WithRetryOnRatelimit(false))
}

const (
	discordHandleTTL = time.Hour
	discordLookupMax = 10 * time.Second
	// discordHandleCap bounds the cache; past it the map starts over.
	discordHandleCap = 1000
)

type cachedHandle struct {
	handle string
	until  time.Time
}

var discordHandles = struct {
	sync.Mutex
	m map[string]cachedHandle
}{m: map[string]cachedHandle{}}

// discordFlight coalesces concurrent lookups of one id.
var discordFlight singleflight.Group

// discordHandle names a Discord user through the bot, cached for an hour;
// "" with an error when there is no session, the lookup fails or ctx ends.
func discordHandle(ctx context.Context, id string) (string, error) {
	now := time.Now()
	discordHandles.Lock()
	c, found := discordHandles.m[id]
	discordHandles.Unlock()
	if found && now.Before(c.until) {
		return c.handle, nil
	}
	type result struct {
		handle string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		defer recoverJob("discord-handle")
		v, err, _ := discordFlight.Do(id, func() (any, error) {
			// Shared by callers, so it outlives any one of their contexts.
			lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discordLookupMax)
			defer cancel()
			u, err := discordLookup(lctx, id)
			if err != nil {
				return "", err
			}
			handle := "@" + u.String()
			discordHandles.Lock()
			if len(discordHandles.m) >= discordHandleCap {
				discordHandles.m = map[string]cachedHandle{}
			}
			discordHandles.m[id] = cachedHandle{handle: handle, until: time.Now().Add(discordHandleTTL)}
			discordHandles.Unlock()
			return handle, nil
		})
		handle, ok := v.(string)
		if !ok && err == nil {
			err = errors.New("discord lookup returned no handle")
		}
		done <- result{handle, err}
	}()
	select {
	case r := <-done:
		return r.handle, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// resetDiscordHandles empties the cache, for tests.
func resetDiscordHandles() {
	discordHandles.Lock()
	discordHandles.m = map[string]cachedHandle{}
	discordHandles.Unlock()
}

package main

import (
	"context"
	"log"
	"time"

	"github.com/lib/pq"
)

// Deployments that split the access table and the grant list into their own
// bucket files can share those files - the grants especially are one list
// across the magic and lorcana sites. A save on one deployment then has to
// reach the others, and the shared price database already connects them all:
// the saver sends a Postgres NOTIFY on the changed file's channel, and every
// peer listening there re-reads that file - just that file, since the two
// change independently.

// The NOTIFY channels, one per shared file. The payload is the sender's
// instance name, so the sender can recognize and skip its own notification.
const (
	aclReloadChannel    = "acl_reload"
	grantsReloadChannel = "grants_reload"
)

// notifyAccessReload tells the peer deployments to re-read the file behind
// the channel. Best effort: the save it follows already succeeded, so a
// failure here only delays the peers until their next reload and is just
// logged.
func notifyAccessReload(ctx context.Context, channel string) {
	if PricesArchiveDB == nil {
		return
	}
	err := PricesArchiveDB.Notify(ctx, channel, Config.InstanceName)
	if err != nil {
		log.Printf("access reload: notify %s failed: %v", channel, err)
	}
}

// skipAccessNotification reports whether a notification needs no reload:
// only the sender's own, and only when instance names can actually tell the
// deployments apart. A nil notification is lib/pq reporting a reconnect -
// NOTIFY has no queue, so anything sent while disconnected is gone and the
// only safe answer is to reload.
func skipAccessNotification(n *pq.Notification, instanceName string) bool {
	if n == nil {
		return false
	}
	return n.Extra != "" && n.Extra == instanceName
}

// startAccessReloadListener subscribes to the reload channel of every value
// this deployment reads from its own file and keeps that value in sync with
// the peers' saves. It needs the shared database to listen on, and there is
// nothing to subscribe to for a value still carried inline: a peer cannot
// write this deployment's config.
func startAccessReloadListener() {
	if Config.SQLConfig == nil {
		return
	}
	reloads := map[string]func(context.Context) error{}
	if Config.ACLPath != "" {
		reloads[aclReloadChannel] = Access.ReloadTable
	}
	if Config.PatreonGrantsPath != "" {
		reloads[grantsReloadChannel] = Access.ReloadGrants
	}
	if len(reloads) == 0 {
		return
	}

	// The listener holds its own connection outside PricesArchiveDB's pool:
	// LISTEN is per-session, and lib/pq reconnects and re-subscribes this one
	// on its own (backing off between the two durations below).
	listener := pq.NewListener(Config.SQLConfig.DSN(), 10*time.Second, time.Minute,
		func(event pq.ListenerEventType, err error) {
			if err != nil {
				log.Println("access reload: listener:", err)
			}
		})
	for channel := range reloads {
		err := listener.Listen(channel)
		if err != nil {
			log.Println("access reload: listen failed, peer saves won't be picked up:", err)
			listener.Close()
			return
		}
	}

	go func() {
		for {
			select {
			case n := <-listener.Notify:
				if skipAccessNotification(n, Config.InstanceName) {
					continue
				}
				if n == nil {
					// Reconnected: anything notified in between is lost, so
					// refresh every subscribed value.
					for channel, reload := range reloads {
						runAccessReload(channel, "reconnect", reload)
					}
					continue
				}
				reload := reloads[n.Channel]
				if reload == nil {
					continue
				}
				source := "notify"
				if n.Extra != "" {
					source = "notify from " + n.Extra
				}
				runAccessReload(n.Channel, source, reload)
			case <-time.After(90 * time.Second):
				// A dead connection surfaces nothing on the Notify channel;
				// pinging is what makes the listener notice and reconnect.
				go listener.Ping()
			}
		}
	}()
	log.Println("access reload: listening for", len(reloads), "channels")
}

func runAccessReload(channel, source string, reload func(context.Context) error) {
	err := reload(context.Background())
	if err != nil {
		log.Printf("access reload: %s (%s): %v", channel, source, err)
		return
	}
	log.Printf("access reload: %s (%s): done", channel, source)
}

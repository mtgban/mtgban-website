package main

import (
	"context"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/mtgban/mtgban-website/internal/access"
	"github.com/mtgban/mtgban-website/userstate"
)

// Deployments that split the access table, the grant list, the affiliate
// data, the chart datasets and the infrastructure settings into their own
// bucket files can share those
// files - the grants and
// the affiliates are one value across the magic and lorcana sites. A save on
// one deployment then has to
// reach the others, and the shared price database already connects them all:
// the saver sends a Postgres NOTIFY on the changed file's channel, and every
// peer listening there re-reads that file - just that file, since the two
// change independently.

// The NOTIFY channels, one per shared file. The payload is the sender's
// instance name, so the sender can recognize and skip its own notification.
const (
	aclReloadChannel            = "acl_reload"
	grantsReloadChannel         = "grants_reload"
	affiliatesReloadChannel     = "affiliates_reload"
	datasetsReloadChannel       = "datasets_reload"
	infrastructureReloadChannel = "infrastructure_reload"
)

// patreonPokeChannel carries the webhook's pokes (auth_webhook.go) to the
// peers. It is not a file to re-read: the payload is the email hash of the
// reader to poke, then a space and the sender's instance name, by which the
// sender skips its own.
const patreonPokeChannel = "patreon_poke"

// notifyAccessReload tells the peer deployments to re-read the file behind
// the channel. Best effort: the save it follows already succeeded, so a
// failure here only delays the peers until their next reload and is just
// logged.
func notifyAccessReload(ctx context.Context, channel string) {
	if PricesArchiveDB == nil {
		return
	}
	err := PricesArchiveDB.Notify(ctx, channel, Config().InstanceName)
	if err != nil {
		log.Printf("access reload: notify %s failed: %v", channel, err)
	}
}

// notifyPoke tells the peer deployments to poke the reader with the given
// email hash. Best effort: the sender's own set already has the poke, so a
// failure here only leaves the peers to the age window and is just logged.
func notifyPoke(ctx context.Context, hash string) {
	if PricesArchiveDB == nil {
		return
	}
	err := PricesArchiveDB.Notify(ctx, patreonPokeChannel, hash+" "+Config().InstanceName)
	if err != nil {
		log.Printf("patreon poke: notify failed: %v", err)
	}
}

// reloadACL re-reads the access table. A table that differs from the one it
// replaces stamps the poke set, so every signature issued before now renews on
// its next request; one that does not, as when the listener reconnects and
// re-reads every value, stamps nothing.
func reloadACL(ctx context.Context) error {
	before := ACL()
	err := Access.ReloadTable(ctx)
	if err != nil {
		return err
	}
	stampACLIfChanged(before)
	return nil
}

// stampACLIfChanged stamps the poke set when the live access table is not
// before, the one it replaced.
func stampACLIfChanged(before access.Table) {
	if !before.Equal(ACL()) {
		Pokes.StampACL(time.Now())
	}
}

// reloadGrants re-reads the grant list and pokes the grantees whose grant
// changed.
func reloadGrants(ctx context.Context) error {
	before := PatreonGrants()
	err := Access.ReloadGrants(ctx)
	if err != nil {
		return err
	}
	pokeGrantees(before, PatreonGrants())
	return nil
}

// pokeGrantees pokes and stamps each reader whose grant differs between
// before and after, so their next request renews onto the tier and overrides
// it now gives, or is re-signed with them where Patreon cannot renew it.
func pokeGrantees(before, after []PatreonGrant) {
	for _, email := range access.GrantsChanged(before, after) {
		hash := userstate.HashEmail(email)
		Pokes.Poke(hash, time.Now(), pokeWindow())
		Pokes.StampGrant(hash, time.Now(), DefaultSignatureDuration)
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

// takePoke pokes the reader a patreon_poke notification names, and says
// whether n was one. A nil notification is lib/pq reporting a reconnect, which
// pokes nothing: the age window catches a poke the dropped connection missed.
// The sender's own notification pokes nothing either, since the delivery
// poked its set already and a later poke would renew once more a reader who
// renewed in between; nor does a payload that names no email hash.
func takePoke(n *pq.Notification) bool {
	if n == nil || n.Channel != patreonPokeChannel {
		return false
	}
	hash, from, _ := strings.Cut(n.Extra, " ")
	if from != "" && from == Config().InstanceName {
		return true
	}
	if emailHashPattern.MatchString(hash) {
		Pokes.Poke(hash, time.Now(), pokeWindow())
	}
	return true
}

// emailHashPattern is what userstate.HashEmail returns: SHA-256 in lower-case
// hex.
var emailHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// startAccessReloadListener subscribes to the reload channel of every value
// this deployment reads from its own file and keeps that value in sync with
// the peers' saves, and to the channel the webhook's pokes arrive on. It needs
// the shared database to listen on, and skips any value with no path
// configured: there is nothing to reload.
func startAccessReloadListener() {
	sqlConfig := Infrastructure().SQLConfig
	if sqlConfig == nil {
		return
	}
	reloads := map[string]func(context.Context) error{}
	if Config().ACLPath != "" {
		reloads[aclReloadChannel] = reloadACL
	}
	if Config().PatreonGrantsPath != "" {
		reloads[grantsReloadChannel] = reloadGrants
	}
	if Config().AffiliatesPath != "" {
		reloads[affiliatesReloadChannel] = loadAffiliates
	}
	if Config().DatasetsPath != "" {
		reloads[datasetsReloadChannel] = loadDatasets
	}
	if Config().InfrastructurePath != "" {
		reloads[infrastructureReloadChannel] = loadInfrastructure
	}

	// The listener holds its own connection outside PricesArchiveDB's pool:
	// LISTEN is per-session, and lib/pq reconnects and re-subscribes this one
	// on its own (backing off between the two durations below).
	listener := pq.NewListener(sqlConfig.SessionDSN(), 10*time.Second, time.Minute,
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
	err := listener.Listen(patreonPokeChannel)
	if err != nil {
		log.Println("access reload: listen failed, Patreon pokes won't be picked up:", err)
		listener.Close()
		return
	}

	go func() {
		for {
			select {
			case n := <-listener.Notify:
				if takePoke(n) {
					continue
				}
				if skipAccessNotification(n, Config().InstanceName) {
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
	log.Println("access reload: listening for", len(reloads)+1, "channels")
}

func runAccessReload(channel, source string, reload func(context.Context) error) {
	// This runs on the listener's goroutine, which has to outlive a reload
	// that panics to serve the next notification.
	defer recoverJob("access reload " + channel)

	err := reload(context.Background())
	if err != nil {
		log.Printf("access reload: %s (%s): %v", channel, source, err)
		return
	}
	log.Printf("access reload: %s (%s): done", channel, source)
}

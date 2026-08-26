#!/usr/bin/env bash
#
# Which ports, paths and names each site runs under.
#
# Sourced by deploy.sh and bootstrap.sh, so a droplet hosting several games has
# one place that says who owns what, and adding a game is one line below.
#
# Magic predates the game dimension and keeps the names its droplet was set up
# with — mtgban-website-<port>, the bare mtgban@ unit, upstream mtgban — so
# nothing about that host has to change for any of this to work.

# game_ports <game> prints the blue/green port pair, or fails for a game with
# no allocation. The pairs are fixed rather than derived so that a game's ports
# never move when another is added: a port is baked into an nginx upstream and
# a systemd instance name on every host already running it.
game_ports() {
    case "$1" in
        magic)         echo "8081 8082" ;;
        beta)          echo "8083 8084" ;;
        yugioh)        echo "8091 8092" ;;
        lorcana)       echo "8093 8094" ;;
        onepiece)      echo "8095 8096" ;;
        riftbound)     echo "8097 8098" ;;
        fleshandblood) echo "8099 8100" ;;
        *)             return 1 ;;
    esac
}

# game_env <game> <src-dir> sets every name the two scripts key off. Each one
# keeps a value it already has, so a caller can override any single name
# without restating the rest — which is also how a host that was set up by
# hand, before this file existed, stays deployable.
game_env() {
    local game=$1 src=$2 ports
    if ! ports=$(game_ports "$game"); then
        echo "!! unknown game: $game — add its port pair to deploy/games.sh" >&2
        return 1
    fi
    PORT_BLUE=${PORT_BLUE:-${ports%% *}}
    PORT_GREEN=${PORT_GREEN:-${ports##* }}

    if [ "$game" = magic ]; then
        CO_PREFIX=${CO_PREFIX:-${src}/mtgban-website-}
        UNIT=${UNIT:-mtgban}
        UPSTREAM_NAME=${UPSTREAM_NAME:-mtgban}
        UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/conf.d/mtgban_upstream.conf}
    else
        CO_PREFIX=${CO_PREFIX:-${src}/mtgban-${game}-}
        UNIT=${UNIT:-mtgban-${game}}
        UPSTREAM_NAME=${UPSTREAM_NAME:-mtgban_${game}}
        UPSTREAM_CONF=${UPSTREAM_CONF:-/etc/nginx/conf.d/mtgban_${game}_upstream.conf}
    fi

    # The config each instance is started with. Every game reads its own from
    # the config bucket, named after the game, so the only thing a droplet
    # holds is the key to that bucket.
    CFG=${CFG:-b2://mtgban-config/${game}/config.json}
}

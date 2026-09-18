#!/bin/sh
#
# node-metering-off.sh -- reverse of Job 4 (metering) in node-daily-maintenance.sh.
#
# Installed to /usr/local/sbin/node-metering-off.sh on every metered node so
# ops can revert by hand without the maintenance script. Also what Job 4 runs
# itself when a node is metered but no longer in METERING_IPS (git revert of
# the canary list == fleet-wide rollback within one maintenance cycle).
#
# Steps, in an order that can never leave the freeze trap behind (official
# binary + experimental.v2ray_api block => `sing-box check` fails forever and
# the 10s monitor stops applying user changes):
#   1. touch the hold file so Job 4 stays out tomorrow (rm it to re-enable)
#   2. put the official package binary back: move our diverted build aside
#      (kept, not deleted), dpkg-divert --remove --rename restores .distrib
#   3. strip experimental.v2ray_api from the config
#   4. restore the pre-metering sing-monitor.sh from the newest .bak-*
#   5. sing-box check, then restart
# Nothing is deleted: the v2ray_api binary, sing-stats, pending.json and the
# monitor backups all stay on disk.
#
# Usage: sudo /usr/local/sbin/node-metering-off.sh
export PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH

CONFIG="/etc/sing-box/config.json"
MONITOR="/usr/local/bin/sing-monitor.sh"
SB_BIN="/usr/bin/sing-box"
SB_DISTRIB="/usr/bin/sing-box.distrib"
SB_KEEP="/usr/local/lib/sing-box-v2rayapi/sing-box"
HOLD="/etc/sing-box/metering.off"
STATE="/var/lib/sing-monitor/metering.release"

log() { printf '[%s] metering-off: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1"; }

# 1. hold
touch "$HOLD" 2>/dev/null && log "hold file $HOLD written (rm it to let Job 4 re-enable)"

# 1b. [added v3 2026-09-05] harvest before anything below changes what is
# running or what the monitor can do: the per-user counters live in the
# metered sing-box's memory (gone at step 5's restart) and only the metering
# edition of the monitor (replaced at step 4) knows how to read them. Same
# retry as Job 4's metering_harvest, since the 10s timer may hold the lock.
if [ -x "$MONITOR" ] && grep -q '^harvest_stats()' "$MONITOR" 2>/dev/null; then
    n=0
    while [ "$n" -lt 3 ]; do
        "$MONITOR" harvest >/dev/null 2>&1 && { log "counters harvested into pending.json"; break; }
        n=$((n+1)); sleep 2
    done
    [ "$n" -lt 3 ] || log "harvest did not succeed (lock busy?), continuing anyway"
fi

# 2. binary
if dpkg-divert --list "$SB_BIN" 2>/dev/null | grep -q "$SB_DISTRIB"; then
    mkdir -p "$(dirname "$SB_KEEP")" 2>/dev/null
    if [ -f "$SB_BIN" ]; then
        mv -f "$SB_BIN" "$SB_KEEP" 2>/dev/null || rm -f "$SB_BIN"
    fi
    if dpkg-divert --remove --rename --divert "$SB_DISTRIB" "$SB_BIN"; then
        log "diversion removed, official binary back at $SB_BIN"
    else
        log "dpkg-divert --remove failed"
    fi
fi
if [ ! -x "$SB_BIN" ]; then
    log "$SB_BIN missing after un-divert, reinstalling the package"
    DEBIAN_FRONTEND=noninteractive apt-get -qq install --reinstall -o Dpkg::Options::="--force-confold" -y sing-box
fi

# 3. config: strip the block; drop an emptied experimental object
if [ -f "$CONFIG" ] && command -v jq >/dev/null 2>&1 \
   && jq -e '.experimental.v2ray_api != null' "$CONFIG" >/dev/null 2>&1; then
    cp "$CONFIG" "$CONFIG.metering-off-backup"
    NEW=$(jq 'del(.experimental.v2ray_api) | if .experimental == {} then del(.experimental) else . end' "$CONFIG")
    if [ -n "$NEW" ]; then
        printf '%s' "$NEW" > "$CONFIG.new" && [ -s "$CONFIG.new" ] && mv "$CONFIG.new" "$CONFIG" \
            && log "experimental.v2ray_api stripped from $CONFIG"
    fi
    rm -f "$CONFIG.new"
fi

# 4. monitor script
BAK=$(ls -1t "$MONITOR".bak-* 2>/dev/null | head -n1)
if [ -n "$BAK" ] && [ -s "$BAK" ]; then
    cp "$MONITOR" "$MONITOR.metering-off-backup" 2>/dev/null
    cp "$BAK" "$MONITOR" && chmod +x "$MONITOR" && log "restored $MONITOR from $BAK"
else
    log "no $MONITOR.bak-* found, leaving the current monitor in place"
fi

rm -f "$STATE"

# 5. check + restart
if sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    systemctl restart sing-box && log "sing-box restarted on the official binary"
else
    log "sing-box check FAILED on the stripped config, NOT restarting; inspect $CONFIG"
    exit 1
fi
echo metering-removed

#!/bin/dash
#
# Daily maintenance for a sing-box proxy node.
#
# Every node runs this as root once a day via the update-sbox systemd timer,
# which was installed by the provisioning script and points at a bit.ly link.
# That link used to resolve to a repository outside this organisation, so
# whoever controlled it controlled every node. It now resolves here.
#
# Three jobs:
#   1. Keep sing-box current from the upstream apt repo (what the old script did).
#   2. Apply per-client-IP fair-share shaping (anti-abuse). [added v2 2026-08]
#   3. Re-sync the ACME certificate credential from the API.
#   4. Per-user byte metering (canary rollout; runs BEFORE 1). [added v3 2026-09-05]
#   5. Poller curl timeouts (runs after 4, before 1). [added v4 2026-09-09]
#
# Why (3) exists: /v1/server/config is fetched exactly once, by the installer.
# Nodes provisioned before the Cloudflare token was rotated still hold the
# revoked one, so their certificates would fail to renew — around 30 days before
# expiry, silently, with nothing looking wrong until TLS stops working.
#
# Safety: this touches a live proxy. Every failure path leaves the node exactly
# as it was. The config is only replaced after `sing-box check` accepts it, and
# the service is only restarted if the file actually changed. The shaping step
# (2) rebuilds a tc tree fresh each run and tears it back down (node returns to
# its prior un-shaped state) if the node fails a post-apply health check.
set +e
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH

CONFIG="/etc/sing-box/config.json"
BACKUP="/etc/sing-box/config.json.maint-backup"
SAGER_NET="https://sing-box.app/gpg.key"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1"; }

# ── 4. Per-user byte metering (canary) ────────────────────────────────────────
# [added v3 2026-09-05] Numbered 4 because it was added last, but it runs FIRST:
# Job 1's daily `apt-get install sing-box` triggers the package postinst, which
# restarts the service and zeroes sing-box's in-memory traffic counters, so the
# counters must be harvested before Job 1 gets its turn.
#
# What it does on a node whose public IP is in METERING_IPS:
#   * every run: harvest the per-user counters into pending.json via the
#     monitor script (`sing-monitor.sh harvest`, under the monitor's own lock);
#   * first run (and whenever the pinned release changes): install a sing-box
#     built with the with_v2ray_api tag (official apt build lacks it) at
#     /usr/bin/sing-box behind a dpkg-divert, so tomorrow's apt upgrade lands
#     in /usr/bin/sing-box.distrib instead of clobbering it; install sing-stats;
#     splice `experimental.v2ray_api` into the config with the inbound user
#     names (name == account id) as the counted users; install the metering
#     edition of sing-monitor.sh (old copy kept as .bak-<stamp>); check;
#     restart;
#   * not in the list (or hold file present) but still metered: run the
#     off-switch, so removing an IP from the list below == rollback.
#
# Fail-open at every step: any failure leaves the node exactly as it was for
# that step. Two traps this guards against explicitly:
#   * FREEZE TRAP: the official binary plus a config with a v2ray_api block =>
#     `sing-box check` fails forever, and the 10s monitor then never applies a
#     user-list change again. So the build-tag gate (`sing-box version` must
#     print with_v2ray_api) runs BEFORE the block is spliced in, and a config
#     that has the block while the binary lacks the tag gets the block stripped.
#   * DIVERT-MISS: if the package's binary is not /usr/bin/sing-box or the unit
#     does not exec that path, the diversion would protect nothing; both are
#     checked with dpkg -L / systemctl cat before the first install (not
#     verifiable from the repo, hence the canary).
#
# Rollout: AU001 first, then five nodes, then the fleet -- by editing the list.
# [v3 2026-09-06] was: METERING_IPS="168.222.243.5"      # AU001 canary
# Canary verified on AU001 (with_v2ray_api binary live, stats listener on
# 127.0.0.1:10085, 19 users in the stats list, pending.json ticking every 10s).
# HK002 added next: it is the only pay-per-GB node in the fleet (Zenlayer,
# $0.017/GB both directions), so per-user metering matters there first.
METERING_IPS="168.222.243.5 64.205.176.209"      # AU001 canary + HK002 (Zenlayer, metered)
METERING_RELEASE="sing-box-v1.14.0-v2rayapi"   # GitHub Release tag of this repo (binaries + SHA256SUMS attached to the release)
# [v3 2026-09-05] Expected sha256 of the metering binaries, pinned HERE so the
# node does not have to trust a SHA256SUMS that lives in the same release as
# the binary (anyone who can write the release can rewrite both). Empty = only
# the release's own SHA256SUMS is checked (acceptable for the first canary
# build, when the hashes are not known yet); MUST be filled in from the
# workflow's published SHA256SUMS before METERING_IPS grows beyond the canary.
# [v3 2026-09-06] was: METERING_SHA256_AMD64="" (canary-only mode, hashes unknown before the first build)
METERING_SHA256_AMD64="7e90787bf1a9a74a6882dfb86ce3de693e2529c643966aab3308386ef1d924bb"
METERING_SHA256_ARM64="607634f3fb706cb4b5df8cc3e005048869dcfa2d4aff16179b4ba131e97c838c"
# [2026-09-18 repo-move] The release and the raw scripts now live in this repo;
# both URLs below used to point at the previous hosting repository.
METERING_BASE="https://github.com/jamesmaustralia-arch/wold/releases/download/$METERING_RELEASE"
XTPU_RAW="https://raw.githubusercontent.com/jamesmaustralia-arch/wold/main/scripts"
MONITOR="/usr/local/bin/sing-monitor.sh"
SBSTATS="/usr/local/bin/sing-stats"                 # STATS_BIN in sing-monitor.sh
METERING_OFF="/usr/local/sbin/node-metering-off.sh"
METERING_HOLD="/etc/sing-box/metering.off"           # written by the off-switch; rm to re-enable
METERING_STATE="/var/lib/sing-monitor/metering.release"
SB_BIN="/usr/bin/sing-box"
SB_DISTRIB="/usr/bin/sing-box.distrib"
V2RAY_LISTEN="127.0.0.1:10085"                       # the monitor reads .experimental.v2ray_api.listen back from the config

metering_harvest() {
    # Only the metering edition of the monitor knows `harvest`; the pre-metering
    # script would run a full heartbeat cycle with "harvest" as $1, harmless but
    # pointless. Retry a few times: the 10s timer may hold the lock right now.
    [ -x "$MONITOR" ] && grep -q '^harvest_stats()' "$MONITOR" 2>/dev/null || return 0
    n=0
    while [ "$n" -lt 3 ]; do
        "$MONITOR" harvest >/dev/null 2>&1 && { log "metering: harvested"; return 0; }
        n=$((n+1)); sleep 2
    done
    log "metering: harvest skipped (monitor busy), <=10s of counters may be lost"
    return 0
}

metering_has_tag() {
    "$SB_BIN" version 2>/dev/null | grep -q with_v2ray_api
}

metering_config_has_block() {
    jq -e '.experimental.v2ray_api != null' "$CONFIG" >/dev/null 2>&1
}

metering_strip_block() {
    metering_config_has_block || return 0
    cp "$CONFIG" "$BACKUP" || return 0
    NEW=$(jq 'del(.experimental.v2ray_api) | if .experimental == {} then del(.experimental) else . end' "$CONFIG" 2>/dev/null)
    [ -n "$NEW" ] || return 0
    printf '%s' "$NEW" > "$CONFIG.new" && [ -s "$CONFIG.new" ] || { rm -f "$CONFIG.new"; return 0; }
    if sing-box check -c "$CONFIG.new" >/dev/null 2>&1; then
        mv "$CONFIG.new" "$CONFIG" && systemctl restart sing-box && log "metering: v2ray_api block stripped (binary lacks the tag), restarted"
    else
        rm -f "$CONFIG.new"; log "metering: stripped candidate failed check, config left alone"
    fi
    return 0
}

metering_install_offswitch() {
    TMPOFF=$(mktemp 2>/dev/null) || return 0
    if curl -fsSL --max-time 30 -o "$TMPOFF" "$XTPU_RAW/node-metering-off.sh" 2>/dev/null \
       && grep -q '^# node-metering-off.sh' "$TMPOFF" && sh -n "$TMPOFF" 2>/dev/null; then
        install -m 0755 "$TMPOFF" "$METERING_OFF" 2>/dev/null
    fi
    rm -f "$TMPOFF"
    return 0
}

# Download release assets for this arch into $1, verify SHA256SUMS, and prove
# the candidate binary carries the tag before anything on the node is touched.
metering_fetch_release() {
    case "$(uname -m)" in
        x86_64)  ARCH=amd64 ;;
        aarch64) ARCH=arm64 ;;
        *) log "metering: unsupported arch $(uname -m), skip"; return 1 ;;
    esac
    for f in "sing-box-linux-$ARCH" "sing-stats-linux-$ARCH" SHA256SUMS; do
        curl -fsSL --max-time 300 -o "$1/$f" "$METERING_BASE/$f" 2>/dev/null \
            || { log "metering: download of $f failed"; return 1; }
    done
    ( cd "$1" && sha256sum -c --ignore-missing SHA256SUMS 2>/dev/null | grep -c ': OK$' ) | grep -qx 2 \
        || { log "metering: checksum mismatch, refusing"; return 1; }
    # [added v3 2026-09-05] second, independent check against the hash pinned
    # in this script (see METERING_SHA256_* above). Skipped only while empty.
    case "$ARCH" in amd64) want="$METERING_SHA256_AMD64" ;; arm64) want="$METERING_SHA256_ARM64" ;; *) want="" ;; esac
    if [ -n "$want" ]; then
        got=$(sha256sum "$1/sing-box-linux-$ARCH" 2>/dev/null | awk '{print $1}')
        [ "$got" = "$want" ] \
            || { log "metering: sing-box-linux-$ARCH sha256 $got != pinned $want, refusing"; return 1; }
    else
        log "metering: no pinned sha256 for $ARCH in this script (canary-only mode)"
    fi
    chmod 0755 "$1/sing-box-linux-$ARCH" "$1/sing-stats-linux-$ARCH"
    "$1/sing-box-linux-$ARCH" version 2>/dev/null | grep -q with_v2ray_api \
        || { log "metering: downloaded binary lacks with_v2ray_api, refusing"; return 1; }
    return 0
}

metering_install_binary() {
    # Already on the pinned release and carrying the tag: nothing to do.
    if [ "$(cat "$METERING_STATE" 2>/dev/null)" = "$METERING_RELEASE" ] && metering_has_tag; then
        return 0
    fi
    # First install only: the diversion must actually cover the binary the
    # unit runs, otherwise the official package would keep winning.
    if ! dpkg-divert --list "$SB_BIN" 2>/dev/null | grep -q "$SB_DISTRIB"; then
        dpkg -L sing-box 2>/dev/null | grep -qx "$SB_BIN" \
            || { log "metering: package does not own $SB_BIN, skip (verify on canary)"; return 1; }
        systemctl cat sing-box 2>/dev/null | grep -q "^ExecStart=$SB_BIN" \
            || { log "metering: unit ExecStart is not $SB_BIN, skip (verify on canary)"; return 1; }
    fi
    TMPD=$(mktemp -d 2>/dev/null) || return 1
    if ! metering_fetch_release "$TMPD"; then rm -rf "$TMPD"; return 1; fi
    # [v3 2026-09-05] Remember whether THIS run added the diversion, so a
    # failed copy can lift it again. Without that a first-install failure left
    # the node with no /usr/bin/sing-box at all: the package binary was already
    # renamed to .distrib, the same day's apt upgrade then honoured the
    # diversion (writing to .distrib as well), and the unit's ExecStart pointed
    # at nothing -- a node offline until someone ran the off-switch by hand.
    DIVERTED_NOW=0
    if ! dpkg-divert --list "$SB_BIN" 2>/dev/null | grep -q "$SB_DISTRIB"; then
        dpkg-divert --add --rename --divert "$SB_DISTRIB" "$SB_BIN" >/dev/null 2>&1 \
            || { log "metering: dpkg-divert --add failed"; rm -rf "$TMPD"; return 1; }
        log "metering: diverted package binary to $SB_DISTRIB"
        DIVERTED_NOW=1
    fi
    # [v3 2026-09-05] Stage next to the target and mv into place, so a release
    # bump that fails mid-copy keeps the old binary intact (mv on the same
    # filesystem is atomic; `install` unlinks the target first). Was:
    #   install -m 0755 "$TMPD/sing-box-linux-$ARCH" "$SB_BIN" || { rm -rf "$TMPD"; return 1; }
    if ! install -m 0755 "$TMPD/sing-box-linux-$ARCH" "$SB_BIN.metering-new" \
       || ! mv -f "$SB_BIN.metering-new" "$SB_BIN"; then
        log "metering: installing $SB_BIN failed"
        rm -f "$SB_BIN.metering-new"
        if [ "$DIVERTED_NOW" -eq 1 ]; then
            rm -f "$SB_BIN"
            if dpkg-divert --remove --rename --divert "$SB_DISTRIB" "$SB_BIN" >/dev/null 2>&1; then
                log "metering: diversion lifted again, package binary back at $SB_BIN"
            else
                log "metering: dpkg-divert --remove failed, run $METERING_OFF"
            fi
        fi
        rm -rf "$TMPD"; return 1
    fi
    install -m 0755 "$TMPD/sing-stats-linux-$ARCH" "$SBSTATS" || { rm -rf "$TMPD"; return 1; }
    rm -rf "$TMPD"
    if ! metering_has_tag; then
        # Should be impossible after the pre-install gate; undo everything.
        log "metering: installed binary lacks the tag, reverting diversion"
        rm -f "$SB_BIN"
        dpkg-divert --remove --rename --divert "$SB_DISTRIB" "$SB_BIN" >/dev/null 2>&1
        return 1
    fi
    PREV_RELEASE=$(cat "$METERING_STATE" 2>/dev/null)
    mkdir -p "$(dirname "$METERING_STATE")" 2>/dev/null
    printf '%s' "$METERING_RELEASE" > "$METERING_STATE"
    log "metering: installed $METERING_RELEASE at $SB_BIN (arch $ARCH)"
    # Release bump on an already-metered node: the file changed but the old
    # process is still running. First install needs no restart here -- the
    # config splice that follows restarts anyway.
    if [ -n "$PREV_RELEASE" ] && [ "$PREV_RELEASE" != "$METERING_RELEASE" ]; then
        metering_harvest
        systemctl restart sing-box && log "metering: restarted onto $METERING_RELEASE"
    fi
    return 0
}

# Install the metering edition of sing-monitor.sh, carrying over the seven
# %PLACEHOLDER% values hydra rendered into the current copy (API host, paths).
# Idempotent: nothing happens when the rendered candidate equals what is there.
metering_install_monitor() {
    [ -s "$MONITOR" ] || { log "metering: no $MONITOR, skip monitor install"; return 1; }
    TMPM=$(mktemp 2>/dev/null) || return 1
    curl -fsSL --max-time 30 -o "$TMPM" "$XTPU_RAW/sing-monitor.sh" 2>/dev/null \
        && grep -q '^harvest_stats()' "$TMPM" && grep -q '%API_SERVER%' "$TMPM" \
        || { log "metering: monitor download failed"; rm -f "$TMPM"; return 1; }
    for k in API_SERVER CONFIG_PATH USERS_PATH SCHEME_PATH TEMP_USERS TEMP_SCHEME LOCK_FILE; do
        v=$(sed -n "s/^$k=\"\(.*\)\"$/\1/p" "$MONITOR" | head -n1)
        [ -n "$v" ] || { log "metering: $k not found in current monitor, skip"; rm -f "$TMPM"; return 1; }
        case "$v" in *'|'*|*'%'*|*'&'*) log "metering: unusable $k value, skip"; rm -f "$TMPM"; return 1 ;; esac
        sed "s|%$k%|$v|g" "$TMPM" > "$TMPM.r" && mv "$TMPM.r" "$TMPM" || { rm -f "$TMPM" "$TMPM.r"; return 1; }
    done
    # Only the seven real placeholders: a generic %X% pattern would false-match
    # the template's own ${BYTES%% *} expansion.
    if grep -q '%\(API_SERVER\|CONFIG_PATH\|USERS_PATH\|SCHEME_PATH\|TEMP_USERS\|TEMP_SCHEME\|LOCK_FILE\)%' "$TMPM"; then
        log "metering: unrendered placeholder, skip"; rm -f "$TMPM"; return 1
    fi
    dash -n "$TMPM" 2>/dev/null || { log "metering: candidate monitor fails dash -n, skip"; rm -f "$TMPM"; return 1; }
    if cmp -s "$TMPM" "$MONITOR"; then rm -f "$TMPM"; return 0; fi
    cp "$MONITOR" "$MONITOR.bak-$(date +%Y%m%d%H%M%S)" || { rm -f "$TMPM"; return 1; }
    install -m 0755 "$TMPM" "$MONITOR" && log "metering: monitor script updated (previous kept as .bak-*)"
    rm -f "$TMPM"
    return 0
}

# Splice (or refresh) experimental.v2ray_api. Only after the tag gate passed.
metering_splice_block() {
    WANT=$(jq -c --arg l "$V2RAY_LISTEN" '{listen: $l, stats: {enabled: true, users: [.inbounds[0].users[]? | select(.name != null) | .name]}}' "$CONFIG" 2>/dev/null)
    [ -n "$WANT" ] || return 0
    HAVE=$(jq -c '.experimental.v2ray_api // empty' "$CONFIG" 2>/dev/null)
    [ "$WANT" = "$HAVE" ] && return 0
    cp "$CONFIG" "$BACKUP" || return 0
    NEW=$(jq --argjson v "$WANT" '.experimental.v2ray_api = $v' "$CONFIG" 2>/dev/null)
    [ -n "$NEW" ] || return 0
    printf '%s' "$NEW" > "$CONFIG.new" && [ -s "$CONFIG.new" ] || { rm -f "$CONFIG.new"; return 0; }
    if ! sing-box check -c "$CONFIG.new" >/dev/null 2>&1; then
        rm -f "$CONFIG.new"; log "metering: config with v2ray_api failed check, left alone"; return 0
    fi
    metering_harvest
    mv "$CONFIG.new" "$CONFIG" || return 0
    if systemctl restart sing-box; then
        log "metering: v2ray_api block applied on $V2RAY_LISTEN, restarted"
    else
        log "metering: restart failed, rolling the config back"
        cp "$BACKUP" "$CONFIG"; systemctl restart sing-box
    fi
    return 0
}

apply_metering() {
    for c in jq curl dpkg-divert systemctl sha256sum install; do
        command -v "$c" >/dev/null 2>&1 || { log "metering: $c absent, skip"; return 0; }
    done
    [ -f "$CONFIG" ] || { log "metering: no config, skip"; return 0; }

    MYIP=$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null)
    [ -n "$MYIP" ] || { log "metering: cannot learn public IP, skip"; return 0; }
    WANTED=0
    for mip in $METERING_IPS; do [ "$MYIP" = "$mip" ] && WANTED=1; done
    [ -f "$METERING_HOLD" ] && WANTED=0

    # Every run, first thing: counters out of memory before anything restarts.
    metering_harvest

    if [ "$WANTED" -eq 0 ]; then
        if [ -f "$METERING_STATE" ] && [ -x "$METERING_OFF" ]; then
            log "metering: $MYIP no longer in the list, running off-switch"
            "$METERING_OFF" >/dev/null 2>&1 || log "metering: off-switch reported failure"
        elif metering_config_has_block && ! metering_has_tag; then
            metering_strip_block   # freeze-trap escape, whatever left it behind
        fi
        return 0
    fi

    metering_install_offswitch
    metering_install_binary
    # Gate on what is actually at /usr/bin/sing-box now, not on whether the
    # install above succeeded: an already-metered node whose download failed
    # today still runs a tagged binary and must keep its block.
    metering_has_tag || { metering_strip_block; return 0; }
    metering_install_monitor
    # Count only once something on the node harvests: with the pre-metering
    # monitor still in place the counters would just pile up in memory until
    # Job 1's apt restart zeroes them.
    if grep -q '^harvest_stats()' "$MONITOR" 2>/dev/null; then
        metering_splice_block
    else
        log "metering: monitor lacks harvest support, block not enabled yet"
    fi
    return 0
}
apply_metering

# ── 5. Poller curl timeouts ───────────────────────────────────────────────────
# [added v4 2026-09-09] sing-monitor.sh's heartbeat curls had NO timeout, so one
# TCP/TLS hang to the Cloudflare edge held the oneshot for curl's 300s default,
# the 10s timer could not fire meanwhile, and hydra reaped the node for exactly
# that: >300s without a /users poll, then a "back online" on the next success.
# Measured on DE002/003/004 (MassiveGrid Frankfurt, lossy path to the FRA edge):
# 54-91 reaps per node in 7 days, most heartbeat gaps 301-330s; AU001 with the
# identical script: 2 in 30 days. A poll normally takes ~1s for ~3 KB, so
# 10s connect / 30s total is generous, and the 10s timer retries after it.
#
# This patches whatever edition of sing-monitor.sh is installed (the
# pre-metering template still on most nodes, or the metering edition from this
# repo, which now carries the flags at the source -- as does hydra's template
# for newly provisioned nodes). Only lines that invoke the poller
# (`curl -sSX POST`) and lack --max-time are touched; comment lines (the
# metering edition keeps an "Old body" copy) are skipped so history stays
# verbatim. Idempotent, syntax-gated with dash -n, previous copy kept as
# .bak-<stamp>, fail-open like everything else here. Replacing the file via
# install(1) gives it a new inode, so a heartbeat run in progress keeps
# executing its already-open copy.
POLL_CURL_OPTS="--connect-timeout 10 --max-time 30"
ensure_poller_timeouts() {
    [ -s "$MONITOR" ] || { log "timeouts: no $MONITOR, skip"; return 0; }
    # `-sSX POST` (not `curl -sSX POST`): once patched, the flags sit between
    # `curl` and `-sSX`, and this presence check must still recognise the file.
    grep -q -- '-sSX POST' "$MONITOR" 2>/dev/null || { log "timeouts: no poller curl lines in $MONITOR, skip"; return 0; }
    # Every live poller line already has a timeout => nothing to do (quiet).
    if ! grep -v '^[[:space:]]*#' "$MONITOR" | grep -- '-sSX POST' | grep -qv -- '--max-time'; then
        return 0
    fi
    TMPT=$(mktemp 2>/dev/null) || { log "timeouts: mktemp failed, skip"; return 0; }
    sed -e '/^[[:space:]]*#/b' -e '/curl -sSX POST/!b' -e '/--max-time/b' \
        -e "s/curl -sSX POST/curl $POLL_CURL_OPTS -sSX POST/" "$MONITOR" > "$TMPT" 2>/dev/null \
        || { rm -f "$TMPT"; log "timeouts: sed failed, skip"; return 0; }
    [ -s "$TMPT" ] || { rm -f "$TMPT"; log "timeouts: empty candidate, skip"; return 0; }
    dash -n "$TMPT" 2>/dev/null || { rm -f "$TMPT"; log "timeouts: candidate fails dash -n, skip"; return 0; }
    if cmp -s "$TMPT" "$MONITOR"; then rm -f "$TMPT"; return 0; fi
    cp "$MONITOR" "$MONITOR.bak-$(date +%Y%m%d%H%M%S)" || { rm -f "$TMPT"; log "timeouts: backup failed, skip"; return 0; }
    install -m 0755 "$TMPT" "$MONITOR" && log "timeouts: poller curl now runs with $POLL_CURL_OPTS (previous kept as .bak-*)"
    rm -f "$TMPT"
    return 0
}
ensure_poller_timeouts

# ── 1. sing-box package update (unchanged behaviour) ──────────────────────────
sudo -E apt-get -qq update
sudo -E apt-get -qq install -o Dpkg::Options::="--force-confold" -y gnupg2 jq

curl -fsSL "$SAGER_NET" | sudo -E gpg --yes --dearmor -o /etc/apt/trusted.gpg.d/sagernet.gpg
echo "deb https://deb.sagernet.org * *" | sudo -E tee /etc/apt/sources.list.d/sagernet.list >/dev/null

sudo -E apt-get -qq update
sudo -E apt-get -qq install -o Dpkg::Options::="--force-confold" -y sing-box

# ── 2. Per-client-IP fair-share shaping (anti-abuse) ──────────────────────────
# [added v2 2026-08] Rolls the per-IP rate limit to the whole fleet via the
# self-heal timer instead of SSHing 40+ nodes. Idempotent (rebuilt each run) and
# fail-open by construction:
#   * a node that runs the daily-volume TIERED throttle (HK) is skipped — its own
#     systemd unit owns shaping and a flat tree here would clobber it;
#   * nodes on the explicit special-management IP list are skipped;
#   * if anything is missing (no tc, no uplink) the step returns without touching
#     the node;
#   * after apply, a health gate (sing-box active + egress reachable + full tree)
#     must pass, else the whole tree is torn down and the node is left un-shaped
#     exactly as before.
# Shaping only touches the client plane (tcp sport/dport 443). The node's own
# egress (WARP udp/2408, DNS/53, SSH/22, ACME dns01 which is outbound dport 443
# with an ephemeral sport) never matches the sport/dport-443 hash and rides the
# unshaped default class.
# [v3 2026-09-05] HK001 joins the fleet-wide flat per-IP shaping. Its tiered
# daily-volume throttle (node-tierlimit) is being retired by hand (see
# docs/HK001-merge-into-fleet.md); once its apply script loses +x and the nft
# ledger is gone, the tiered-node probe below no longer matches and this list
# is what would still exclude it. Emptied so `for sip in $SPECIAL_IPS` iterates
# zero times. The probe block (node-tierlimit-apply.sh -x / nft table) stays
# as-is so the ordering is safe either way: HK001 keeps its tiered shaping
# until the manual steps are done, whatever this file says.
# Old value preserved:
#   SPECIAL_IPS="191.222.218.103"     # HK001: managed by node-tierlimit (tiered)
SPECIAL_IPS=""

apply_shaping() {
    command -v tc >/dev/null 2>&1 || { log "shaping: tc absent, skip"; return 0; }

    # Skip tiered nodes (HK): presence of the tier apply script or the nft ledger.
    if [ -x /usr/local/sbin/node-tierlimit-apply.sh ] \
       || nft list table ip fjolsky_tiers >/dev/null 2>&1; then
        log "shaping: tiered node, leaving shaping to node-tierlimit"; return 0
    fi

    # Skip explicit special-management IPs (belt-and-suspenders for HK).
    MYIP=$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null)
    for sip in $SPECIAL_IPS; do
        [ "$MYIP" = "$sip" ] && { log "shaping: special IP $MYIP, skip"; return 0; }
    done

    DEV=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
    [ -n "$DEV" ] || { log "shaping: no uplink dev, skip"; return 0; }
    [ "$DEV" = lo ] && { log "shaping: refuse lo, skip"; return 0; }

    # [2026-09-01] Ceilings raised 3x on operator instruction: the old 12mbit
    # per-client ceiling was shaping real playback, not just abuse. An Australian
    # tester on hydra v1.8.7 (which moved porn traffic from WARP to the node exit)
    # got bursts of `failed to create session: connection reset by peer` against
    # JP002 mid-video: a media page opens dozens of parallel segment fetches, they
    # all hash to the caller's single bucket, and 12mbit is under what adaptive
    # bitrate asks for. This stays a per-client-IP abuse guard, just a roomier one.
    #
    # BURST MOVES WITH CEIL -- it is not decoration. HTB can only emit `burst`
    # bytes per timer tick, so a ceiling raised without it simply never gets
    # reached (burst >= ceil/HZ; at HZ=250, 36mbit needs >=18k, 12mbit needs >=6k).
    # Leaving burst at 16k/6k would have made this change a no-op for download and
    # a partial one for upload. Kept just above the minimum, not far above: an
    # oversized burst lets a flow overshoot ceil on each tick.
    #
    # Aggregate stays safe: the 256 buckets' guaranteed rates total
    # 256 x 1152kbit = 295mbit down / 98mbit up, both still well under LINE, so
    # the borrow-up-to-ceil behaviour is unchanged -- a single client can burst to
    # 36mbit when the node is idle and falls back to its fair share under load.
    # LINE and DIV deliberately unchanged.
    #
    # Old values preserved:
    #   DOWN=12mbit; UP=4mbit; LINE=1000mbit
    #   DOWN_RATE=384kbit; UP_RATE=128kbit; DOWN_BURST=16k; UP_BURST=6k; DIV=256
    DOWN=36mbit; UP=12mbit; LINE=1000mbit
    DOWN_RATE=1152kbit; UP_RATE=384kbit; DOWN_BURST=48k; UP_BURST=18k; DIV=256

    for m in sch_htb sch_fq_codel cls_u32 act_mirred ifb; do modprobe "$m" 2>/dev/null; done

    tear_down() {
        tc qdisc del dev "$DEV" root 2>/dev/null
        tc qdisc del dev "$DEV" ingress 2>/dev/null
        tc qdisc del dev ifb0 root 2>/dev/null
    }

    # persist an off-switch so ops can revert by hand without this script.
    # NOTE(2026-08-10, AU001 canary): generated via an UNQUOTED here-doc that
    # bakes the resolved $DEV in, NOT `echo`. This script is #!/bin/dash and
    # dash's echo is XSI — it turns the sed backref \1 into octal \001, which
    # corrupted the device-detection line of the old echo-built off-switch and
    # left eth0's tree un-removable (ifb0 gone but ingress mirred still pointing
    # at it → dropped client uploads). Hard-coding $DEV removes the sed entirely,
    # same as tear_down(), so ops revert is always reliable. \$PATH is escaped so
    # it stays literal in the generated file.
    cat > /usr/local/sbin/node-ratelimit-off.sh 2>/dev/null <<OFF
#!/bin/sh
export PATH=/usr/sbin:/sbin:/usr/bin:/bin:\$PATH
tc qdisc del dev $DEV root 2>/dev/null
tc qdisc del dev $DEV ingress 2>/dev/null
tc qdisc del dev ifb0 root 2>/dev/null
ip link set ifb0 down 2>/dev/null
ip link del ifb0 2>/dev/null
echo shaping-removed
OFF
    chmod +x /usr/local/sbin/node-ratelimit-off.sh 2>/dev/null

    tear_down   # idempotent clean before rebuild

    # ---- A. egress (download): hash by client dst IP, tcp sport 443 -----------
    tc qdisc add dev "$DEV" root handle 1: htb default 9999 r2q 100
    tc class add dev "$DEV" parent 1: classid 1:1 htb rate "$LINE" ceil "$LINE"
    tc class add dev "$DEV" parent 1:1 classid 1:9999 htb rate "$LINE" ceil "$LINE"
    i=0; while [ "$i" -lt "$DIV" ]; do cid=$((256+i))
      tc class add dev "$DEV" parent 1:1 classid 1:$cid htb rate "$DOWN_RATE" ceil "$DOWN" burst "$DOWN_BURST" cburst "$DOWN_BURST" quantum 1514
      tc qdisc add dev "$DEV" parent 1:$cid handle $cid: fq_codel; i=$((i+1)); done
    tc filter add dev "$DEV" parent 1:0 protocol ip handle 10: u32 divisor "$DIV"
    tc filter add dev "$DEV" parent 1:0 protocol ip prio 1 u32 match ip protocol 6 0xff match ip sport 443 0xffff hashkey mask 0x000000ff at 16 link 10:
    i=0; while [ "$i" -lt "$DIV" ]; do h=$(printf '%x' "$i")
      tc filter add dev "$DEV" parent 1:0 protocol ip prio 1 u32 ht 10:$h: match ip dst 0.0.0.0/0 flowid 1:$((256+i)); i=$((i+1)); done

    # ---- B. ingress (upload) -> ifb0: hash by client src IP, tcp dport 443 ----
    ip link add ifb0 type ifb 2>/dev/null || true
    ip link set ifb0 up
    tc qdisc add dev "$DEV" handle ffff: ingress
    tc filter add dev "$DEV" parent ffff: protocol ip prio 1 u32 match ip protocol 6 0xff match ip dport 443 0xffff action mirred egress redirect dev ifb0
    tc qdisc add dev ifb0 root handle 1: htb default 9999 r2q 100
    tc class add dev ifb0 parent 1: classid 1:1 htb rate "$LINE" ceil "$LINE"
    tc class add dev ifb0 parent 1:1 classid 1:9999 htb rate "$LINE" ceil "$LINE"
    i=0; while [ "$i" -lt "$DIV" ]; do cid=$((256+i))
      tc class add dev ifb0 parent 1:1 classid 1:$cid htb rate "$UP_RATE" ceil "$UP" burst "$UP_BURST" cburst "$UP_BURST" quantum 1514
      tc qdisc add dev ifb0 parent 1:$cid handle $cid: fq_codel; i=$((i+1)); done
    tc filter add dev ifb0 parent 1:0 protocol ip handle 10: u32 divisor "$DIV"
    tc filter add dev ifb0 parent 1:0 protocol ip prio 1 u32 match ip protocol 6 0xff match ip dport 443 0xffff hashkey mask 0x000000ff at 12 link 10:
    i=0; while [ "$i" -lt "$DIV" ]; do h=$(printf '%x' "$i")
      tc filter add dev ifb0 parent 1:0 protocol ip prio 1 u32 ht 10:$h: match ip src 0.0.0.0/0 flowid 1:$((256+i)); i=$((i+1)); done

    # ---- health gate: keep only if node is healthy + full tree; else revert ---
    EG=fail; curl -fsS --max-time 8 -o /dev/null https://1.1.1.1 && EG=ok
    SB=$(systemctl is-active sing-box 2>/dev/null)
    ECLS=$(tc class show dev "$DEV" 2>/dev/null | grep -c 'class htb')
    ICLS=$(tc class show dev ifb0 2>/dev/null | grep -c 'class htb')
    EFIL=$(tc filter show dev "$DEV" 2>/dev/null | grep -c 'flowid')
    IFIL=$(tc filter show dev ifb0 2>/dev/null | grep -c 'flowid')
    L443=$(ss -tlnp 2>/dev/null | grep -c ':443')
    # NOTE(2026-08-11, review hardening): also assert the UPLOAD path is live, not
    # just structurally present. The structural counts (ICLS/IFIL) pass even if ifb0
    # is admin-DOWN or the ingress->ifb0 redirect is missing, which would blackhole
    # client uploads (tcp dport 443) while the gate stays green. Near-impossible to
    # reach in steady state, but the check is free.
    #   * IFUP: match the IFF_UP flag in <...>, NOT `state UP` — ifb virtual devices
    #     report operstate UNKNOWN even when administratively up, so `state UP` would
    #     false-fail a healthy apply and silently un-shape the whole fleet.
    #   * MIR: the $DEV ingress -> ifb0 mirred redirect must be installed.
    IFUP=$(ip link show ifb0 2>/dev/null | grep -cE '[<,]UP[,>]')
    MIR=$(tc filter show dev "$DEV" parent ffff: 2>/dev/null | grep -c mirred)
    if [ "$EG" = ok ] && [ "$SB" = active ] && [ "$ECLS" -ge 257 ] && [ "$ICLS" -ge 257 ] \
       && [ "$EFIL" -ge 256 ] && [ "$IFIL" -ge 256 ] && [ "$L443" -ge 1 ] \
       && [ "$IFUP" -ge 1 ] && [ "$MIR" -ge 1 ]; then
        log "shaping: applied per-IP $DOWN/$UP on $DEV (egress=$EG singbox=$SB)"
    else
        log "shaping: health gate FAILED (egress=$EG singbox=$SB ecls=$ECLS icls=$ICLS ifup=$IFUP mir=$MIR), reverting to un-shaped"
        tear_down
    fi
    return 0
}
apply_shaping

# ── 3. ACME credential re-sync ────────────────────────────────────────────────
# Bail out quietly on anything unexpected: a node with a stale renewal token
# still serves traffic today, so nothing here is worth risking the service for.
[ -f "$CONFIG" ] || { log "no config at $CONFIG, skipping acme sync"; exit 0; }
command -v jq >/dev/null 2>&1 || { log "jq missing, skipping acme sync"; exit 0; }

# The API identifies the node by source IP; no credentials are sent or needed.
DOMAIN=$(jq -r '.inbounds[0].tls.server_name // empty' "$CONFIG" 2>/dev/null \
         | sed 's/^[^.]*\.//')
[ -n "$DOMAIN" ] || DOMAIN="fjolskylduoryggisverndar.com"

RESPONSE=$(curl -fsS --max-time 30 -X POST "https://api.$DOMAIN/v1/server/config" 2>/dev/null)
[ -n "$RESPONSE" ] || { log "config fetch failed, keeping current token"; exit 0; }

WANT=$(printf '%s' "$RESPONSE" | jq -r '.data.config' 2>/dev/null | base64 -d 2>/dev/null \
       | jq -r '.inbounds[0].tls.acme.dns01_challenge.api_token // empty' 2>/dev/null)
[ -n "$WANT" ] || { log "no acme token in response, keeping current"; exit 0; }

HAVE=$(jq -r '.inbounds[0].tls.acme.dns01_challenge.api_token // empty' "$CONFIG" 2>/dev/null)
[ "$WANT" = "$HAVE" ] && { log "acme token already current"; exit 0; }

log "acme token differs, updating"
sudo cp "$CONFIG" "$BACKUP" || exit 0

NEW=$(jq --arg t "$WANT" '.inbounds[0].tls.acme.dns01_challenge.api_token = $t' "$CONFIG")
[ -n "$NEW" ] || { log "jq produced nothing, aborting"; exit 0; }

printf '%s' "$NEW" | sudo tee "$CONFIG.new" >/dev/null
[ -s "$CONFIG.new" ] || { sudo rm -f "$CONFIG.new"; log "empty candidate, aborting"; exit 0; }

sudo mv "$CONFIG.new" "$CONFIG"
if sudo sing-box check -c "$CONFIG" >/dev/null 2>&1; then
    if sudo systemctl restart sing-box; then
        log "acme token updated and sing-box restarted"
    else
        log "restart failed, rolling back"
        sudo cp "$BACKUP" "$CONFIG"
        sudo systemctl restart sing-box
    fi
else
    log "sing-box rejected the new config, rolling back"
    sudo cp "$BACKUP" "$CONFIG"
fi

#!/bin/sh
# Shared helpers for the confmask test suites.
#
# Observers are /proc-first (that IS the ground truth `ps` reads) and the
# helpers only need busybox-grade tools, so the suites run identically on
# a full host and inside a minimal initramfs VM.

# suites `cd` to their own directory before sourcing this file
BIN_DIR="$(pwd)"
TOOL="$BIN_DIR/confmask"
CASES="$BIN_DIR/testcases"

# ---------------------------------------------------------------- scanning

# sightings MARKER
# Count processes whose /proc cmdline, environ or comm contain MARKER.
# Excludes our own shell/grep machinery and the observer itself.
sightings() {
    m="$1"
    n=0
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        for f in cmdline environ comm; do
            if cat "$d/$f" 2>/dev/null | tr '\0' ' ' | grep -qF -- "$m"; then
                n=$((n + 1))
                break
            fi
        done
    done
    if command -v ps >/dev/null 2>&1; then
        pn=$(ps -e -o args= 2>/dev/null | grep -F -- "$m" | grep -cv grep || true)
        n=$((n + pn))
    fi
    echo "$n"
}

# watch MARKER SECONDS
# Sample repeatedly; sets SEE to the max sighting count, stops early on
# the first sighting.
watch() {
    m="$1"; secs="$2"
    SEE=0
    end=$(( $(date +%s 2>/dev/null || echo 0) + secs ))
    while :; do
        s=$(sightings "$m")
        [ "$s" -gt "$SEE" ] && SEE=$s
        [ "$SEE" -gt 0 ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# comm_count PREFIX
# Number of processes whose comm starts with PREFIX.
comm_count() {
    p="$1"
    n=0
    for c in /proc/[0-9]*/comm; do
        case "$(cat "$c" 2>/dev/null)" in
            "$p"*) n=$((n + 1)) ;;
        esac
    done
    if command -v ps >/dev/null 2>&1; then
        pn=$(ps -e -o comm= 2>/dev/null | awk -v p="$p" 'index($0, p) == 1' | wc -l | tr -d ' ')
        n=$((n + pn))
    fi
    echo "$n"
}

# ------------------------------------------------------- scoped cleanup
# kill_comm only touches processes that belong to this suite run.
# CONFMASK_TEST_GLOBAL_KILL=1 restores the machine-wide comm-prefix kill
# (disposable VMs and containers only).

MY_UID=$(id -u 2>/dev/null || echo 0)

proc_ppid() {  # pid -> parent pid (empty when the process is gone)
    sed -n 's/^PPid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$1/status" 2>/dev/null
}

proc_uid() {  # pid -> real uid
    sed -n 's/^Uid:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$1/status" 2>/dev/null
}

proc_start() {  # pid -> start time in clock ticks (stat field 22)
    # strip "pid (comm) " up to the last ") "; the state is then field 1
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20
}

# start time of this shell: no process of this run started earlier
SUITE_START=$(proc_start $$)
[ -n "$SUITE_START" ] || SUITE_START=0

# in_suite_scope PID
# True when PID descends from this shell (PPid walk, at most 16 hops).
# A double-forked daemon is reparented to init, so a chain that ends at
# pid 1 is attributed by its topmost process: same uid and started after
# this shell.  Two suites of one uid running at the same time can see
# each other's orphans; that is the documented limit of the scoped mode.
in_suite_scope() {
    sc_p="$1"; sc_d=0
    while [ "$sc_d" -lt 16 ]; do
        sc_pp=$(proc_ppid "$sc_p")
        [ -n "$sc_pp" ] || return 1
        [ "$sc_pp" = "$$" ] && return 0
        if [ "$sc_pp" -le 1 ]; then
            [ "$(proc_uid "$sc_p")" = "$MY_UID" ] || return 1
            sc_st=$(proc_start "$sc_p")
            [ -n "$sc_st" ] || return 1
            [ "$sc_st" -ge "$SUITE_START" ]
            return
        fi
        sc_p="$sc_pp"
        sc_d=$((sc_d + 1))
    done
    return 1
}

# kill_comm PREFIX [SIGNAL]
kill_comm() {
    p="$1"; sig="${2:-KILL}"
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                if [ "${CONFMASK_TEST_GLOBAL_KILL:-0}" = 1 ] || in_suite_scope "$pid"; then
                    kill -"$sig" "$pid" 2>/dev/null
                fi
                ;;
        esac
    done
}

# comm_exe_count COMM-PREFIX EXE-BASENAME
# Processes whose comm starts with COMM-PREFIX and whose /proc/<pid>/exe
# names EXE-BASENAME.  Liveness that cannot be satisfied by the
# supervisor itself carrying the label.
comm_exe_count() {
    p="$1"; exe="$2"; n=0
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                case "$(readlink "$d/exe" 2>/dev/null)" in
                    */"$exe") n=$((n + 1)) ;;
                esac
                ;;
        esac
    done
    echo "$n"
}

# wait_comm_exe COMM-PREFIX EXE-BASENAME WANT SECONDS
# Poll until comm_exe_count reaches WANT; prints the last count.
wait_comm_exe() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $4 ))
    while :; do
        n=$(comm_exe_count "$1" "$2")
        [ "$n" -ge "$3" ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$n"
}

# environ_hits MARKER
# Count processes whose /proc environ contains MARKER (own shell excluded).
environ_hits() {
    m="$1"; n=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$$" ] && continue
        if cat "$d/environ" 2>/dev/null | tr '\0' ' ' | grep -qF -- "$m"; then
            n=$((n + 1))
        fi
    done
    echo "$n"
}

# unique marker for this run
fresh_marker() {
    dd if=/dev/urandom bs=6 count=1 2>/dev/null | base64 2>/dev/null | tr -dc 'a-zA-Z0-9'
    echo -n ""
}

# ---------------------------------------------------------------- binaries
# refresh_bins: make tests/{confmask,confmaskd,testcases,protocases} current.
#   1. TESTBIN_DIR set: copy the prebuilt binaries from there.
#   2. cargo present: always run `cargo build --release --bins` (a no-op
#      when fresh), copy, and refuse binaries older than any src/**/*.rs.
#   3. otherwise (the VM): use the binaries already in this directory.
# Returns 1 with a FATAL line when a required binary is missing or stale.
BIN_PAIRS="confmask:confmask confmaskd:confmaskd confmask-testcases:testcases confmask-protocases:protocases"

refresh_bins() {
    root="$BIN_DIR/.."
    if [ -n "${TESTBIN_DIR:-}" ]; then
        for pair in $BIN_PAIRS; do
            # TESTBIN_DIR may use the cargo names or the tests/ names
            cargo_name=${pair%%:*}; dst=${pair##*:}
            src=""
            [ -x "$TESTBIN_DIR/$dst" ] && src="$TESTBIN_DIR/$dst"
            [ -z "$src" ] && [ -x "$TESTBIN_DIR/$cargo_name" ] && src="$TESTBIN_DIR/$cargo_name"
            [ -n "$src" ] || continue
            [ "$src" -ef "$BIN_DIR/$dst" ] && continue
            cp -p "$src" "$BIN_DIR/$dst" || return 1
        done
        [ -x "$TESTBIN_DIR/testcases32" ] && cp -p "$TESTBIN_DIR/testcases32" "$BIN_DIR/testcases32"
    elif command -v cargo >/dev/null 2>&1 && [ -f "$root/Cargo.toml" ]; then
        (cd "$root" && cargo build --release --bins) \
            || { echo "FATAL: cargo build failed" >&2; return 1; }
        for pair in $BIN_PAIRS; do
            src=${pair%%:*}; dst=${pair##*:}
            [ -x "$root/target/release/$src" ] || continue
            cp -p "$root/target/release/$src" "$BIN_DIR/$dst" || return 1
            newer=$(find "$root/src" -name '*.rs' -newer "$BIN_DIR/$dst" 2>/dev/null | head -1)
            if [ -n "$newer" ]; then
                echo "FATAL: $BIN_DIR/$dst is older than $newer (stale binary)" >&2
                return 1
            fi
        done
    fi
    for b in confmask confmaskd testcases; do
        if [ ! -x "$BIN_DIR/$b" ]; then
            echo "FATAL: $BIN_DIR/$b missing (no cargo, no TESTBIN_DIR)" >&2
            return 1
        fi
    done
    return 0
}

# require_bins: suites call this first.  run.sh has already refreshed the
# binaries and sets CONFMASK_BINS_READY=1 so each suite does not rebuild.
require_bins() {
    [ "${CONFMASK_BINS_READY:-0}" = 1 ] && return 0
    refresh_bins
}

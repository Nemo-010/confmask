#!/bin/sh
# Shared helpers for the confmask suites.
#
# Observers read /proc directly: that IS the ground truth `ps` reads, and
# it keeps the suites runnable in a minimal initramfs.

# Suites cd to their own directory before sourcing this file, so the
# working directory is already right; re-resolving $0 here would break
# when the suite was invoked as `sh tests/run.sh` (relative path, already
# consumed by the caller's cd).
BIN_DIR="$(pwd)"
TOOL="$BIN_DIR/confmask"
WORK="${CONFMASK_TEST_DIR:-/tmp/confmask-tests}"

FAIL=0
SKIP=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=1; }
skip() { echo "SKIP $*"; SKIP=$((SKIP + 1)); }

# marker: a random string no other process can be carrying
marker() {
    printf 'MK%s' "$(dd if=/dev/urandom bs=6 count=1 2>/dev/null | base64 | tr -dc 'a-zA-Z0-9')"
}

# sightings MARKER: how many processes expose MARKER in cmdline or environ
sightings() {
    m="$1"
    n=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$$" ] && continue
        for f in cmdline environ; do
            if cat "$d/$f" 2>/dev/null | tr '\0' ' ' | grep -qF -- "$m"; then
                n=$((n + 1))
                break
            fi
        done
    done
    echo "$n"
}

# comm_count PREFIX
comm_count() {
    p="$1"
    n=0
    for c in /proc/[0-9]*/comm; do
        case "$(cat "$c" 2>/dev/null)" in
            "$p"*) n=$((n + 1)) ;;
        esac
    done
    echo "$n"
}

# require the binary; build it if it is not there yet
require_bin() {
    [ -x "$TOOL" ] && return 0
    ( cd "$BIN_DIR/.." && cargo build --release >/dev/null 2>&1 ) || return 1
    cp "$BIN_DIR/../target/release/confmask" "$TOOL" || return 1
    chmod +x "$TOOL"
}

setup_work() {
    rm -rf "$WORK"
    mkdir -p "$WORK"
    printf 'test-passphrase\n' > "$WORK/pp"
    chmod 600 "$WORK/pp"
    printf 'ghp_SUPERSECRETVALUE\n' > "$WORK/token"
    chmod 600 "$WORK/token"
}

cleanup_work() {
    rm -rf "$WORK"
}

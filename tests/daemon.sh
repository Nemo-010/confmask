#!/bin/sh
# ============================================================================
# confmaskd: the job runs with the secret, and nothing on the machine can
# read it back out of /proc.
#
#   D1  negative control: a secret in a plain shell's environment IS
#       visible in /proc/<pid>/environ (the observer can detect it)
#   D2  the job started by the daemon receives the secret (length check,
#       so the value is never printed)
#   D3  while that job runs, the secret appears in no /proc cmdline or
#       environ: not the daemon's, not the client's, not the job's
#   D4  the daemon's own /proc entry carries the label, not its argv
#   D5  exit status and stdout pass through the daemon
#   D6  a job that cannot exec fails with 127 and the daemon survives it
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

DAEMON="$BIN_DIR/confmaskd"
SOCK="/tmp/confmask-test-$$.sock"
ENVF="/tmp/confmask-env-$$"
SECRET="CMK-$(fresh_marker)"
LABEL="cm-test-$$"
LABEL15=$(printf '%s' "$LABEL" | cut -c1-15)
FAIL=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

[ -x "$DAEMON" ] || { echo "FATAL: confmaskd missing"; exit 2; }

printf 'CI_TOKEN=%s\n' "$SECRET" > "$ENVF"
chmod 600 "$ENVF"

# ------------------------------------------------- D1: negative control
CI_TOKEN="$SECRET" /bin/sh -c 'sleep 1' &
CTL=$!
sleep 0.3
seen=0
for d in /proc/[0-9]*; do
    if cat "$d/environ" 2>/dev/null | tr '\0' '\n' | grep -qF -- "$SECRET"; then
        seen=1
        break
    fi
done
kill "$CTL" 2>/dev/null
[ "$seen" = 1 ] && pass d1-control-secret-is-detectable \
    || fail "d1-control (the observer cannot see an unmasked environment)"

# ------------------------------------------------------------ start daemon
"$DAEMON" -q -l "$LABEL" -S "$SOCK" -e "$ENVF" &
DPID=$!
i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
[ -S "$SOCK" ] || { fail "d0-daemon-did-not-start"; echo "== VERDICT: FAIL=$FAIL =="; exit 1; }

# ------------------------------------- D2/D3: job runs, secret stays hidden
LEN=$(printf '%s' "$SECRET" | wc -c | tr -d ' ')
OUT=$( "$TOOL" --daemon "$SOCK" --label "$LABEL" -- /bin/sh -c 'echo ${#CI_TOKEN}; sleep 1' 2>/dev/null )
case "$OUT" in
    *"$LEN"*) pass "d2-job-received-secret (length $LEN)" ;;
    *) fail "d2-job-received-secret (got '$OUT', want length $LEN)" ;;
esac

# The job has exited by now; run a long one and sweep /proc while it lives.
"$TOOL" --daemon "$SOCK" --label "$LABEL" -- /bin/sh -c 'sleep 2' >/dev/null 2>&1 &
CLIENT=$!
sleep 0.6
leaks=0
for d in /proc/[0-9]*; do
    for f in cmdline environ; do
        if cat "$d/$f" 2>/dev/null | tr '\0' '\n' | grep -qF -- "$SECRET"; then
            leaks=$((leaks + 1))
        fi
    done
done
[ "$leaks" = 0 ] && pass d3-secret-in-no-proc-entry \
    || fail "d3-secret-in-no-proc-entry ($leaks sightings)"

# ------------------------------------------------- D4: daemon self-mask
dc=""
dtxt=""
for d in /proc/[0-9]*; do
    [ "${d#/proc/}" = "$DPID" ] || continue
    dc=$(cat "$d/comm" 2>/dev/null)
    dtxt=$(tr -d '\000' < "$d/cmdline" 2>/dev/null)
done
# The daemon zeroes its own argv block and writes the label into it, so
# its cmdline reads back as exactly the label (issue #19).
if [ "$dc" = "$LABEL15" ] && [ "$dtxt" = "$LABEL" ]; then
    pass d4-daemon-selfmask
else
    fail "d4-daemon-selfmask (comm=[$dc] cmdline=[$dtxt])"
fi

wait "$CLIENT" 2>/dev/null

# --------------------------------------------- D5: status and stdout pass
OUT=$("$TOOL" --daemon "$SOCK" -- /bin/sh -c 'echo hello-from-job; exit 7' 2>/dev/null)
rc=$?
if [ "$OUT" = "hello-from-job" ] && [ "$rc" = 7 ]; then
    pass d5-stdio-and-exit-status
else
    fail "d5-stdio-and-exit-status (out='$OUT' rc=$rc)"
fi

# --------------------------------------- D6: a failed job keeps the daemon
"$TOOL" --daemon "$SOCK" -- /nonexistent/confmask-job >/dev/null 2>&1
rc=$?
OUT=$("$TOOL" --daemon "$SOCK" -- /bin/sh -c 'echo alive' 2>/dev/null)
if [ "$rc" = 127 ] && [ "$OUT" = "alive" ]; then
    pass d6-failed-job-keeps-daemon
else
    fail "d6-failed-job-keeps-daemon (rc=$rc out='$OUT')"
fi

kill "$DPID" 2>/dev/null
rm -f "$SOCK" "$ENVF"

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]

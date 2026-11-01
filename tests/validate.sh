#!/bin/sh
# ============================================================================
# confmask validation -- run a battery of marker-carrying commands under a
# mask and verify with /proc (cmdline, environ, comm) + ps that nothing
# real is observable, while the programs themselves keep working.
#
# Self-contained.  Verification method (no trust in the tool required):
#   1. NEGATIVE CONTROL: the same battery runs WITHOUT the mask; the
#      observer MUST find the markers (proves the detector can detect).
#   2. The battery runs under confmask while an observer samples:
#        /proc/<pid>/cmdline   (what every /proc reader gets)
#        /proc/<pid>/environ   (environment disclosure)
#        /proc/<pid>/comm      (the Name top/htop display)
#        ps -e -o args         (when a ps is present)
#   3. A case passes only with ZERO sightings of its marker.
#   4. LIVENESS: processes must be alive under the label (not silently
#      dead -- that would make "zero sightings" vacuous).
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAKE='[kworker/1:2-rcu_gp]'
R=$(fresh_marker); [ -n "$R" ] || R="x$$$(date +%s 2>/dev/null || echo 1)"

OVERALL=0
PIDS=""

run_case() {  # $1 marker, $2 payload, $3 mode(mask|control), $4 expect(see|blind)
    if [ "$3" = mask ]; then
        PAYLOAD="$2" "$TOOL" -q -l "$FAKE" /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
    else
        PAYLOAD="$2" /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
    fi
    pid=$!
    [ -n "$pid" ] && PIDS="$PIDS $pid"
    sleep 0.3
    watch "$1" 1
    if [ "$4" = see ]; then
        if [ "$SEE" -gt 0 ]; then echo "PASS control-$1 (detector works, $SEE sightings)"
        else echo "FAIL control-$1: marker not even visible WITHOUT confmask (detector broken)"; OVERALL=1; fi
    else
        if [ "$SEE" -eq 0 ]; then echo "PASS $1: no sightings"
        else echo "FAIL $1: LEAKED $SEE sighting(s) via /proc or ps"; OVERALL=1; fi
    fi
}

cleanup() { for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; PIDS=""; }
trap 'cleanup' EXIT INT TERM

echo "== confmask validation run (suffix $R, label $FAKE) =="

A="MK${R}A"; B="MK${R}B"; C="MK${R}C"; D="MK${R}D"
E="MK${R}E"; F="MK${R}F"; G="MK${R}G"; H="MK${R}H"

echo "-- phase 1: negative control (no confmask; markers MUST be observable)"
run_case "$A" "yes $A >/dev/null"                          control see
run_case "$D" "env $D=leaky-env-value yes $D >/dev/null"   control see
cleanup; kill_comm "yes" TERM 2>/dev/null; sleep 0.3

echo "-- phase 2: battery under confmask (expect zero sightings)"
run_case "$A" "yes $A >/dev/null"                                mask blind
run_case "$B" "exec yes $B >/dev/null"                           mask blind
run_case "$C" "yes $C >/dev/null & wait"                         mask blind
run_case "$D" "env $D=leaky-env-value yes $D >/dev/null"         mask blind
run_case "$E" "sh -c 'sh -c \"exec yes $E >/dev/null\"'"         mask blind
run_case "$F" "( ( exec yes $F >/dev/null ) & ) ; while :; do sleep 5; done" mask blind
run_case "$G" "for i in 1 2 3 4 5 6 7 8; do yes $G >/dev/null & done; wait"  mask blind
run_case "$H" "i=0; while [ \$i -lt 30 ]; do sh -c true v\$i; i=\$((i+1)); done; exec yes $H >/dev/null" mask blind
cleanup; kill_comm "yes" KILL 2>/dev/null; sleep 0.3

echo "-- phase 2b: liveness proof (processes really run under the mask)"
L="MK${R}L"
PAYLOAD="yes $L >/dev/null" "$TOOL" -q -l mask-liveness /bin/sh -c 'eval "$PAYLOAD"' >/dev/null 2>&1 &
LP=$!
PIDS="$PIDS $LP"
sleep 0.8
alive=$(comm_count mask-liveness)
leakL=$(sightings "$L")
kill -9 $LP 2>/dev/null
kill_comm "yes" KILL 2>/dev/null
if [ "$alive" -ge 1 ] && [ "$leakL" = "0" ]; then
    echo "PASS liveness: $alive process(es) running with the label, marker unseen"
elif [ "$alive" -ge 1 ]; then
    echo "FAIL liveness: running but marker leaked ($leakL)"; OVERALL=1
else
    echo "FAIL liveness: nothing ran under confmask (vacuous pass risk)"; OVERALL=1
fi
sleep 0.3

echo "-- phase 3: functional sanity under confmask"
out=$(echo mask-io-test | "$TOOL" -q -l "$FAKE" /bin/cat 2>/dev/null); rc=$?
if [ "$out" = "mask-io-test" ] && [ "$rc" = "0" ]; then
    echo "PASS functional: stdin/stdout/exit-code intact"
else
    echo "FAIL functional: got [$out] rc=$rc"; OVERALL=1
fi
"$TOOL" -q -l "$FAKE" /bin/sh -c 'exit 42' 2>/dev/null; rc=$?
if [ "$rc" = "42" ]; then echo "PASS functional: exit codes propagate"
else echo "FAIL functional: rc=$rc (want 42)"; OVERALL=1; fi

echo "-- phase 4: the program still sees its own argv/env"
o=$("$TOOL" -q -l "$FAKE" "$CASES" echoargs X1 X2 2>/dev/null)
case "$o" in
    *X1*X2*env=\[ok\]*) echo "PASS argv-fidelity: [$o]" ;;
    *) echo "FAIL argv-fidelity: [$o]"; OVERALL=1 ;;
esac

echo "== VERDICT: $([ $OVERALL = 0 ] && echo ALL-PASS || echo FAILURES) =="
exit $OVERALL

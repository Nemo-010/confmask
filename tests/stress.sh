#!/bin/sh
# Stress / signals / cleanup / race-window probes.
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing"; exit 2; }

FAKE='[kworker/1:2]'
FAIL=0
PIDS=""
RACEFILE=""
RACESWEEP=""
RACESCRIPT=""

finish() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    kill_comm '[kworker/1:2' KILL 2>/dev/null
    kill_comm 'yes' KILL 2>/dev/null
    kill_comm 'sleeper' KILL 2>/dev/null
    kill_comm 'testcases' KILL 2>/dev/null
    [ -n "$RACEFILE" ] && rm -f "$RACEFILE" "$RACESWEEP" "$RACESCRIPT"
}
trap 'finish' EXIT INT TERM

echo "== S1: race-window probe: continuous spawns vs tight /proc observer =="
RACEFILE=/tmp/confmask-sight.$$
RACESWEEP=/tmp/confmask-sweeps.$$
RACESCRIPT=/tmp/confmask-racer.$$
echo 0 > "$RACEFILE"; echo 0 > "$RACESWEEP"
cat > "$RACESCRIPT" <<RS
i=0
while [ \$i -lt 200 ]; do
    ./testcases sleeper RACEMARK &
    sleep 0.01 2>/dev/null || true
    i=\$((i+1))
done
wait
RS
(
    while [ -e "$RACESCRIPT" ]; do
        for d in /proc/[0-9]*; do
            cat $d/cmdline 2>/dev/null | tr '\0' ' ' | grep -qF RACEMARK \
                && echo "LEAK $d" >> "$RACEFILE"
        done
        echo x >> "$RACESWEEP"
    done
) 2>/dev/null &
OB=$!
"$TOOL" -q -l "$FAKE" /bin/sh "$RACESCRIPT" >/dev/null 2>&1 &
V=$!
PIDS="$PIDS $V"
# let it spawn for a while, then reap everything via EXITKILL
sleep 8
alive=$(comm_count '[kworker/1:2')
kill -9 $V 2>/dev/null
rm -f "$RACESCRIPT"
kill $OB 2>/dev/null
sleep 0.5; kill -9 $OB 2>/dev/null
sweeps=$(wc -l < "$RACESWEEP" | tr -d ' ')
leaks=$(grep -c LEAK "$RACEFILE" 2>/dev/null | tr -d ' ')
[ "$leaks" = "0" ] || leaks=$(grep LEAK "$RACEFILE" 2>/dev/null | wc -l | tr -d ' ')
echo "confmask: observer sweeps=$sweeps real-arg sightings=$leaks label-comm-alive=$alive"
if [ "$leaks" = "0" ] && [ "$alive" -ge 100 ]; then echo "PASS s1-race"
else echo "FAIL s1-race (leaks=$leaks alive=$alive sweeps=$sweeps)"; FAIL=1; fi
kill_comm 'testcases' KILL 2>/dev/null
sleep 0.5

echo "== S2: stress: 100 sequential execs, exit codes intact =="
ok=0; bad=0; i=0
while [ $i -lt 100 ]; do
    "$TOOL" -q -l "$FAKE" /bin/sh -c 'exit $1' sh $((i % 7)) 2>/dev/null
    r=$?; exp=$((i % 7))
    if [ "$r" = "$exp" ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "exit mismatch: got $r want $exp"; fi
    i=$((i+1))
done
[ "$bad" = "0" ] && echo "PASS s2-stress ($ok ok)" || { echo "FAIL s2-stress"; FAIL=1; }

echo "== S3: kill -9 the tracer -> no survivors (EXITKILL) =="
# Kernel comm is 15 bytes: the 16-byte label shows up as its first 15.
# Defect caught: comparing the full label never matches, so "no
# survivors" passed for free.  The liveness count before the kill makes
# the comm half non-vacuous.
KILL_LABEL=systemd-tmpfiles
KILL_COMM=$(printf '%s' "$KILL_LABEL" | cut -c1-15)
"$TOOL" -q -l "$KILL_LABEL" /bin/sh -c './testcases sleeper KILL-TEST & ./testcases sleeper KILL-TEST & wait' >/dev/null 2>&1 &
Z=$!
PIDS="$PIDS $Z"
sleep 1
before=$(comm_count "$KILL_COMM")
kill -9 $Z 2>/dev/null
sleep 1.5
left=$(comm_count "$KILL_COMM")
left2=$(sightings KILL-TEST)
if [ "$before" -ge 1 ] && [ "$left" = "0" ] && [ "$left2" = "0" ]; then
    echo "PASS s3-exitkill (labelled before: $before, after: $left)"
else
    echo "FAIL s3-exitkill (labelled before: $before, label survivors: $left, real-arg survivors: $left2)"; FAIL=1
fi
kill_comm "$KILL_COMM" KILL 2>/dev/null
PIDS=""

echo "== S4: SIGTERM passthrough =="
"$TOOL" -q -l "$FAKE" /bin/sh -c 'trap "exit 55" TERM; while :; do sleep 0.05; done' >/dev/null 2>&1 &
Z=$!
PIDS="$PIDS $Z"
sleep 0.8
kill -TERM $Z 2>/dev/null
wait $Z 2>/dev/null
r=$?
[ "$r" = "55" ] && echo "PASS s4-sigterm" || { echo "FAIL s4-sigterm rc=$r"; FAIL=1; }
PIDS=""

echo "== S5: stdin passthrough (multi-line) =="
o=$(printf 'line1\nline2\n' | "$TOOL" -q -l "$FAKE" /bin/cat)
[ "$o" = "line1
line2" ] && echo "PASS s5-stdin" || { echo "FAIL s5-stdin [$o]"; FAIL=1; }

echo "== S6: overhead: 200 execs with/without confmask (wall clock) =="
t0=$(date +%s)
i=0; while [ $i -lt 200 ]; do /bin/sh -c 'true'; i=$((i+1)); done
t1=$(date +%s)
i=0; while [ $i -lt 200 ]; do "$TOOL" -q -l "$FAKE" /bin/sh -c 'true'; i=$((i+1)); done
t2=$(date +%s)
echo "plain=$((t1-t0))s masked=$((t2-t1))s"

echo "== VERDICT: FAIL=$FAIL =="
exit $FAIL

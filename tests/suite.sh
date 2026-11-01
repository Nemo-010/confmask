#!/bin/sh
# Spawn-matrix suite: one case per way a process tree can grow, verified
# against /proc + ps.  Cases are real binaries from ./testcases (and a Go
# binary when a Go toolchain is present).
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing"; exit 2; }

FAKE='[kworker/1:2]'
FAIL=0
PIDS=""

check() {  # name, marker
    name="$1"; marker="$2"
    sleep 0.5
    n=$(sightings "$marker")
    if [ "$n" -gt 0 ]; then
        echo "FAIL $name: $n sighting(s) of '$marker'"
        FAIL=1
    else
        echo "PASS $name: no '$marker' visible"
    fi
}

alive() { # name, expected-min count of label-comm processes
    name="$1"; want="$2"
    n=$(comm_count '[kworker/1:2')
    if [ "$n" -ge "$want" ]; then
        echo "PASS $name-liveness: $n process(es) alive with the label"
    else
        echo "FAIL $name-liveness: only $n alive (want >= $want)"; FAIL=1
    fi
}

launch() { # wrapper: start TOOL under the label in background
    "$TOOL" -q -l "$FAKE" "$@" >/dev/null 2>&1 &
    PIDS="$PIDS $!"
}

finish() {
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    kill_comm '[kworker/1:2' KILL 2>/dev/null
    kill_comm 'sleeper' KILL 2>/dev/null
    kill_comm 'testcases' KILL 2>/dev/null
}
trap 'finish' EXIT INT TERM

echo "== control (no confmask): markers MUST be visible =="
"$CASES" sleeper CTRL-SPAWN-MARK &
CP=$!
sleep 0.4
n=$(sightings CTRL-SPAWN-MARK)
if [ "$n" -ge 1 ]; then echo "PASS control-detects-leaks ($n sightings)"
else echo "FAIL control saw nothing"; FAIL=1; fi
kill -9 $CP 2>/dev/null

echo "== T1: single process =="
launch "$CASES" sleeper MK-T1
sleep 0.8
check t1-cmdline MK-T1
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T2: shell children (sh, &, wait) =="
launch /bin/sh -c "$CASES sleeper MK-T2a & $CASES sleeper MK-T2b & wait"
sleep 1.0
check t2-script-children MK-T2a
check t2-script-children MK-T2b
alive t2 3
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T3: spawns from secondary threads (posix_spawn + system) =="
launch "$CASES" threadspawn "$CASES" MK-T3-THREAD MK-T3-SYSTEM
sleep 1.2
check t3-posix-thread MK-T3-THREAD
check t3-system-thread MK-T3-SYSTEM
alive t3 5
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T4: daemon double-fork (reparented to init) =="
launch "$CASES" daemonspawn "$CASES" MK-T4-DAEMON
sleep 1.2
check t4-daemon MK-T4-DAEMON
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T5: nested shell depth 3 =="
launch /bin/sh -c "/bin/sh -c '/bin/sh -c \"$CASES sleeper MK-T5-DEPTH & wait\"'"
sleep 1.2
check t5-depth3 MK-T5-DEPTH
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T6: vfork + execv =="
launch "$CASES" vforkspawn "$CASES" MK-T6-VFORK
sleep 1.2
check t6-vfork MK-T6-VFORK
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T7: raw clone(2)+execve(2) from threads (Go-runtime path) =="
launch "$CASES" rawspawn "$CASES" MK-T7-RAW
sleep 1.5
check t7-raw-clone MK-T7-RAW
alive t7 5
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

if command -v go >/dev/null 2>&1; then
    echo "== T7b: real Go binary (raw runtime spawns) =="
    if [ ! -x ./gospawn ]; then
        sed "s/MARKERGO/MK-T7B-GO/g" cases/gospawn.go > /tmp/gospawn-$$.go
        CGO_ENABLED=0 go build -o ./gospawn /tmp/gospawn-$$.go 2>/dev/null
        rm -f /tmp/gospawn-$$.go
    fi
    if [ -x ./gospawn ]; then
        launch ./gospawn
        sleep 1.5
        check t7b-go MK-T7B-GO
        kill_comm 'gospawn' KILL 2>/dev/null
        sleep 0.3; PIDS=""
    else
        echo "SKIP t7b-go: go build failed"
    fi
else
    echo "== T7b: skipped (no Go toolchain; raw-clone path covered by T7) =="
fi

echo "== T8: comm redacted (the Name column of top/htop) =="
launch "$CASES" sleeper MK-T8
sleep 0.8
check t8-cmdline MK-T8
n=$(comm_count '[kworker/1:2')
[ "$n" -ge 1 ] && echo "PASS t8-comm: comm '[kworker/1:2]' present ($n)" \
              || { echo "FAIL t8-comm: label comm missing"; FAIL=1; }
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T9: environ redacted, process still works =="
# `env` accepts a name that is not a shell identifier, so the variable
# really reaches the program's environment.  Defect caught: redaction of
# /proc/<pid>/environ broken (marker found), and the launch silently not
# running at all (the control and the exe-based liveness fail).
"$CASES" sleeper MK-T9-CTRLARG &
CP=$!
env 'SECRET-VALUE=MK-T9-CTRL' "$CASES" sleeper MK-T9-CTRLARG2 &
CP2=$!
sleep 1.0
h=$(environ_hits MK-T9-CTRL)
if [ "$h" -ge 1 ]; then echo "PASS t9-control-environ-detectable ($h environ hit(s) without confmask)"
else echo "FAIL t9-control: environ marker not visible without confmask"; FAIL=1; fi
kill -9 $CP $CP2 2>/dev/null
# the trailing true keeps sh alive as a parent, so two labelled processes exist
launch /bin/sh -c "env 'SECRET-VALUE=MK-T9-ENV' $CASES sleeper MK-T9-ARG; true"
n=$(wait_comm_exe '[kworker/1:2' testcases 1 10)
if [ "$n" -ge 1 ]; then echo "PASS t9-liveness: $n testcases process(es) alive with the label"
else echo "FAIL t9-liveness: the sleeper never ran under the label"; FAIL=1; fi
alive t9 2
h=$(environ_hits MK-T9-ENV)
if [ "$h" = 0 ]; then echo "PASS t9-environ: no MK-T9-ENV in any environ"
else echo "FAIL t9-environ: $h process(es) expose MK-T9-ENV"; FAIL=1; fi
check t9-cmdline MK-T9-ARG
kill_comm 'testcases' KILL 2>/dev/null; sleep 0.3; PIDS=""

echo "== T10: exit code passthrough =="
"$TOOL" -q -l "$FAKE" /bin/sh -c 'exit 42' 2>/dev/null
rc=$?
if [ "$rc" = "42" ]; then echo "PASS t10-exitcode"
else echo "FAIL t10-exitcode rc=$rc"; FAIL=1; fi

echo "== T11: stdout/stdin passthrough =="
o=$(echo hello-marker | "$TOOL" -q -l "$FAKE" /bin/cat)
if [ "$o" = "hello-marker" ]; then echo "PASS t11-stdio"
else echo "FAIL t11-stdio [$o]"; FAIL=1; fi

echo "== T12: program sees its own argv =="
o=$("$TOOL" -q -l "$FAKE" "$CASES" echoargs A1 A2 2>/dev/null)
case "$o" in
    *A1*A2*) echo "PASS t12-argv: [$o]" ;;
    *) echo "FAIL t12-argv: [$o]"; FAIL=1 ;;
esac

echo "== VERDICT: FAIL=$FAIL =="
exit $FAIL

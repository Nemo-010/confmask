#!/bin/sh
# ============================================================================
# confmaskd negative protocol suite.  Every case drives the daemon with a
# deliberately bad request and then checks that the daemon (a) answered
# with a refusal where a refusal is due, and (b) still serves a valid
# job afterwards.  A crash, a hang or a silently accepted bad frame fails
# the case.
#
#   N1  socket mode is 0600
#   N2  bad magic is refused, daemon survives
#   N3  bad protocol version is refused, daemon survives
#   N4  the old 1-byte banner is refused with a protocol message
#   N5  argc above the limit is refused
#   N6  one argument above 1 MiB is refused
#   N7  a request whose arguments exceed the budget is refused
#   N8  an 8 MiB label is refused
#   N9  a NUL in the label is refused
#   N10 a truncated frame is dropped, daemon survives
#   N11 connect-and-close does not disturb the daemon
#   N12 zero descriptors is refused with a message naming three
#   N13 five descriptors is refused (MSG_CTRUNC)
#   N14 a stalled client is dropped after --io-timeout and the daemon serves
#   N15 a symlink at the socket path makes the daemon refuse to start
#   N16 a plain file at the socket path makes the daemon refuse to start
#   N17 a second daemon does not steal a live socket
#   N18 a stale socket after SIGKILL is replaced
#   N19 a job whose master exits while a double-forked grandchild
#       lives does not wedge the daemon
#   N20 a daemonizing job does not hold the client's pipes open
#   N21 --no-inherit-env jobs see the env-file only
#   N22 a label-less client gets the daemon label
#   N23 a newline label is refused
#   N24 --job-timeout kills a hung job and returns 137
#   N25 an unauthorised uid is refused (root only)
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

DAEMON="$BIN_DIR/confmaskd"
PROTO="$BIN_DIR/protocases"
[ -x "$PROTO" ] || { echo "SKIP daemon_neg (protocases missing)"; echo "== VERDICT: FAIL=0 SKIP =="; exit 0; }

D=/tmp/confmask-neg.$$
mkdir -p "$D"
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

DPID=""
DAEMON_PIDS=""
cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    # every daemon this suite started, not only the last one: a daemon
    # left running outlives the suite and the pass, and later suites
    # then observe it
    for p in $DAEMON_PIDS; do kill -9 "$p" 2>/dev/null; done
    for p in "$D"/pid.*; do
        [ -f "$p" ] && kill -9 "$(cat "$p")" 2>/dev/null
    done
    kill_comm cm-neg KILL 2>/dev/null
    kill_comm sleeper KILL 2>/dev/null
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

# start_daemon NAME [extra options...]  -> sets SOCK and DPID
# Stops the previous daemon first: one live daemon per suite.
start_daemon() {
    sd_name="$1"; shift
    stop_daemon
    SOCK="$D/$sd_name.sock"
    "$DAEMON" -q -S "$SOCK" "$@" 2>"$D/$sd_name.err" &
    DPID=$!
    DAEMON_PIDS="$DAEMON_PIDS $DPID"
    sdi=0
    while [ ! -S "$SOCK" ] && [ "$sdi" -lt 100 ]; do
        kill -0 "$DPID" 2>/dev/null || break
        sleep 0.1
        sdi=$((sdi + 1))
    done
    [ -S "$SOCK" ]
}

stop_daemon() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    wait "$DPID" 2>/dev/null
    DPID=""
}

# alive NAME: a valid request still runs a job
serves() {
    sa=$("$TOOL" --daemon "$SOCK" --label cm-neg -- /bin/sh -c 'echo alive' 2>/dev/null)
    [ "$sa" = "alive" ]
}
check_alive() {  # case-name
    if serves; then
        pass "$1-daemon-survives"
    else
        fail "$1-daemon-survives (a valid job after the bad frame failed)"
    fi
}

# --------------------------------------------------------------- N1
# wait_gone PID SECONDS: 0 when the process exited or is a zombie.
# A fixed sleep is not evidence under TCG; poll the observable state.
wait_gone() {
    wg_p="$1"; wg_max=$(( $2 * 10 )); wg_i=0
    while [ "$wg_i" -lt "$wg_max" ]; do
        wg_st=$(sed -n 's/.*) \([A-Za-z]\).*/\1/p' "/proc/$wg_p/stat" 2>/dev/null)
        [ -z "$wg_st" ] && return 0
        [ "$wg_st" = "Z" ] && return 0
        sleep 0.1
        wg_i=$((wg_i + 1))
    done
    return 1
}

# wait_pid PID SECONDS: wait for a background client to exit.  A zombie
# counts as exited (kill -0 keeps succeeding on one).  Sets WP_RC to the
# exit status, or 124 when the wait timed out.
wait_pid() {
    wp_p="$1"; wp_max=$(( $2 * 10 )); wp_i=0
    while [ "$wp_i" -lt "$wp_max" ]; do
        wp_st=$(sed -n 's/.*) \([A-Za-z]\).*/\1/p' "/proc/$wp_p/stat" 2>/dev/null)
        [ -z "$wp_st" ] && break
        [ "$wp_st" = "Z" ] && break
        sleep 0.1
        wp_i=$((wp_i + 1))
    done
    if [ "$wp_i" -ge "$wp_max" ]; then
        WP_RC=124
        return 1
    fi
    wait "$wp_p" 2>/dev/null
    WP_RC=$?
    return 0
}

if start_daemon sock; then
    m=$(ls -l "$SOCK" 2>/dev/null | cut -c1-10)
    ch=$(ls -ld "$SOCK" 2>/dev/null | sed 's/^\(..........\).*/\1/')
    mode=$(stat -c %a "$SOCK" 2>/dev/null)
    [ "$mode" = "600" ] && pass "n1-socket-mode-600 ($mode)" \
        || fail "n1-socket-mode (mode=$mode, want 600)"
else
    fail "n1-daemon-start ($(cat "$D/sock.err" 2>/dev/null | tr '\n' ' '))"
fi

# ------------------------------------------------------- N2..N14 frames
# run_bad CASE EXPECT-SUBCOMMAND [ARGS...]
# protocases takes SUBCOMMAND SOCKET [ARGS...], so the socket goes
# directly after the subcommand and never at the end.
run_bad() {  # case, expect-substring, subcommand, [args...]
    rb_case="$1"; shift
    rb_want="$1"; shift
    rb_sub="$1"; shift
    out=$("$PROTO" "$rb_sub" "$SOCK" "$@" 2>&1)
    rc=$?
    case "$out" in
        *"$rb_want"*) pass "$rb_case ($(printf '%s' "$out" | cut -c1-90))" ;;
        *) fail "$rb_case (rc=$rc out=$(printf '%s' "$out" | cut -c1-120))" ;;
    esac
}

run_bad n2-bad-magic "bad magic" bad-magic
check_alive n2
run_bad n3-bad-version "version" bad-version 9
check_alive n3
# the old 1-byte banner gets its own message: it names protocol 1
run_bad n4-old-banner "protocol 1" bad-version old
check_alive n4
run_bad n5-argc-too-large "argc" argc-4097
check_alive n5
run_bad n6-argument-too-large "argument" arg-over-1mib
check_alive n6
# the argv sum is capped, not the request size: the refusal names the
# job arguments
run_bad n7-request-too-large "job arguments" argv-sum-over
check_alive n7
run_bad n8-label-too-large "label" label-huge
check_alive n8
run_bad n9-label-nul "label" label-hex 610062
check_alive n9
out=$("$PROTO" truncated-frame "$SOCK" 2>&1)
case "$out" in
    *"response"*|*"no-response"*) pass "n10-truncated-frame ($(printf '%s' "$out" | cut -c1-70))" ;;
    *) fail "n10-truncated-frame (out=$out)" ;;
esac
check_alive n10
# the client prints "closed" for this case, not a response line
out=$("$PROTO" connect-and-close "$SOCK" 2>&1)
case "$out" in
    *"closed"*|*"no-response"*|*"response"*) pass "n11-connect-and-close ($(printf '%s' "$out" | cut -c1-40))" ;;
    *) fail "n11-connect-and-close (out=$out)" ;;
esac
check_alive n11
run_bad n12-zero-fds "exactly 3 file descriptors" fds 0
check_alive n12
run_bad n13-five-fds "too many file descriptors" fds 5
check_alive n13

# N14: a stalled client is dropped.  Measure the wait; the daemon was
# started with the default 30 s timeout, so start a second one with 2 s.
start_daemon io --io-timeout 2 || fail "n14-daemon-start"
t0=$(date +%s)
out=$("$PROTO" stall "$SOCK" 2>&1)
rc=$?
t1=$(date +%s)
d=$((t1 - t0))
if [ "$d" -ge 2 ] && [ "$d" -le 20 ]; then
    pass "n14-stalled-client-dropped (${d}s, rc=$rc, $(printf '%s' "$out" | cut -c1-60))"
else
    fail "n14-stalled-client (${d}s, rc=$rc, out=$(printf '%s' "$out" | cut -c1-120))"
fi
check_alive n14
stop_daemon

# ------------------------------------------------- N15..N18 socket paths
sl="$D/symlink.sock"
ln -s "$D/target-dir" "$sl"
"$DAEMON" -q -S "$sl" 2>"$D/n15.err" &
p15=$!
if wait_gone "$p15" 10; then
    if grep -qi "symbolic link\|not a socket\|refus" "$D/n15.err"; then
        pass "n15-symlink-refused ($(head -1 "$D/n15.err" | cut -c1-100))"
    else
        fail "n15-symlink-refused (no named error: $(head -1 "$D/n15.err" | cut -c1-100))"
    fi
else
    fail "n15-symlink-refused (the daemon kept running)"
    kill -9 "$p15" 2>/dev/null
fi

pf="$D/plain.sock"
: > "$pf"
"$DAEMON" -q -S "$pf" 2>"$D/n16.err" &
p16=$!
if wait_gone "$p16" 10; then
    grep -qi "socket\|refus" "$D/n16.err" \
        && pass "n16-plain-file-refused ($(head -1 "$D/n16.err" | cut -c1-100))" \
        || fail "n16-plain-file-refused (no named error: $(head -1 "$D/n16.err" | cut -c1-100))"
else
    fail "n16-plain-file-refused (the daemon kept running)"
    kill -9 "$p16" 2>/dev/null
fi

start_daemon live || fail "n17-first-daemon-start"
"$DAEMON" -q -S "$SOCK" 2>"$D/n17.err" &
p17=$!
if wait_gone "$p17" 10; then
    grep -qi "already\|live\|refus" "$D/n17.err" \
        && pass "n17-live-socket-not-stolen ($(head -1 "$D/n17.err" | cut -c1-100))" \
        || fail "n17-live-socket-not-stolen (no named error: $(head -1 "$D/n17.err" | cut -c1-100))"
else
    fail "n17-live-socket-not-stolen (the second daemon started)"
    kill -9 "$p17" 2>/dev/null
fi
check_alive n17
kill -9 "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null
DPID=""
sleep 0.3
"$DAEMON" -q -S "$SOCK" 2>"$D/n18.err" &
p18=$!
n18_i=0
while [ "$n18_i" -lt 100 ]; do
    if ! kill -0 "$p18" 2>/dev/null; then
        break
    fi
    [ -S "$SOCK" ] && break
    sleep 0.1
    n18_i=$((n18_i + 1))
done
if kill -0 "$p18" 2>/dev/null && [ -S "$SOCK" ]; then
    pass "n18-stale-socket-replaced"
else
    fail "n18-stale-socket (daemon did not start on a stale path: $(head -1 "$D/n18.err" | cut -c1-100))"
fi
kill -9 "$p18" 2>/dev/null
wait "$p18" 2>/dev/null

# ------------------------------------------------------- N19, N20 jobs
# Both cases use a job whose master exits while a double-forked
# grandchild keeps running and holds the job's stdio.  The client is run
# in the background with its stdio on /dev/null and the wait for it is
# bounded, so a daemon that wedges on the job fails the case instead of
# hanging the suite.
start_daemon jobs || fail "n19-daemon-start"
"$TOOL" --daemon "$SOCK" --label cm-neg -- /bin/sh -c \
    "$CASES daemonspawn $CASES cm-neg-marker & exit 0" \
    >/dev/null 2>&1 </dev/null &
c19=$!
if wait_pid "$c19" 20 && [ "$WP_RC" = 0 ]; then
    pass "n19-double-fork-job-keeps-daemon (client rc=$WP_RC)"
else
    fail "n19-double-fork-job (rc=$WP_RC, the client did not return: the daemon wedges on the job)"
    kill -9 "$c19" 2>/dev/null
fi
if serves; then
    pass "n19-daemon-survives"
else
    fail "n19-daemon-survives (a valid job after the double-fork job failed)"
fi
kill_comm cm-neg KILL 2>/dev/null

# N20: the job closes 0,1,2 and keeps running in the background; the
# client must still return instead of waiting for the pipes to close.
t0=$(date +%s)
"$TOOL" --daemon "$SOCK" --label cm-neg -- /bin/sh -c \
    "$CASES daemonspawn $CASES cm-neg-marker >/dev/null 2>&1 </dev/null & exit 0" \
    >/dev/null 2>&1 </dev/null &
c20=$!
if wait_pid "$c20" 20; then
    t1=$(date +%s)
    d=$((t1 - t0))
    if [ "$d" -le 15 ] && [ "$WP_RC" = 0 ]; then
        pass "n20-daemonizing-job-releases-client (${d}s, rc=$WP_RC)"
    else
        fail "n20-daemonizing-job (${d}s, rc=$WP_RC)"
    fi
else
    fail "n20-daemonizing-job (client still running after 20s: it waits for the job's pipes)"
    kill -9 "$c20" 2>/dev/null
fi
kill_comm cm-neg KILL 2>/dev/null
stop_daemon

# --------------------------------------------- N21: --no-inherit-env
printf 'NEG_ONLY=value-from-file\n' > "$D/envf"
chmod 600 "$D/envf"
start_daemon noenv --no-inherit-env -e "$D/envf" || fail "n21-daemon-start"
out=$("$TOOL" --daemon "$SOCK" --label cm-neg -- "$CASES" getenv NEG_ONLY 2>&1)
case "$out" in
    NEG_ONLY=value-from-file*) pass "n21-env-file-reaches-job ($out)" ;;
    *) fail "n21-env-file (got '$out')" ;;
esac
out=$("$TOOL" --daemon "$SOCK" --label cm-neg -- "$CASES" getenv NEG_ABSENT 2>&1)
case "$out" in
    *unset*) pass "n21-no-inherit-env (absent variable is unset)" ;;
    *) fail "n21-no-inherit-env (got '$out')" ;;
esac
# control: the same variable is inherited when the flag is off.  The
# variable must be in the DAEMON's environment: a client never forwards
# its own environment to the daemon.
stop_daemon
NEG_INHERIT=inherited
export NEG_INHERIT
start_daemon inherit -e "$D/envf" || fail "n21b-daemon-start"
out=$("$TOOL" --daemon "$SOCK" --label cm-neg -- "$CASES" getenv NEG_INHERIT 2>&1)
unset NEG_INHERIT
case "$out" in
    NEG_INHERIT=inherited*) pass "n21-control-inherit-env (default inherits)" ;;
    *) fail "n21-control-inherit-env (got '$out')" ;;
esac
stop_daemon

# kill_job_tracees PREFIX: SIGKILL the masked tracees of a running job.
# The label is the comm of the daemon, the job supervisor and every
# tracee, so a comm sweep would kill the daemon this case still needs.
# The tracees are the ones whose exe is the test probe.
kill_job_tracees() {
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$1"*)
                case "$(readlink "$d/exe" 2>/dev/null)" in
                    */testcases) kill -9 "${d#/proc/}" 2>/dev/null ;;
                esac
                ;;
        esac
    done
}

# ------------------------------------------------ N22, N23 label rules
start_daemon label -l cm-neg-label || fail "n22-daemon-start"
"$TOOL" --daemon "$SOCK" -- "$CASES" sleeper >/dev/null 2>&1 &
c22=$!
sleep 0.8
found=0
for d in /proc/[0-9]*; do
    c=$(cat "$d/comm" 2>/dev/null)
    [ "$c" = "cm-neg-label" ] && found=$((found + 1))
done
if [ "$found" -ge 2 ]; then
    pass "n22-label-less-client-gets-daemon-label ($found processes)"
else
    fail "n22-label-less-client (comm 'cm-neg-label' in $found processes, want supervisor and job)"
fi
kill -9 "$c22" 2>/dev/null
kill_job_tracees cm-neg-label
out=$("$PROTO" label-hex "$SOCK" 6e65770a)  # "new\n"
case "$out" in
    *"label"*) pass "n23-newline-label-refused ($(printf '%s' "$out" | cut -c1-80))" ;;
    *) fail "n23-newline-label (out=$(printf '%s' "$out" | cut -c1-100))" ;;
esac
check_alive n23
stop_daemon

# ------------------------------------------------------ N24 job timeout
start_daemon jt --job-timeout 2 || fail "n24-daemon-start"
t0=$(date +%s)
out=$("$TOOL" --daemon "$SOCK" --label cm-neg -- /bin/sh -c 'sleep 30' 2>&1)
rc=$?
t1=$(date +%s)
d=$((t1 - t0))
if [ "$d" -le 15 ] && { [ "$rc" = 137 ] || [ "$rc" = 124 ] || [ "$rc" = 9 ]; }; then
    pass "n24-job-timeout (${d}s, rc=$rc)"
else
    fail "n24-job-timeout (${d}s, rc=$rc, out=$(printf '%s' "$out" | cut -c1-80))"
fi
check_alive n24
stop_daemon

# ------------------------------------------------ N25 unauthorised uid
if [ "$(id -u)" = 0 ]; then
    # The socket is 0600 by default, which keeps another uid out before
    # the peer check ever runs.  Open the mode so the refusal under
    # test is the authorisation, not the file permission.
    start_daemon auth --socket-mode 666 || fail "n25-daemon-start"
    out=$("$PROTO" as-uid 1000 "$SOCK" /bin/true 2>&1)
    case "$out" in
        *"not allowed"*) pass "n25-unauthorised-uid-refused ($(printf '%s' "$out" | cut -c1-70))" ;;
        *) fail "n25-unauthorised-uid (out=$(printf '%s' "$out" | cut -c1-100))" ;;
    esac
    check_alive n25
    stop_daemon
else
    skip "n25-unauthorised-uid (needs root to switch to uid 1000)"
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]

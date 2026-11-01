#!/bin/sh
# ============================================================================
# confmask edge cases -- behaviours the main battery does not reach.
#
# Each case here pins a specific defect that was found and fixed, so a
# regression fails loudly instead of silently degrading redaction:
#
#   E1  exec failure exits 127/126, does not hang
#   E2  a non-UTF-8 argument reaches the program byte for byte
#   E3  ELF detection resolves a relative path against the TRACEE's cwd
#       (after a chdir inside the tree), so the entry swap still happens
#   E4  a label longer than the 255-byte scratch still runs and is cut
#   E5  a large argv is forwarded intact and still redacted
#   E6  the supervisor masks its own /proc entry
#   E7  -l- / -a- mean a blank label; --label=- is the literal '-'
#   E8  a missing option value names the flag that was used
#   E9  an executable #! script: zero sightings, liveness, argv fidelity,
#       post-exec fallback log line
#   E10 --keep-env visible vs default redacted environ
#   E11 --no-follow: direct child redacted, grandchild visible and working
#   E12 --no-exit-kill: tree survives the supervisor (default: it dies)
#   E13 --label-empty: blank comm, empty cmdline
#   E14 no label given: cmdline is the program name, arguments stripped
#   E15 execveat and fexecve (skipped while testcases lacks the subcommands)
#   E16 two chained execs keep arguments and exit code
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAKE='[kworker/1:2-rcu_gp]'
FAKE15=$(printf '%s' "$FAKE" | cut -c1-15)   # kernel comm is 15 bytes
ROOT=$(cd .. && pwd)
FAIL=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

# ---------------------------------------------------------------- E1: exec
"$TOOL" -q -l "$FAKE" /nonexistent/confmask-probe >/dev/null 2>&1
rc=$?
[ "$rc" = 127 ] && pass e1-missing-binary-exits-127 \
    || fail "e1-missing-binary (rc=$rc, want 127)"

printf '#!/bin/sh\nexit 0\n' > /tmp/notexec.$$
chmod 644 /tmp/notexec.$$
"$TOOL" -q -l "$FAKE" /tmp/notexec.$$ >/dev/null 2>&1
rc=$?
rm -f /tmp/notexec.$$
[ "$rc" = 126 ] && pass e1-not-executable-exits-126 \
    || fail "e1-not-executable (rc=$rc, want 126)"

# ---------------------------------------------- E2: non-UTF-8 argument
BAD=$(printf 'a\377b')
out=$("$TOOL" -q -l "$FAKE" "$CASES" echoargsraw "$BAD" 2>/dev/null)
case "$out" in
    *arg2=61ff62*) pass e2-non-utf8-argv-forwarded ;;
    *) fail "e2-non-utf8-argv (want arg2=61ff62, got: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160))" ;;
esac

# ---------------------------------------- E3: tracee-relative ELF path
# A subshell chdirs to ROOT and then execs ./tests/testcases as its
# FIRST exec, while the tracer is still in the tests directory.  (A plain
# `exec` here would be a re-exec of an already-settled process, which is
# post-exec by design and would prove nothing.)  Resolving the path
# against the tracer's cwd would miss the binary and silently fall back
# to post-exec redaction.
# `; true` after the command stops the shell from exec-optimising it
# away, so a forked child performs the exec as its first exec.
log=$("$TOOL" -v -l "$FAKE" /bin/sh -c "cd '$ROOT'; ./tests/testcases echoargs X; true" 2>&1)
nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
nscript=$(printf '%s\n' "$log" | grep -c 'script/unknown exec')
if [ "$nswap" -ge 2 ] && [ "$nscript" = 0 ]; then
    pass "e3-tracee-cwd-elf (entry-swaps=$nswap)"
else
    fail "e3-tracee-cwd-elf (entry-swaps=$nswap script-fallbacks=$nscript, want >=2 and 0): $(printf '%s' "$log" | grep -E 'entry pointer-swap|script/unknown|exec-done' | head -4 | tr '\n' '|')"
fi

# ------------------------------------------------- E4: oversized label
LONG=$(head -c 300 /dev/zero 2>/dev/null | tr '\0' 'x')
[ -n "$LONG" ] || LONG="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"$TOOL" -q -l "$LONG" "$CASES" echoargs ok >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && pass e4-long-label-runs \
    || fail "e4-long-label (rc=$rc, want 0)"

# ------------------------------------------------ E5: large argv
set -- 
i=0
while [ "$i" -lt 500 ]; do
    set -- "$@" "MK-E5-${i}-XXXXXXXX"
    i=$((i + 1))
done
out=$("$TOOL" -q -l "$FAKE" "$CASES" echoargs "$@" 2>/dev/null)
case "$out" in
    *arg501=*) pass e5-large-argv-forwarded ;;
    *) fail "e5-large-argv (last argument missing from the program's own view)" ;;
esac

# ------------------------------------------------ E6: supervisor self-mask
# Zeroing does not shrink the arg region, so a size test would be
# vacuous: assert on content.  The supervisor writes the label into the
# zeroed argv block, so its cmdline reads back as exactly the label and
# never as the program path or an argument.
visible_cmdline() {  # pid -> non-NUL text of its cmdline
    cat "/proc/$1/cmdline" 2>/dev/null | tr -d '\000'
}
proc_state() {  # pid -> one-letter process state (Z = zombie)
    sed -n 's/.*) \([A-Za-z]\).*/\1/p' "/proc/$1/stat" 2>/dev/null
}
# The shapes a REAL argv takes: the probe binary by name, and the
# supervisor as a command (its path or its name, then a flag).  A masked
# label that happens to contain the word confmask, such as the daemon
# default label "confmask-job", is not a leak and must not match.
real_argv_shapes() {  # text -> 0 when the text is a real argv of this tree
    case "$1" in
        *testcases*) return 0 ;;
        */confmask\ *|confmask\ *) return 0 ;;
    esac
    return 1
}

# control: without confmask the probe's own name IS in a cmdline
"$CASES" sleeper >/dev/null 2>&1 &
CTL_PID=$!
sleep 0.3
ctl=0
for d in /proc/[0-9]*; do
    case "$(visible_cmdline "${d#/proc/}")" in
        *testcases*) ctl=1; break ;;
    esac
done
kill "$CTL_PID" 2>/dev/null
# reap the control before the masked run scans: a SIGTERM in flight is
# not a dead process, and its argv names the probe
wait "$CTL_PID" 2>/dev/null
[ "$ctl" = 1 ] && pass e6-control-cmdline-detectable \
    || fail "e6-control (the observer cannot see an unmasked cmdline)"

"$TOOL" -q -l "$FAKE" "$CASES" sleeper >/dev/null 2>&1 &
SELF_PID=$!
# Wait for the observable condition, not a fixed sleep: the kernel
# publishes the supervisor's real argv until the supervisor zeroes the
# block, and that window is not closable from inside the process.
e6_i=0
while [ "$e6_i" -lt 60 ]; do
    [ "$(visible_cmdline "$SELF_PID")" = "$FAKE" ] && break
    kill -0 "$SELF_PID" 2>/dev/null || break
    sleep 0.1
    e6_i=$((e6_i + 1))
done
leak=0
selfmasked=0
leakers=""
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    txt=$(visible_cmdline "$pid")
    if real_argv_shapes "$txt"; then
        leak=1
        leakers="$leakers $pid:[$(cat "$d/comm" 2>/dev/null)][$txt]"
    fi
    c=$(cat "$d/comm" 2>/dev/null) || continue
    [ "$c" = "$FAKE15" ] || continue
    # a zombie has no mm and therefore an empty cmdline: not evidence
    [ "$(proc_state "$pid")" = "Z" ] && continue
    # the label is what the supervisor publishes in place of its argv
    if [ "$txt" = "$FAKE" ]; then
        selfmasked=1
    fi
done
if [ "$leak" = 0 ] && [ "$selfmasked" = 1 ]; then
    pass e6-supervisor-selfmask
else
    fail "e6-supervisor-selfmask (leak=$leak selfmasked=$selfmasked leakers:$leakers)"
fi
kill "$SELF_PID" 2>/dev/null

# ------------------------------------------------------ E7: label forms
# Every spelling of the blank label must produce a blank comm for the
# supervisor and for the tracee: the supervisor masks its own comm, and
# the tracee's comm is set at the exec completion stop.
# Catches: '-l-' and '--label=-' diverging, or a blank label rendering
# as something else.
blank_tracees() {  # pid-of-supervisor -> live tracees with a one-space comm
    bt=0
    for d in /proc/[0-9]*; do
        [ "${d#/proc/}" = "$1" ] && continue
        [ "$(cat "$d/comm" 2>/dev/null)" = " " ] || continue
        # a zombie has no mm: its comm survives but it is not a running
        # masked process
        [ "$(proc_state "${d#/proc/}")" = "Z" ] && continue
        bt=$((bt + 1))
    done
    echo "$bt"
}
await_blank() {  # pid-of-supervisor -> count, waiting up to 4s for one
    ab=0
    abi=0
    while [ "$abi" -lt 40 ]; do
        ab=$(blank_tracees "$1")
        [ "$ab" -ge 1 ] && break
        sleep 0.1
        abi=$((abi + 1))
    done
    echo "$ab"
}
for form in "-l-" "--label=-" "-l -" "--label -"; do
    # shellcheck disable=SC2086
    "$TOOL" -q $form "$CASES" sleeper >/dev/null 2>&1 &
    P=$!
    n=$(await_blank "$P")
    sc=$(cat "/proc/$P/comm" 2>/dev/null)
    kill "$P" 2>/dev/null
    if [ "$sc" = " " ] && [ "$n" -ge 1 ]; then
        pass "e7-blank-label [$form] (supervisor comm blank, $n tracee(s) blank)"
    else
        fail "e7-blank-label [$form] (supervisor comm=[$sc] tracees=$n, want ' ' and >= 1)"
    fi
    sleep 0.2
done

# ------------------------------------------- E8: missing value names flag
msg=$("$TOOL" -a 2>&1)
rc=$?
case "$msg" in
    *"-a needs a value"*) pass e8-missing-value-names-flag ;;
    *) fail "e8-missing-value (rc=$rc, msg did not name -a)" ;;
esac

# ======================================================================
# Cases E9 to E17.  Shared helpers first.
# ======================================================================

# labelled_tracees COMM-PREFIX: labelled processes that are not the
# supervisor (exe names confmask) and not zombies (exe unreadable).
labelled_tracees() {
    p="$1"; n=0
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            "$p"*)
                exe=$(readlink "$d/exe" 2>/dev/null)
                case "$exe" in
                    "") ;;
                    */confmask) ;;
                    *) n=$((n + 1)) ;;
                esac
                ;;
        esac
    done
    echo "$n"
}

# wait_labelled COMM-PREFIX WANT SECONDS: poll labelled_tracees.
wait_labelled() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $3 ))
    while :; do
        n=$(labelled_tracees "$1")
        [ "$n" -ge "$2" ] && break
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && break
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$n"
}

# wait_file FILE SECONDS: poll until FILE exists and is not empty.
wait_file() {
    end=$(( $(date +%s 2>/dev/null || echo 0) + $2 ))
    while :; do
        [ -s "$1" ] && return 0
        now=$(date +%s 2>/dev/null || echo 99999999999)
        [ "$now" -ge "$end" ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
}

# stop_tree SUPERVISOR-PID COMM-PREFIX...: SIGKILL the supervisor (the
# default EXITKILL takes the tree) and sweep the labelled leftovers.
stop_tree() {
    sp="$1"; shift
    kill -9 "$sp" 2>/dev/null
    wait "$sp" 2>/dev/null
    for cp in "$@"; do kill_comm "$cp" KILL 2>/dev/null; done
    sleep 0.2
}

# ------------------------------------------- E9: executable #! script
# The whole State::Script path: the kernel copies the real interpreter
# line, the post-exec completion stop zeroes it.
# Defects caught: script argv left visible (sightings > 0); the script not
# running (no output file, no liveness); argv changed on the way through
# the interpreter (argv fidelity); the script exec taking the ELF swap or
# losing the fallback log line.
E9_SCRIPT=/tmp/mk-e9-script.$$
E9_OUT=/tmp/mk-e9-out.$$
E9_LOG=/tmp/mk-e9-log.$$
cat > "$E9_SCRIPT" <<EOS
#!/bin/sh
printf '0=%s\nn=%s\n' "\$0" "\$#" > "$E9_OUT"
for a in "\$@"; do printf 'arg=%s\n' "\$a" >> "$E9_OUT"; done
while :; do sleep 1; done
EOS
chmod 755 "$E9_SCRIPT"
rm -f "$E9_OUT" "$E9_LOG"

"$E9_SCRIPT" MK-E9-ARG "two words" >/dev/null 2>&1 &
CTL=$!
wait_file "$E9_OUT" 15
sleep 0.3
n=$(sightings MK-E9-ARG)
kill -9 "$CTL" 2>/dev/null; wait "$CTL" 2>/dev/null
kill_comm sleep KILL 2>/dev/null
[ "$n" -ge 1 ] && pass "e9-control-script-argv-detectable ($n sightings)" \
    || fail "e9-control (script argument not visible without confmask)"
rm -f "$E9_OUT"

"$TOOL" -v -l mk-e9-label "$E9_SCRIPT" MK-E9-ARG "two words" >/dev/null 2>"$E9_LOG" &
E9_PID=$!
if wait_file "$E9_OUT" 20; then
    n=$(wait_labelled mk-e9-label 1 10)
    sleep 0.5
    s=$(sightings MK-E9-ARG)
    [ "$s" = 0 ] && pass e9-script-zero-sightings \
        || fail "e9-script-zero-sightings ($s sighting(s) of the script argument)"
    [ "$n" -ge 1 ] && pass "e9-script-liveness ($n labelled process(es))" \
        || fail "e9-script-liveness (no labelled process; the script is not running under the label)"
    want="0=$E9_SCRIPT
n=2
arg=MK-E9-ARG
arg=two words"
    got=$(cat "$E9_OUT")
    [ "$got" = "$want" ] && pass e9-script-argv-fidelity \
        || fail "e9-script-argv-fidelity (got: $(printf '%s' "$got" | tr '\n' '|'))"
else
    fail "e9-script-ran (the script wrote no output within 20 s)"
fi
stop_tree "$E9_PID" mk-e9-label sleep
nfall=$(grep -c 'script/unknown exec, post-exec mode' "$E9_LOG")
[ "$nfall" -ge 1 ] && pass "e9-script-fallback-log (lines=$nfall)" \
    || fail "e9-script-fallback-log (no 'script/unknown exec, post-exec mode' line): $(head -c 300 "$E9_LOG" | tr '\n' '|')"
rm -f "$E9_SCRIPT" "$E9_OUT" "$E9_LOG"

# ------------------------------------- shared control for E10 to E16
"$CASES" sleeper MK-E-CTRL >/dev/null 2>&1 &
CTL=$!
sleep 0.5
n=$(sightings MK-E-CTRL)
kill -9 "$CTL" 2>/dev/null; wait "$CTL" 2>/dev/null
[ "$n" -ge 1 ] && pass "e-control-argv-detectable ($n sightings)" \
    || fail "e-control (the observer cannot see an unmasked sleeper argument)"

# ------------------------------------------------------ E10: --keep-env
# Defects caught: --keep-env ignored (the visible run finds nothing);
# redaction of environ broken in the default mode (the hidden run finds
# the value).  The --keep-env run is also the detector control for the
# default run.
"$TOOL" -q --keep-env -l mk-e10-keep env MK_E10_VAR=MK-E10-VISIBLE "$CASES" sleeper >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe mk-e10-keep testcases 1 15)
hits=$(environ_hits MK-E10-VISIBLE)
stop_tree "$P" mk-e10-keep
[ "$n" -ge 1 ] && [ "$hits" -ge 1 ] && pass "e10-keep-env-visible (hits=$hits)" \
    || fail "e10-keep-env-visible (alive=$n hits=$hits, want >=1 and >=1)"

"$TOOL" -q -l mk-e10-hide env MK_E10_VAR=MK-E10-HIDDEN "$CASES" sleeper >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe mk-e10-hide testcases 1 15)
sleep 0.3
hits=$(environ_hits MK-E10-HIDDEN)
stop_tree "$P" mk-e10-hide
[ "$n" -ge 1 ] && [ "$hits" = 0 ] && pass "e10-default-environ-redacted (alive=$n)" \
    || fail "e10-default-environ-redacted (alive=$n hits=$hits, want >=1 and 0)"

# ----------------------------------------------------- E11: --no-follow
# Defects caught: --no-follow ignored (the grandchild is redacted, so its
# marker is not visible); the direct child left unredacted (the parent
# marker is visible); a grandchild that stopped working.
E11_OUT=/tmp/mk-e11-out.$$
rm -f "$E11_OUT"
"$TOOL" -q --no-follow -l mk-e11-only /bin/sh -c ": MK-E11-PARENT; $CASES echoargs G1 G2 > $E11_OUT; $CASES sleeper MK-E11-GC & wait" >/dev/null 2>&1 &
P=$!
if wait_file "$E11_OUT" 20; then
    watch MK-E11-GC 8
    gc=$SEE
    parent=$(sightings MK-E11-PARENT)
    n=$(wait_labelled mk-e11-only 1 5)
    [ "$gc" -ge 1 ] && pass "e11-no-follow-grandchild-visible (sightings=$gc)" \
        || fail "e11-no-follow-grandchild-visible (grandchild was redacted)"
    [ "$parent" = 0 ] && [ "$n" -ge 1 ] && pass "e11-no-follow-direct-child-redacted (labelled=$n)" \
        || fail "e11-no-follow-direct-child-redacted (parent sightings=$parent labelled=$n)"
    case "$(cat "$E11_OUT")" in
        *G1*G2*) pass e11-no-follow-grandchild-functional ;;
        *) fail "e11-no-follow-grandchild-functional ($(cat "$E11_OUT"))" ;;
    esac
else
    fail "e11-no-follow (the command produced no output within 20 s)"
fi
stop_tree "$P" mk-e11-only testcases
rm -f "$E11_OUT"

# ------------------------------------------------- E12: --no-exit-kill
# Defects caught: --no-exit-kill ignored (the tree dies with the
# supervisor); EXITKILL missing in the default mode (the control run
# leaves survivors).  The supervisor exe is confmask, so only tracees
# (exe testcases) are counted.
"$TOOL" -q --no-exit-kill -l mk-e12-keep /bin/sh -c "$CASES sleeper MK-E12 & wait" >/dev/null 2>&1 &
P=$!
before=$(wait_comm_exe mk-e12-keep testcases 1 15)
kill -9 "$P" 2>/dev/null; wait "$P" 2>/dev/null
sleep 1.5
after=$(comm_exe_count mk-e12-keep testcases)
kill_comm mk-e12-keep KILL 2>/dev/null; sleep 0.2
[ "$before" -ge 1 ] && [ "$after" -ge 1 ] && pass "e12-no-exit-kill-tree-survives (before=$before after=$after)" \
    || fail "e12-no-exit-kill-tree-survives (before=$before after=$after, want >=1 and >=1)"

"$TOOL" -q -l mk-e12-kill /bin/sh -c "$CASES sleeper MK-E12 & wait" >/dev/null 2>&1 &
P=$!
before=$(wait_comm_exe mk-e12-kill testcases 1 15)
kill -9 "$P" 2>/dev/null; wait "$P" 2>/dev/null
sleep 1.5
after=$(comm_exe_count mk-e12-kill testcases)
kill_comm mk-e12-kill KILL 2>/dev/null; sleep 0.2
[ "$before" -ge 1 ] && [ "$after" = 0 ] && pass "e12-default-exit-kill-control (before=$before after=$after)" \
    || fail "e12-default-exit-kill-control (before=$before after=$after, want >=1 and 0)"

# ---------------------------------------------------- E13: --label-empty
# Defects caught: --label-empty ignored (the cmdline shows the program
# name, so no labelled process has an empty cmdline); the marker visible.
"$TOOL" -q --label-empty "$CASES" sleeper MK-E13 >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe ' ' testcases 1 15)
sleep 0.3
empty=0
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = " " ] || continue
    case "$(readlink "$d/exe" 2>/dev/null)" in
        */testcases) [ -z "$(visible_cmdline "${d#/proc/}")" ] && empty=$((empty + 1)) ;;
    esac
done
s=$(sightings MK-E13)
stop_tree "$P" ' '
[ "$n" -ge 1 ] && [ "$empty" -ge 1 ] && [ "$s" = 0 ] \
    && pass "e13-label-empty (blank comm, empty cmdline: $empty process(es))" \
    || fail "e13-label-empty (alive=$n empty-cmdline=$empty sightings=$s)"

# ------------------------------------------ E14: default, no label given
# Defects caught: no-label mode leaves the arguments visible; no-label
# mode produces an empty or foreign cmdline instead of the program name.
kill_comm testcases KILL 2>/dev/null; sleep 0.2
"$TOOL" -q "$CASES" sleeper MK-E14 >/dev/null 2>&1 &
P=$!
n=$(wait_comm_exe testcases testcases 1 15)
sleep 0.3
named=0
for d in /proc/[0-9]*; do
    case "$(readlink "$d/exe" 2>/dev/null)" in
        */testcases) [ "$(visible_cmdline "${d#/proc/}")" = "testcases" ] && named=$((named + 1)) ;;
    esac
done
s=$(sightings MK-E14)
stop_tree "$P" testcases
[ "$n" -ge 1 ] && [ "$named" -ge 1 ] && [ "$s" = 0 ] \
    && pass "e14-default-no-label (cmdline is the program name, args stripped)" \
    || fail "e14-default-no-label (alive=$n named=$named sightings=$s)"

# --------------------------------------------- E15: execveat and fexecve
# Defects caught: execveat/fexecve not recognised as exec (marker visible
# or program broken).  Skipped, visibly, while the testcases binary has
# no such subcommand.
for sub in execveat fexecve; do
    if "$CASES" "$sub" 2>&1 | grep -q 'unknown testcase'; then
        echo "SKIP e15-$sub (testcases has no '$sub' subcommand)"
        continue
    fi
    out=$("$TOOL" -q -l "$FAKE" "$CASES" "$sub" "$CASES" echoargs E15A E15B 2>/dev/null)
    case "$out" in
        *E15A*E15B*) pass "e15-$sub-argv-fidelity" ;;
        *) fail "e15-$sub-argv-fidelity (got: $out)" ;;
    esac
    "$TOOL" -q -l mk-e15-label "$CASES" "$sub" "$CASES" sleeper MK-E15-$sub >/dev/null 2>&1 &
    P=$!
    n=$(wait_comm_exe mk-e15-label testcases 1 15)
    sleep 0.3
    s=$(sightings MK-E15-$sub)
    stop_tree "$P" mk-e15-label
    [ "$n" -ge 1 ] && [ "$s" = 0 ] && pass "e15-$sub-redacted (alive=$n)" \
        || fail "e15-$sub-redacted (alive=$n sightings=$s)"
done

# ------------------------------------------------ E16: two chained execs
# env execs a shell that runs a script: two execs in one tree.
# Defects caught: the second exec loses its arguments or exit code; the
# verbose log shows fewer than two completed execs.
E16_SCRIPT=/tmp/mk-e16-inner.$$
E16_LOG=/tmp/mk-e16-log.$$
printf 'echo "inner-ok $1"\n' > "$E16_SCRIPT"
out=$("$TOOL" -v -l testlabel env /bin/sh "$E16_SCRIPT" MK-E16 2>"$E16_LOG")
rc=$?
ndone=$(grep -c 'exec-done' "$E16_LOG")
[ "$rc" = 0 ] && [ "$out" = "inner-ok MK-E16" ] && pass "e16-two-exec-output (rc=$rc)" \
    || fail "e16-two-exec-output (rc=$rc out=[$out])"
[ "$ndone" -ge 2 ] && pass "e16-two-exec-completions (exec-done lines=$ndone)" \
    || fail "e16-two-exec-completions (exec-done lines=$ndone, want >=2)"
rm -f "$E16_SCRIPT" "$E16_LOG"

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]

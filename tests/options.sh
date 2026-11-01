#!/bin/sh
# ============================================================================
# confmask option suite -- one case group per CLI/library option.
#
# Every group has a control that must behave differently from the tested
# run, so a group cannot pass because the observer sees nothing.  The
# defect each group catches is named in its header comment.
#
# Cases that need a kernel feature the machine may lack print SKIP with
# the reason.  A SKIP is never a PASS and is not counted as one.
#
#   O1  --help documents CONFMASK_NO_SELFMASK and the '-' label
#   O2  --argv0 sets argv[0]
#   O3  default argv[0] is the original program string, not the path
#   O4  --comm overrides comm; more than 15 bytes is rejected
#   O5  NUL label is rejected by Mask::run and Mask::spawn
#   O6  LF label is rejected by the CLI
#   O7  -l- , '-l -' and --label=- give the same blank label
#   O8  {:?} of a Mask holds no environment name or value
#   O9  --env and --env-file reach the program but not /proc
#   O10 --keep-env=NAME keeps NAME visible and the rest hidden
#   O11 --args-from-fd keeps the secret out of confmask's own cmdline
#   O12 the supervisor shows the label and hides argv and environ
#   O13 race probe against the supervisor's own /proc entry
#   O14 --on-exit detach | kill | wait
#   O15 --no-dumpable blocks a same-uid observer
#   O16 --no-new-privs and --watch-rename set NoNewPrivs
#   O17 --watch-rename keeps the label across PR_SET_NAME
#   O18 --rexec shows a memfd as /proc/<pid>/exe
#   O19 --unshare shows only the payload in /proc
#   O20 mask options with --daemon print a warning
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
T="/tmp/mkopt.$$"
mkdir -p "$T" || { echo "FATAL: cannot create $T"; exit 2; }

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }

# every label of this suite starts with "mko", so one prefix cleans up
cleanup() {
    kill_comm mko KILL
    rm -rf "$T"
}
trap cleanup EXIT

# child_of PID -> pid of the first process whose parent is PID
child_of() {
    for d in /proc/[0-9]*; do
        cp=${d#/proc/}
        pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$d/status" 2>/dev/null)
        if [ "$pp" = "$1" ]; then
            echo "$cp"
            return 0
        fi
    done
    return 1
}

# await_child PID -> prints the tracee pid once it exists (3 s limit)
await_child() {
    n=0
    while [ "$n" -lt 30 ]; do
        ac=$(child_of "$1") && [ -n "$ac" ] && { echo "$ac"; return 0; }
        n=$((n + 1))
        sleep 0.1
    done
    return 1
}

# reap SUPERVISOR_PID
reap() {
    kill -9 "$1" 2>/dev/null
    kill_comm mko KILL
    wait "$1" 2>/dev/null
    return 0
}

# comm_of PID -> comm text without the trailing newline
comm_of() {
    cat "/proc/$1/comm" 2>/dev/null
}

# wait_text FILE PATTERN SECONDS -> 0 once FILE contains PATTERN
wait_text() {
    n=0
    lim=$(($3 * 10))
    while [ "$n" -lt "$lim" ]; do
        grep -q -- "$2" "$1" 2>/dev/null && return 0
        n=$((n + 1))
        sleep 0.1
    done
    return 1
}

# ------------------------------------------------------------ O1: --help
help=$("$TOOL" --help 2>&1)
case "$help" in
    *CONFMASK_NO_SELFMASK*) pass o1-help-names-selfmask-escape ;;
    *) fail "o1-help-names-selfmask-escape (CONFMASK_NO_SELFMASK not in --help)" ;;
esac
case "$help" in
    *"--label=-"*) pass o1-help-documents-dash-label ;;
    *) fail "o1-help-documents-dash-label (--label=- not in --help)" ;;
esac

# ----------------------------------------------------------- O2: --argv0
# Catches: --argv0 ignored, argv[0] always the program path.
out=$("$TOOL" -q --argv0 git "$CASES" echoargs x 2>/dev/null)
case "$out" in
    *"arg0=[git] arg1=[echoargs]"*) pass o2-argv0-override ;;
    *) fail "o2-argv0-override (got: $out)" ;;
esac

# ------------------------------------------- O3: original string is argv[0]
# Catches: argv[0] rewritten to the resolved path (issue 20, item 1).
mkdir -p "$T/bin"
ln -s "$CASES" "$T/bin/tcprog"
out=$(PATH="$T/bin:$PATH" "$TOOL" -q tcprog echoargs 2>/dev/null)
case "$out" in
    *"arg0=[tcprog] arg1=[echoargs]"*) pass o3-default-argv0-is-original-string ;;
    *) fail "o3-default-argv0-is-original-string (got: $out)" ;;
esac

# --------------------------------------------------------------- O4: comm
# Catches: comm always cut from the label; no length check.
"$TOOL" -q -l "mko-long-label-for-comm-test" --comm mko-cm "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.6
c=""
[ -n "$tr_pid" ] && c=$(comm_of "$tr_pid")
[ "$c" = "mko-cm" ] && pass o4-comm-override \
    || fail "o4-comm-override (tracee comm=[$c], want mko-cm)"
reap "$SUP"

out=$("$TOOL" -q --comm 0123456789abcdef "$CASES" echoargs 2>&1)
rc=$?
if [ "$rc" != 0 ] && ! printf '%s' "$out" | grep -q "arg0="; then
    pass o4-comm-over-15-bytes-rejected
else
    fail "o4-comm-over-15-bytes-rejected (rc=$rc out=$out)"
fi

# ------------------------------------------------------- O5: NUL label
# The shell cannot pass NUL, so the library API is called directly.
# Catches: NUL label accepted at run or spawn.
out=$("$CASES" label-nul 2>&1)
rc=$?
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q "label-nul run: rejected" \
    && printf '%s' "$out" | grep -q "label-nul spawn: rejected"; then
    pass o5-nul-label-rejected-run-and-spawn
else
    fail "o5-nul-label-rejected (rc=$rc out=$(printf '%s' "$out" | tr '\n' '|'))"
fi

# ------------------------------------------------------- O6: LF label
# Catches: a newline label reaching ps output.
NL=$(printf 'a\nb')
out=$("$TOOL" -q -l "$NL" "$CASES" echoargs 2>&1)
rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -qi "label" \
    && ! printf '%s' "$out" | grep -q "arg0="; then
    pass o6-newline-label-rejected
else
    fail "o6-newline-label-rejected (rc=$rc out=$out)"
fi

# --------------------------------------------- O7: -l- equals --label=-
# Catches: the two spellings of the blank label diverging again.
blank_comm() {  # OPTION... -> comm of the tracee started with those options
    "$TOOL" -q "$@" "$CASES" sleeper >/dev/null 2>&1 &
    bsup=$!
    bt=$(await_child "$bsup") || bt=""
    sleep 0.6
    bc="<none>"
    [ -n "$bt" ] && bc=$(comm_of "$bt")
    reap "$bsup"
    printf '%s' "[$bc]"
}
a=$(blank_comm -l-)
b=$(blank_comm --label=-)
d=$(blank_comm -l -)
e=$(blank_comm --label -)
if [ "$a" = "[ ]" ] && [ "$a" = "$b" ] && [ "$a" = "$d" ] && [ "$a" = "$e" ]; then
    pass o7-dash-label-forms-agree
else
    fail "o7-dash-label-forms-agree (-l-=$a --label=-=$b '-l -'=$d '--label -'=$e, want all [ ])"
fi

# ------------------------------------------------------ O8: Debug output
# Catches: derived Debug printing environment names or values.
out=$("$CASES" debug-mask MK_DBG_KEY MK-DBG-SECRET 2>&1)
if printf '%s' "$out" | grep -q "MK-DBG-SECRET" || printf '%s' "$out" | grep -q "MK_DBG_KEY"; then
    fail "o8-debug-hides-env (secret or name printed: $out)"
elif printf '%s' "$out" | grep -q "redacted"; then
    pass o8-debug-hides-env
else
    fail "o8-debug-hides-env (no 'redacted' marker in: $out)"
fi

# ----------------------------------------------- O9: --env, --env-file
out=$("$TOOL" -q --env MK_OPT_E=envval "$CASES" getenv MK_OPT_E 2>/dev/null)
[ "$out" = "MK_OPT_E=envval" ] && pass o9-env-reaches-program \
    || fail "o9-env-reaches-program (got: $out)"

printf 'MK_OPT_F=filval\n# comment\n\nMK_OPT_G=two\n' > "$T/envf"
out=$("$TOOL" -q --env-file "$T/envf" "$CASES" getenv MK_OPT_F 2>/dev/null)
[ "$out" = "MK_OPT_F=filval" ] && pass o9-env-file-reaches-program \
    || fail "o9-env-file-reaches-program (got: $out)"

printf 'MK_OPT_SECF=MK-OPT-FILESECRET\n' > "$T/envf2"
"$TOOL" -q -l mko-env --env MK_OPT_SECE=MK-OPT-ENVSECRET --env-file "$T/envf2" "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
await_child "$SUP" >/dev/null
sleep 0.8
s1=$(sightings MK-OPT-ENVSECRET)
s2=$(sightings MK-OPT-FILESECRET)
reap "$SUP"
[ "$s1" = 0 ] && [ "$s2" = 0 ] && pass o9-env-and-env-file-hidden-from-proc \
    || fail "o9-env-and-env-file-hidden-from-proc (env=$s1 file=$s2 sightings)"

# control: with --keep-env the same secret IS visible, so the observer works
"$TOOL" -q -l mko-envc --keep-env --env MK_OPT_SECE=MK-OPT-ENVSECRET "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
await_child "$SUP" >/dev/null
sleep 0.8
s=$(sightings MK-OPT-ENVSECRET)
reap "$SUP"
[ "$s" -ge 1 ] && pass o9-control-keep-env-secret-visible \
    || fail "o9-control-keep-env-secret-visible (observer saw $s)"

# --------------------------------------------------- O10: --keep-env=NAME
# Catches: keep list ignored (PATH absent) or ignored the other way
# (secret visible).
"$TOOL" -q -l mko-keep --keep-env=PATH --env PATH=/usr/bin:/bin --env MK_OPT_HID=hiddenvalue "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.8
envtxt=""
[ -n "$tr_pid" ] && envtxt=$(tr '\0' '\n' < "/proc/$tr_pid/environ" 2>/dev/null)
reap "$SUP"
if printf '%s\n' "$envtxt" | grep -q '^PATH=' && ! printf '%s\n' "$envtxt" | grep -q 'MK_OPT_HID'; then
    pass o10-keep-env-name-visible-secret-hidden
else
    fail "o10-keep-env-name (environ: $(printf '%s' "$envtxt" | tr '\n' '|' | cut -c1-120))"
fi

"$TOOL" -q -l mko-keepc --env PATH=/usr/bin:/bin "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.8
envtxt=""
[ -n "$tr_pid" ] && envtxt=$(tr '\0' '\n' < "/proc/$tr_pid/environ" 2>/dev/null)
reap "$SUP"
if printf '%s\n' "$envtxt" | grep -q '^PATH='; then
    fail "o10-control-default-redacts-path (PATH visible without --keep-env)"
else
    pass o10-control-default-redacts-path
fi

# ---------------------------------------------------- O11: --args-from-fd
# Catches: the secret reaching confmask's own argv.
printf '%s\0%s\0%s\0' "$CASES" sleeper MK-OPT-FDSECRET > "$T/args.bin"
nuls=$(tr -cd '\0' < "$T/args.bin" | wc -c | tr -d ' ')
if [ "$nuls" != 3 ]; then
    skip "o11-args-from-fd (this printf cannot write NUL bytes: $nuls found, want 3)"
else
    "$TOOL" -q -l mko-fd --args-from-fd 3 3<"$T/args.bin" >/dev/null 2>&1 &
    SUP=$!
    tr_pid=$(await_child "$SUP") || tr_pid=""
    sleep 0.8
    own=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
    s=$(sightings MK-OPT-FDSECRET)
    reap "$SUP"
    if [ -z "$tr_pid" ]; then
        fail "o11-args-from-fd (the program did not start)"
    elif printf '%s' "$own" | grep -q "MK-OPT-FDSECRET" || [ "$s" != 0 ]; then
        fail "o11-args-from-fd-secret-absent (own cmdline=[$own] sightings=$s)"
    else
        pass o11-args-from-fd-secret-absent
    fi

    printf '%s\0%s\0%s\0' "$CASES" echoargs MK-OPT-FDARG > "$T/args2.bin"
    out=$("$TOOL" -q --args-from-fd 3 3<"$T/args2.bin" 2>/dev/null)
    case "$out" in
        *"arg2=[MK-OPT-FDARG]"*) pass o11-args-from-fd-program-gets-arguments ;;
        *) fail "o11-args-from-fd-program-gets-arguments (got: $out)" ;;
    esac
fi

# control: an unmasked process with the same marker IS found by sightings
"$CASES" sleeper MK-OPT-FDCTL >/dev/null 2>&1 &
CTL=$!
sleep 0.3
s=$(sightings MK-OPT-FDCTL)
kill "$CTL" 2>/dev/null
[ "$s" -ge 1 ] && pass o11-control-observer-sees-plain-argv \
    || fail "o11-control-observer-sees-plain-argv (saw $s)"

# ------------------------------------------- O12: supervisor self-mask
# Catches: label missing from the supervisor (it showed as '[-]'), argv or
# environ left readable.
MK_OPT_SUPENV=MK-OPT-SUPENVSECRET "$TOOL" -q -l mko-supself "$CASES" sleeper MK-OPT-SUPSECRET >/dev/null 2>&1 &
SUP=$!
sleep 0.9
sc=$(comm_of "$SUP")
sv=$(tr -d '\0' < "/proc/$SUP/cmdline" 2>/dev/null)
se=$(tr '\0' ' ' < "/proc/$SUP/environ" 2>/dev/null)
reap "$SUP"
[ "$sc" = "mko-supself" ] && pass o12-supervisor-comm-is-label \
    || fail "o12-supervisor-comm-is-label (comm=[$sc])"
[ "$sv" = "mko-supself" ] && pass o12-supervisor-cmdline-is-label \
    || fail "o12-supervisor-cmdline-is-label (cmdline=[$sv])"
case "$sv$se" in
    *MK-OPT-SUPSECRET*|*MK-OPT-SUPENVSECRET*)
        fail "o12-supervisor-hides-argv-and-environ (secret found)" ;;
    *) pass o12-supervisor-hides-argv-and-environ ;;
esac

# control: CONFMASK_NO_SELFMASK=1 leaves the secret readable
CONFMASK_NO_SELFMASK=1 "$TOOL" -q -l mko-supnos "$CASES" sleeper MK-OPT-SUPSECRET >/dev/null 2>&1 &
SUP=$!
sleep 0.9
sv=$(tr '\0' ' ' < "/proc/$SUP/cmdline" 2>/dev/null)
reap "$SUP"
case "$sv" in
    *MK-OPT-SUPSECRET*) pass o12-control-no-selfmask-leaves-argv ;;
    *) fail "o12-control-no-selfmask-leaves-argv (cmdline=[$sv])" ;;
esac

# -------------------------------------------------- O13: self-entry race
# A program cannot redact the argv the kernel published for its own exec:
# the window opens at execve and closes at the supervisor's first
# instruction that zeroes the block.  What the supervisor CAN guarantee is
# that the secret is gone before it forks any child.  This case asserts
# exactly that, and measures the entry window as an observation.
#
# Catches: a supervisor that parses options, probes and forks before it
# redacts itself (the child then runs while the parent's argv still shows
# the secret).
hits=0
samples=0
k=0
while [ "$k" -lt 10 ]; do
    "$TOOL" -q -l mko-race "$CASES" sleeper MK-OPT-RACESECRET >/dev/null 2>&1 &
    rp=$!
    child=$(await_child "$rp") || child=""
    # the child exists: the session has started.  From here on the
    # supervisor's own cmdline must never show the secret again.
    j=0
    while [ "$j" -lt 5 ]; do
        ctext=$(tr '\0' ' ' 2>/dev/null < "/proc/$rp/cmdline") || ctext=""
        samples=$((samples + 1))
        case "$ctext" in
            *MK-OPT-RACESECRET*) hits=$((hits + 1)) ;;
        esac
        j=$((j + 1))
        sleep 0.1
    done
    reap "$rp"
    [ -n "$child" ] && kill -9 "$child" 2>/dev/null
    kill_comm mko-race KILL 2>/dev/null
    k=$((k + 1))
done
if [ "$hits" = 0 ]; then
    pass "o13-secret-gone-before-fork (0 sightings in $samples samples while the child ran)"
else
    fail "o13-secret-gone-before-fork ($hits sightings in $samples samples: the supervisor forked before it redacted itself)"
fi

# entry window measurement: how long does the kernel publish the real argv
# of a supervisor?  Reported, not asserted: the executor's speed decides it.
if [ "${ID:-}" != "nonroot" ]; then
    worst=0
    n=0
    while [ "$n" -lt 5 ]; do
        "$TOOL" -q -l mko-race "$CASES" sleeper MK-OPT-RACESECRET >/dev/null 2>&1 &
        rp=$!
        t0=$(date +%s%N 2>/dev/null || echo 0)
        w=0
        while [ "$w" -lt 400 ]; do
            ctext=$(tr '\0' ' ' 2>/dev/null < "/proc/$rp/cmdline") || break
            [ -z "$ctext" ] && break
            w=$((w + 1))
        done
        t1=$(date +%s%N 2>/dev/null || echo 0)
        if [ "$t1" -gt "$t0" ] 2>/dev/null; then
            d=$(( (t1 - t0) / 1000000 ))
            [ "$d" -gt "$worst" ] && worst=$d
        fi
        reap "$rp"
        kill_comm mko-race KILL 2>/dev/null
        n=$((n + 1))
    done
    echo "INFO self-entry-window ${worst}ms (kernel publishes the supervisor argv until it zeroes the block; not closable from inside the process)"
fi

# ------------------------------------------------------ O14: --on-exit
# The master shell starts a background child and exits.
# detach: the child lives on.  kill: it is killed.  wait: confmask returns
# only after it ends.
# Catches: session end killing detached jobs, or not killing under kill.
"$TOOL" -q -l mko-oxdet --on-exit detach /bin/sh -c "$CASES sleeper MK-OPT-OX </dev/null >/dev/null 2>&1 & sleep 0.5; exit 0" >/dev/null 2>&1
sleep 0.5
n=$(comm_count mko-oxdet)
kill_comm mko-oxdet KILL
[ "$n" -ge 1 ] && pass o14-on-exit-detach-keeps-background-child \
    || fail "o14-on-exit-detach-keeps-background-child (alive=$n)"

"$TOOL" -q -l mko-oxkill --on-exit kill /bin/sh -c "$CASES sleeper MK-OPT-OX </dev/null >/dev/null 2>&1 & sleep 0.5; exit 0" >/dev/null 2>&1
n=1
w=0
while [ "$w" -lt 20 ]; do
    n=$(comm_count mko-oxkill)
    [ "$n" = 0 ] && break
    w=$((w + 1))
    sleep 0.1
done
kill_comm mko-oxkill KILL
[ "$n" = 0 ] && pass o14-on-exit-kill-terminates-background-child \
    || fail "o14-on-exit-kill-terminates-background-child (alive=$n)"

t0=$(date +%s)
"$TOOL" -q -l mko-oxdet2 --on-exit detach /bin/sh -c "sleep 3 </dev/null >/dev/null 2>&1 & exit 0" >/dev/null 2>&1
t1=$(date +%s)
d_detach=$((t1 - t0))
t0=$(date +%s)
"$TOOL" -q -l mko-oxwait --on-exit wait /bin/sh -c "sleep 3 </dev/null >/dev/null 2>&1 & exit 0" >/dev/null 2>&1
t1=$(date +%s)
d_wait=$((t1 - t0))
if [ "$d_wait" -ge 2 ] && [ "$d_detach" -le 1 ]; then
    pass "o14-on-exit-wait-waits (detach=${d_detach}s wait=${d_wait}s)"
else
    fail "o14-on-exit-wait-waits (detach=${d_detach}s wait=${d_wait}s, want detach<=1 and wait>=2)"
fi

# --------------------------------------------------- O15: --no-dumpable
# The tracee runs as uid 1000.  The observer is another process of uid
# 1000, not an ancestor.  With the flag the observer gets EACCES.
# Catches: dumpable flag not injected (observer can read environ).
if [ "$(id -u)" != 0 ]; then
    skip "o15-no-dumpable (needs root to switch to uid 1000)"
elif ! "$CASES" as-uid 1000 "$CASES" show-nnp >/dev/null 2>&1; then
    skip "o15-no-dumpable (uid 1000 cannot run the test binaries from $BIN_DIR)"
else
    dump_observe() {  # EXTRA_OPTION -> prints "rc|text" of the observer
        MK_OPT_DUMP=dumpvisible "$CASES" as-uid 1000 "$TOOL" -q --keep-env -l mko-dmp $1 "$CASES" sleeper >/dev/null 2>&1 &
        dsup=$!
        dt=$(await_child "$dsup") || dt=""
        sleep 0.9
        if [ -z "$dt" ]; then
            reap "$dsup"
            printf '%s' "99|no-tracee"
            return 0
        fi
        dout=$("$CASES" as-uid 1000 cat "/proc/$dt/environ" 2>&1)
        drc=$?
        reap "$dsup"
        printf '%s' "$drc|$(printf '%s' "$dout" | tr '\0\n' '  ')"
    }
    ctl=$(dump_observe "")
    res=$(dump_observe "--no-dumpable")
    ctl_rc=${ctl%%|*}
    res_rc=${res%%|*}
    case "$ctl" in
        "0|"*dumpvisible*) pass "o15-control-same-uid-observer-reads-environ" ;;
        *) fail "o15-control-same-uid-observer-reads-environ ($ctl)" ;;
    esac
    case "$res" in
        *dumpvisible*) fail "o15-no-dumpable-blocks-observer (environ readable: $res)" ;;
        *)
            if [ "$res_rc" != 0 ] && [ "$res_rc" != 99 ]; then
                pass "o15-no-dumpable-blocks-observer (before: rc=$ctl_rc readable, after: rc=$res_rc)"
            else
                fail "o15-no-dumpable-blocks-observer (rc=$res_rc: $res)"
            fi
            ;;
    esac
fi

# --------------------------------------------- O16: --no-new-privs
# Catches: the prctl missing in the child.
nnp() {  # OPTION... -> the NoNewPrivs value
    nout=$("$TOOL" -q "$@" "$CASES" show-nnp 2>/dev/null)
    printf '%s' "$nout" | tr -d '[:space:]'
}
v=$(nnp --no-new-privs)
[ "$v" = "NoNewPrivs:1" ] && pass o16-no-new-privs-sets-flag || fail "o16-no-new-privs-sets-flag ($v)"
v=$(nnp --watch-rename)
[ "$v" = "NoNewPrivs:1" ] && pass o16-watch-rename-implies-no-new-privs || fail "o16-watch-rename-implies-no-new-privs ($v)"
v=$(nnp -l mko-nnp0)
[ "$v" = "NoNewPrivs:0" ] && pass o16-control-default-leaves-flag-clear || fail "o16-control-default-leaves-flag-clear ($v)"

# --------------------------------------------- O17: --watch-rename
# The renamer settles, calls prctl(PR_SET_NAME, "other") and reports its
# own comm.  With the watch the comm must stay the label.
# Catches: the seccomp watch not reverting the rename.
"$TOOL" -l mko-keeplabel --watch-rename "$CASES" renamer >"$T/rn.out" 2>"$T/rn.err" &
SUP=$!
wait_text "$T/rn.out" "renamer-comm=" 5
rn=$(sed -n 's/^renamer-comm=//p' "$T/rn.out")
reap "$SUP"
if grep -q -- "--watch-rename unavailable" "$T/rn.err"; then
    skip "o17-watch-rename ($(grep -m1 -- '--watch-rename unavailable' "$T/rn.err"))"
elif [ "$rn" = "mko-keeplabel" ]; then
    pass o17-watch-rename-keeps-label
else
    fail "o17-watch-rename-keeps-label (comm after rename=[$rn], want mko-keeplabel)"
fi

"$TOOL" -q -l mko-keepctl "$CASES" renamer >"$T/rn2.out" 2>/dev/null &
SUP=$!
wait_text "$T/rn2.out" "renamer-comm=" 5
rn=$(sed -n 's/^renamer-comm=//p' "$T/rn2.out")
reap "$SUP"
[ "$rn" = "other" ] && pass o17-control-without-watch-rename-comm-changes \
    || fail "o17-control-without-watch-rename-comm-changes (comm=[$rn], want other)"

# ------------------------------------------------------------ O18: --rexec
# Catches: exe still naming the on-disk binary; the path in maps.
"$TOOL" -l mko-rex --rexec "$CASES" sleeper >/dev/null 2>"$T/rx.err" &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
exe=""
n=0
while [ "$n" -lt 30 ]; do
    [ -n "$tr_pid" ] && exe=$(readlink "/proc/$tr_pid/exe" 2>/dev/null)
    case "$exe" in /memfd:*) break ;; esac
    n=$((n + 1))
    sleep 0.1
done
maps_hits=-1
[ -n "$tr_pid" ] && maps_hits=$(grep -c "testcases" "/proc/$tr_pid/maps" 2>/dev/null)
reap "$SUP"
if grep -q -- "--rexec unavailable" "$T/rx.err"; then
    skip "o18-rexec ($(grep -m1 -- '--rexec unavailable' "$T/rx.err"))"
else
    case "$exe" in
        /memfd:*) pass "o18-rexec-exe-is-memfd ($exe)" ;;
        *) fail "o18-rexec-exe-is-memfd (exe=[$exe])" ;;
    esac
    [ "$maps_hits" = 0 ] && pass o18-rexec-maps-has-no-disk-path \
        || fail "o18-rexec-maps-has-no-disk-path (lines naming the binary: $maps_hits)"
fi

"$TOOL" -q -l mko-rexc "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
tr_pid=$(await_child "$SUP") || tr_pid=""
sleep 0.6
exe=""
[ -n "$tr_pid" ] && exe=$(readlink "/proc/$tr_pid/exe" 2>/dev/null)
reap "$SUP"
[ "$exe" = "$CASES" ] && pass o18-control-exe-is-disk-path \
    || fail "o18-control-exe-is-disk-path (exe=[$exe], want $CASES)"

# ----------------------------------------------------------- O19: --unshare
# With a private pid namespace and proc, the payload counts only itself
# (1 to 3 numeric entries).  When the kernel refuses, confmask prints a
# 'confmask: --unshare unavailable:' line and the case is skipped.
ctl_out=$("$TOOL" -q "$CASES" count-proc 2>/dev/null)
ctl_n=$(printf '%s\n' "$ctl_out" | sed -n 's/^proc-count=//p')
out=$("$TOOL" --unshare "$CASES" count-proc 2>"$T/ns.err")
n=$(printf '%s\n' "$out" | sed -n 's/^proc-count=//p')
if grep -q "^confmask: --unshare unavailable:" "$T/ns.err"; then
    skip "o19-unshare ($(grep -m1 '^confmask: --unshare unavailable:' "$T/ns.err"))"
elif [ -n "$n" ] && [ "$n" -ge 1 ] && [ "$n" -le 3 ] && [ -n "$ctl_n" ] && [ "$ctl_n" -gt "$n" ]; then
    pass "o19-unshare-payload-sees-only-itself (inside=$n outside=$ctl_n)"
else
    fail "o19-unshare-payload-sees-only-itself (inside=[$n] outside=[$ctl_n], out=[$out])"
fi

# --------------------------------------------- O20: --daemon warnings
# Catches: mask options silently dropped in daemon mode.
err=$("$TOOL" --daemon "$T/no-such.sock" --no-follow --on-exit wait -- true 2>&1 >/dev/null)
if printf '%s' "$err" | grep -qi "warning" && printf '%s' "$err" | grep -q -- "--no-follow" \
    && printf '%s' "$err" | grep -q -- "--on-exit"; then
    pass o20-daemon-with-mask-options-warns
else
    fail "o20-daemon-with-mask-options-warns (stderr: $err)"
fi
err=$("$TOOL" -q --daemon "$T/no-such.sock" --no-follow -- true 2>&1 >/dev/null)
printf '%s' "$err" | grep -qi "warning" \
    && fail "o20-quiet-suppresses-daemon-warning (stderr: $err)" \
    || pass o20-quiet-suppresses-daemon-warning
err=$("$TOOL" --daemon "$T/no-such.sock" --label x -- true 2>&1 >/dev/null)
printf '%s' "$err" | grep -qi "warning" \
    && fail "o20-control-label-only-has-no-warning (stderr: $err)" \
    || pass o20-control-label-only-has-no-warning

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]

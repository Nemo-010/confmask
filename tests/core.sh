#!/bin/sh
# ============================================================================
# confmask tracer core suite.  One case per defect of the exec/session core.
# Every case names the defect it catches; a planted defect must turn it red.
#
#   K1   exec from a non-leader thread keeps the real argv         (#1)
#   K2   strings of 5010 and 100010 bytes: fidelity, no tail leak  (#2)
#   K3   10001 arguments: full argv, no sighting                   (#3)
#   K4   32-bit program: loud refusal, program still correct       (#4)
#   K5   session end: detach (default), kill, wait                 (#5)
#   K6   job control: SIGSTOP holds, SIGCONT resumes               (#6)
#   K8   failed exec keeps the retry on the entry-swap path        (#8)
#   K9   failed repoint write: warning, nothing visible            (#9)
#   K10  summary line for the script path, silent when quiet       (#29)
#   K11  completion stop: reads per exec with a 4000-entry env     (#33)
#   K12  thread comm, setproctitle-style rewrite, no-vDSO comm     (#21)
#   K13  AT_EXECFN, set-uid gains nothing, execveat/fexecve        (#16)
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

L='core-label-x'
FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; }
T=/tmp/confmask-core.$$
mkdir -p "$T"
cleanup() {
    kill_comm "$L" KILL 2>/dev/null
    kill_comm sleeper KILL 2>/dev/null
    kill_comm testcases KILL 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

waitfile() { # file seconds: wait until the file exists and is non-empty
    i=0
    while [ ! -s "$1" ] && [ "$i" -lt $(($2 * 20)) ]; do sleep 0.05 2>/dev/null || sleep 1; i=$((i + 1)); done
    [ -s "$1" ]
}

# ------------------------------------------------ K1: non-leader exec thread
# Defect: the completion path read the label back as the program's argv.
out=$("$TOOL" -q -l "$L" "$CASES" threadexec "$CASES" echoargs MK-K1-REAL 2>&1)
case "$out" in
    *"arg2=[MK-K1-REAL]"*) pass k1-thread-exec-keeps-argv ;;
    *) fail "k1-thread-exec (want arg2=[MK-K1-REAL], got: $(printf '%s' "$out" | cut -c1-160))" ;;
esac

# --------------------------------------------------------- K2: long strings
# Defect: strings were cut at 4095 bytes and the tail stayed visible.
for n in 5000 100000; do
    pad=$(head -c "$n" /dev/zero | tr '\0' 'a')
    mk="TAILMARKK2N$n"
    rm -f "$T/k2.out"
    # control: the observer must see the tail without confmask
    "$CASES" holdargs "$T/k2c.out" "${pad}${mk}" &
    cp=$!
    waitfile "$T/k2c.out" 5 >/dev/null
    c=$(sightings "$mk")
    kill -9 $cp 2>/dev/null
    [ "$c" -ge 1 ] && pass "k2-control-sees-tail-$n ($c)" || fail "k2-control-$n: observer blind"
    "$TOOL" -q -l "$L" "$CASES" holdargs "$T/k2.out" "${pad}${mk}" &
    waitfile "$T/k2.out" 8 >/dev/null
    arg="${pad}${mk}"
    want=$((n + ${#mk}))
    want_tail=$(printf '%s' "$arg" | tail -c 12)
    if grep -q "len=$want tail=$want_tail$" "$T/k2.out" 2>/dev/null; then
        pass "k2-fidelity-$n (len=$want byte-exact tail)"
    else
        fail "k2-fidelity-$n: $(cat "$T/k2.out" 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
    fi
    s=$(sightings "$mk")
    [ "$s" = 0 ] && pass "k2-no-tail-leak-$n" || fail "k2-tail-leak-$n: $s sighting(s)"
    kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null
    sleep 0.3
done

# ------------------------------------------------------------ K3: 10001 args
# Defect: argc above 8192 ran with the real command line in /proc.
rm -f "$T/k3.out"
# 10000 argument entries built once and handed over with --args-from-fd,
# so the exec of the program that reads them is the FIRST exec of the
# child (the zero-exposure path).  A re-exec of a settled process would
# take the post-exec path and could show the argv in the sampled window.
: > "$T/k3.args"
printf '%s\0' "$CASES" holdargs "$T/k3.out" >> "$T/k3.args"
i=1
while [ "$i" -le 10000 ]; do
    printf '%s\0' "$i" >> "$T/k3.args"
    i=$((i + 1))
done
printf '%s\0' MKK3SECRET >> "$T/k3.args"
"$TOOL" -q -l "$L" --args-from-fd 3 3<"$T/k3.args" >/dev/null 2>&1 &
waitfile "$T/k3.out" 60 >/dev/null
if grep -q '^argc=10004$' "$T/k3.out" 2>/dev/null \
    && grep -q '^arg10003 len=10 tail=MKK3SECRET$' "$T/k3.out"; then
    pass k3-argv-complete-10000
else
    fail "k3-argv: $(head -2 "$T/k3.out" 2>/dev/null | tr '\n' ' ')"
fi
s=$(sightings MKK3SECRET)
[ "$s" = 0 ] && pass k3-no-sighting || fail "k3-sighting: $s"
kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null
sleep 0.3

# ------------------------------------------------------------ K4: 32-bit
# Defect: a 32-bit program was left unredacted without any message.
if [ -x ./testcases32 ]; then
    out=$("$TOOL" -l "$L" ./testcases32 echoargs MK-K4 2>"$T/k4.err")
    rc=$?
    case "$out" in
        *"arg2=[MK-K4]"*) pass k4-32bit-program-correct ;;
        *) fail "k4-32bit-program (rc=$rc out: $(printf '%s' "$out" | cut -c1-120))" ;;
    esac
    if grep -q '32-bit' "$T/k4.err"; then pass "k4-32bit-refusal-is-loud ($(head -1 "$T/k4.err" | cut -c1-100))"
    else fail "k4-silent-32bit-exec (stderr: $(cat "$T/k4.err" | head -3 | tr '\n' '|'))"; fi
    grep -q 'foreign-arch' "$T/k4.err" && pass k4-summary-names-foreign-arch \
        || fail "k4-summary-missing ($(tail -1 "$T/k4.err"))"
else
    skip "k4-32bit (tests/testcases32 absent: the i686 build is part of vm/run.sh)"
fi

# -------------------------------------------------------- K5: session end
# Defect: descendants were frozen (library) or killed (CLI) when the master exited.
SE='se-label-core'
"$TOOL" -q -l "$SE" /bin/sh -c "'$CASES' sleeper MK-K5 & exit 0" >/dev/null 2>&1
sleep 0.5
n=$(comm_count "$SE")
s=$(sightings MK-K5)
if [ "$n" -ge 1 ] && [ "$s" = 0 ]; then pass "k5-detach-keeps-background-job ($n alive with the label, $s sightings)"
else fail "k5-detach (alive=$n sightings=$s)"; fi
kill_comm "$SE" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; sleep 0.2

"$TOOL" -q -l "$SE" --on-exit kill /bin/sh -c "'$CASES' sleeper MK-K5K & exit 0" >/dev/null 2>&1
sleep 0.5
n=$(comm_count "$SE")
[ "$n" = 0 ] && pass k5-on-exit-kill-terminates-tree || fail "k5-on-exit-kill ($n still alive)"
kill_comm "$SE" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null

t0=$(date +%s)
"$TOOL" -q -l "$SE" --on-exit wait /bin/sh -c "'$CASES' sleepfor 2 & exit 0" >/dev/null 2>&1
t1=$(date +%s)
[ $((t1 - t0)) -ge 2 ] && pass "k5-on-exit-wait-waits ($((t1 - t0))s)" || fail "k5-on-exit-wait (returned after $((t1 - t0))s, want >= 2)"

# ------------------------------------------------------- K6: job control
# Defect: the group-stop was swallowed: SIGSTOP never held the tree.
rm -f "$T/k6.f"
"$TOOL" -q -l "$L" "$CASES" touchloop "$T/k6.f" >/dev/null 2>&1 &
sup=$!
waitfile "$T/k6.f" 5 >/dev/null
tp=""
for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$(proc_ppid "$p")" = "$sup" ] && tp=$p
done
if [ -z "$tp" ]; then
    fail "k6-job-control: tracee pid not found"
else
    # A traced tracee shows state 't' in a ptrace-stop and in a
    # group-stop, so the state letter alone proves nothing.  The
    # observable claim is that the tree stops making progress.
    kill -STOP "$tp"
    sleep 0.4
    a=$(wc -c < "$T/k6.f"); sleep 0.6; b=$(wc -c < "$T/k6.f")
    if [ "$a" -gt 0 ] && [ "$a" = "$b" ]; then pass "k6-sigstop-holds (file frozen at $a bytes)"
    else fail "k6-sigstop (size $a -> $b, want equal and non-zero)"; fi
    kill -CONT "$tp"
    sleep 0.6
    c=$(wc -c < "$T/k6.f")
    if [ "$c" -gt "$b" ]; then pass "k6-sigcont-resumes (size $b -> $c)"
    else fail "k6-sigcont (size $b -> $c, want growth)"; fi
fi
kill -9 "$sup" 2>/dev/null; kill_comm "$L" KILL 2>/dev/null; kill_comm testcases KILL 2>/dev/null; sleep 0.2

# --------------------------------------------- K8: failed exec then a retry
# Defect: the failed exec settled to Run; the retry took the post-exec path.
log=$("$TOOL" -v -l "$L" "$CASES" forkretry /nonexistent/confmask-k8 "$CASES" echoargs MK-K8 2>&1)
nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
nre=$(printf '%s\n' "$log" | grep -c 'exec-done reread=1')
if [ "$nswap" -ge 2 ] && [ "$nre" = 0 ]; then pass "k8-retry-keeps-entry-swap (swaps=$nswap rereads=$nre)"
else fail "k8-retry (swaps=$nswap rereads=$nre, want >=2 and 0)"; fi

# ------------------------------------------------ K9: failed repoint write
# Defect: a failed repoint left a kernel-copy pointer without any message.
CONFMASK_FAULT_POKE=1 "$TOOL" -l "$L" "$CASES" sleeper MK-K9 >/dev/null 2>"$T/k9.err" &
sleep 1
s=$(sightings MK-K9)
if grep -q 'repoint failed' "$T/k9.err" && [ "$s" = 0 ]; then pass "k9-failed-repoint-zeroes-and-warns ($s sightings)"
else fail "k9-failed-repoint (sightings=$s err: $(head -2 "$T/k9.err" | tr '\n' '|'))"; fi
kill_comm "$L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; sleep 0.2

# ----------------------------------------------------- K10: summary line
# Defect: a script exec degraded silently.
printf '#!/bin/sh\n/bin/true\n' > "$T/k10.sh"; chmod 755 "$T/k10.sh"
"$TOOL" -l "$L" "$T/k10.sh" >/dev/null 2>"$T/k10.err"
if grep -Eq '^confmask: [0-9]+ of [0-9]+ execs unredacted \(script\)' "$T/k10.err"; then
    pass "k10-summary-names-script ($(grep 'execs unredacted' "$T/k10.err"))"
else fail "k10-summary (stderr: $(head -3 "$T/k10.err" | tr '\n' '|'))"; fi
"$TOOL" -q -l "$L" "$T/k10.sh" >/dev/null 2>"$T/k10q.err"
[ ! -s "$T/k10q.err" ] && pass k10-quiet-prints-nothing || fail "k10-quiet ($(head -1 "$T/k10q.err"))"
"$TOOL" -l "$L" "$CASES" echoargs a >/dev/null 2>"$T/k10e.err"
grep -q 'execs unredacted' "$T/k10e.err" && fail "k10-clean-run-prints-summary" || pass k10-clean-elf-run-is-silent

# ------------------------------------------ K11: completion stop, big env
# Defect: the completion stop re-read every environment string to infer
# the span (one process_vm_readv per entry, more for long strings).
vars=$(seq 1 4000 | sed 's/^/CMKV/;s/$/=value/')
log=$(env $vars "$TOOL" -v -l "$L" "$CASES" echoargs a 2>&1)
line=$(printf '%s\n' "$log" | grep 'completion-stop' | head -1)
reads=$(printf '%s' "$line" | sed -n 's/.*reads=\([0-9]*\).*/\1/p')
us=$(printf '%s' "$line" | sed -n 's/.*completion-stop \([0-9]*\)us.*/\1/p')
if [ -n "$reads" ] && [ "$reads" -lt 200 ]; then
    pass "k11-completion-reads-bounded (reads=$reads for a 4000-entry environment)"
else fail "k11-completion-reads (line: $line)"; fi
echo "INFO completion-stop ${us:-?}us reads=${reads:-?} (4000-entry env, kernel $(uname -r), $(uname -m), VM under TCG when run by vm/run.sh)"

# ----------------------------------------- K12: comm, rename, no-vDSO
# Defect: per-thread comm unset, setproctitle clobbered the program's argv,
# no fallback when no vDSO syscall site is usable.
LC=threadlabelxyza
out=$("$TOOL" -q -l "${LC}bcd" "$CASES" threadnames 2>&1)
n=$(printf '%s\n' "$out" | grep -c "^thread-comm=$LC\$")
o=$(printf '%s\n' "$out" | grep -c '^thread-comm=')
[ "$n" = "$o" ] && [ "$n" -ge 4 ] && pass "k12-thread-comm-is-label ($n of $o threads)" || fail "k12-thread-comm ($n of $o: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-150))"

out=$("$TOOL" -q -l "$L" "$CASES" proctitle MK-K12 2>&1)
case "$out" in
    *"args-same=true path-same=true"*) pass k12-setproctitle-rewrite-keeps-args ;;
    *) fail "k12-setproctitle ($(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160))" ;;
esac

CONFMASK_FAULT_NOVDSO=1 "$TOOL" -q -l "$L" "$CASES" sleeper MK-K12V >/dev/null 2>&1 &
sleep 1
n=$(comm_count "$L")
# the supervisor and the tracee both carry the label comm: two processes
[ "$n" -ge 2 ] && pass "k12-no-vdso-fallback-sets-comm ($n label processes)" || fail "k12-no-vdso (label processes: $n, want >= 2)"
kill_comm "$L" KILL 2>/dev/null; kill_comm sleeper KILL 2>/dev/null; sleep 0.2

# ------------------------------------------------- K13: documented claims
out=$("$TOOL" -q -l "$L" "$CASES" execfn 2>&1)
case "$out" in
    "execfn=$CASES") pass "k13-at-execfn-is-the-real-path ($out)" ;;
    *) fail "k13-at-execfn (got: $out, want execfn=$CASES)" ;;
esac

if [ "$(id -u)" = 0 ]; then
    cp "$CASES" "$T/suidprobe"; chmod 4755 "$T/suidprobe"; chmod 755 "$T"
    ctl=$("$CASES" dropto 1000 "$T/suidprobe" suidprobe 2>&1)
    out=$("$CASES" dropto 1000 "$TOOL" -q -l "$L" "$T/suidprobe" suidprobe 2>&1)
    case "$ctl" in
        *euid=0*) pass "k13-control-setuid-works-unsupervised ($ctl)" ;;
        *) skip "k13-setuid-control ($ctl): filesystem may be nosuid" ;;
    esac
    case "$out" in
        *"uid=1000 euid=1000"*) pass "k13-setuid-gains-nothing-under-supervision ($out)" ;;
        *) fail "k13-setuid ($out)" ;;
    esac
else
    skip "k13-setuid (needs root to create a set-uid file)"
fi

for kind in execveat fexecve; do
    log=$("$TOOL" -v -l "$L" "$CASES" $kind "$CASES" echoargs MK-K13 2>&1)
    nswap=$(printf '%s\n' "$log" | grep -c 'entry pointer-swap (ELF)')
    case "$log" in
        *"arg2=[MK-K13]"*) pass "k13-$kind-argv-intact (entry swaps: $nswap)" ;;
        *) fail "k13-$kind ($(printf '%s' "$log" | tail -3 | tr '\n' '|' | cut -c1-200))" ;;
    esac
done

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]

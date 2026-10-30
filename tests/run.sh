#!/bin/sh
# confmask test suite.
#
# Runs anywhere.  A case that needs a mechanism the host refuses is
# SKIPPED with the reason, never silently passed: "zero sightings"
# means nothing if the process never ran.
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bin || { echo "FATAL: confmask binary missing and could not be built"; exit 2; }
setup_work
trap 'cleanup_work' EXIT INT TERM

S="$WORK/s.enc"
PP="$WORK/pp"
SOCK="$WORK/d.sock"
SECRET='ghp_SUPERSECRETVALUE'

echo "== capabilities =="
"$TOOL" probe > "$WORK/probe.txt" 2>&1
if grep -q 'capability report' "$WORK/probe.txt"; then pass cap-report
else fail cap-report; fi
if grep -q 'secret fds *yes' "$WORK/probe.txt"; then pass cap-secretfds
else fail cap-secretfds; fi

HAVE_PTRACE=no
grep -q 'metadata redaction *yes' "$WORK/probe.txt" && HAVE_PTRACE=yes
HAVE_USERNS=no
grep -q 'isolation *yes' "$WORK/probe.txt" && HAVE_USERNS=yes

# ---------------------------------------------------------------- store ---
echo "== T1: encrypted store round-trip =="
if "$TOOL" store init --store "$S" --passphrase-file "$PP" >/dev/null 2>&1 \
   && printf '%s\n' "$SECRET" | "$TOOL" store set TOKEN --store "$S" --passphrase-file "$PP" >/dev/null 2>&1; then
    got=$("$TOOL" store get TOKEN --store "$S" --passphrase-file "$PP" 2>/dev/null)
    [ "$got" = "$SECRET" ] && pass t1-store-roundtrip || fail "t1-store-roundtrip (got '$got')"
else
    fail t1-store-roundtrip
fi

echo "== T2: store is 0600 and holds no plaintext =="
mode=$(stat -c '%a' "$S" 2>/dev/null || echo '?')
[ "$mode" = "600" ] && pass t2-store-mode || fail "t2-store-mode (mode $mode)"
if grep -qF "$SECRET" "$S" 2>/dev/null; then fail t2-store-no-plaintext; else pass t2-store-no-plaintext; fi

echo "== T3: wrong passphrase is refused =="
printf 'not-the-passphrase\n' > "$WORK/pp2"; chmod 600 "$WORK/pp2"
if "$TOOL" store get TOKEN --store "$S" --passphrase-file "$WORK/pp2" >/dev/null 2>&1; then
    fail t3-wrong-passphrase
else
    pass t3-wrong-passphrase
fi

echo "== T4: store list =="
out=$("$TOOL" store list --store "$S" --passphrase-file "$PP" 2>/dev/null)
case "$out" in *TOKEN*) pass t4-store-list ;; *) fail "t4-store-list [$out]" ;; esac

# --------------------------------------------------------------- daemon ---
echo "== T5: daemon serves secrets =="
"$TOOL" daemon --store "$S" --socket "$SOCK" --passphrase-file "$PP" >"$WORK/d.log" 2>&1 &
DPID=$!
i=0
while [ $i -lt 100 ]; do
    "$TOOL" get TOKEN --socket "$SOCK" >/dev/null 2>&1 && break
    sleep 0.1; i=$((i + 1))
done
got=$("$TOOL" get TOKEN --socket "$SOCK" 2>/dev/null)
[ "$got" = "$SECRET" ] && pass t5-daemon-get || fail "t5-daemon-get (got '$got')"
if "$TOOL" get NOSUCH --socket "$SOCK" >/dev/null 2>&1; then
    fail t5-daemon-missing
else
    pass t5-daemon-missing
fi
mode=$(stat -c '%a' "$SOCK" 2>/dev/null || echo '?')
[ "$mode" = "600" ] && pass t5-socket-mode || fail "t5-socket-mode (mode $mode)"
if [ "$(id -u)" = "0" ]; then
    # root reads any process's environ, dumpable or not; the property is
    # only observable from a different account.
    skip "t5-daemon-not-dumpable (running as root)"
elif cat "/proc/$DPID/environ" >/dev/null 2>&1; then
    fail t5-daemon-not-dumpable
else
    pass t5-daemon-not-dumpable
fi

# ------------------------------------------------------------- delivery ---
echo "== T6: a secret reaches the program and never the process table =="
# Without redaction the environment stays visible, so this is the case where
# "the environ publishes the NAME, never the VALUE" is directly checkable.
"$TOOL" run --no-redact --secret "TOKEN=file:$WORK/token" -- \
        /bin/sh -c "\"$TOOL\" read TOKEN; sleep 3" > "$WORK/out" 2> "$WORK/err" &
RPID=$!
sleep 1.2
got=$(head -n1 "$WORK/out" 2>/dev/null)
[ "$got" = "$SECRET" ] && pass t6-child-reads-secret || fail "t6-child-reads-secret (got '$got')"
envpub=no
valuepub=no
for d in /proc/[0-9]*; do
    cat "$d/environ" 2>/dev/null | tr '\0' '\n' | grep -q '^CONFMASK_SECRET_TOKEN=3$' && envpub=yes
    cat "$d/environ" 2>/dev/null | tr '\0' '\n' | grep -q "^CONFMASK_SECRET_TOKEN=$SECRET$" && valuepub=yes
done
[ "$valuepub" = "no" ] && pass t6-env-value-hidden || fail t6-env-value-hidden
[ "$envpub" = "yes" ] && pass t6-env-name-published || fail "t6-env-name-published"
n=$(sightings "$SECRET")
[ "$n" = "0" ] && pass t6-no-leak || fail "t6-no-leak ($n sightings)"
wait $RPID 2>/dev/null


echo "== T7: several secrets get distinct descriptors =="
printf 'second-value\n' > "$WORK/token2"; chmod 600 "$WORK/token2"
out=$("$TOOL" run --secret "A=file:$WORK/token" --secret "B=file:$WORK/token2" -- \
        /bin/sh -c "printf '%s|%s|%s|%s\n' \"\$CONFMASK_SECRET_A\" \"\$CONFMASK_SECRET_B\" \"\$(\"$TOOL\" read A)\" \"\$(\"$TOOL\" read B)\"" 2>/dev/null)
case "$out" in
    "3|4|$SECRET|second-value") pass t7-two-secrets ;;
    *) fail "t7-two-secrets [$out]" ;;
esac

echo "== T8: exit code and stdio pass through =="
"$TOOL" run -- /bin/sh -c 'exit 42' >/dev/null 2>&1
rc=$?
[ "$rc" = "42" ] && pass t8-exitcode || fail "t8-exitcode (rc $rc)"
out=$(printf 'line-one\n' | "$TOOL" run -- /bin/cat 2>/dev/null)
[ "$out" = "line-one" ] && pass t8-stdio || fail "t8-stdio [$out]"

echo "== T9: program sees its own argv =="
out=$("$TOOL" run -- /bin/sh -c 'printf "%s|%s\n" "$1" "$2"' sh ARG-ONE ARG-TWO 2>/dev/null)
[ "$out" = "ARG-ONE|ARG-TWO" ] && pass t9-argv || fail "t9-argv [$out]"

# ------------------------------------------------------------ redaction ---
echo "== T10-T12: /proc metadata redaction =="
if [ "$HAVE_PTRACE" != "yes" ]; then
    skip "t10-cmdline (ptrace refused on this host)"
    skip "t11-comm (ptrace refused on this host)"
    skip "t12-environ (ptrace refused on this host)"
else
    MK=$(marker)
    "$TOOL" run --label 'ci-runner' -- /bin/sh -c "sleep 6" "$MK" >/dev/null 2>&1 &
    APID=$!
    sleep 0.9
    # comm first: the sightings sweep is slow and the payload must still be
    # alive when it is sampled.
    n=$(comm_count 'ci-runner')
    [ "$n" -ge 1 ] && pass t11-comm || fail "t11-comm ($n)"
    n=$(sightings "$MK")
    [ "$n" = "0" ] && pass t10-cmdline || fail "t10-cmdline ($n sightings)"
    n=0
    for d in /proc/[0-9]*; do
        if cat "$d/environ" 2>/dev/null | tr '\0' '\n' | grep -qF "$SECRET"; then n=$((n + 1)); fi
    done
    [ "$n" = "0" ] && pass t12-environ || fail "t12-environ ($n)"
    kill "$APID" 2>/dev/null
    wait "$APID" 2>/dev/null
fi

echo "== T13: redaction does not disturb secret delivery =="
if [ "$HAVE_PTRACE" != "yes" ]; then
    skip "t13-redact-secret (ptrace refused on this host)"
else
    got=$("$TOOL" run --label 'ci-runner' --secret "TOKEN=file:$WORK/token" -- \
            /bin/sh -c "\"$TOOL\" read TOKEN" 2>/dev/null)
    [ "$got" = "$SECRET" ] && pass t13-redact-secret || fail "t13-redact-secret (got '$got')"
    n=$(sightings "$SECRET")
    [ "$n" = "0" ] && pass t13-redact-no-leak || fail "t13-redact-no-leak ($n)"
fi

# ------------------------------------------------------------ isolation ---
echo "== T14: isolation gives the payload its own /proc =="
if [ "$HAVE_USERNS" != "yes" ]; then
    skip "t14-isolate (no unprivileged user namespaces on this host)"
else
    outer=$(ls /proc | grep -c '^[0-9]*$')
    inner=$("$TOOL" run --isolate -- /bin/sh -c 'ls /proc | grep -c "^[0-9]*$"' 2>/dev/null)
    if [ -n "$inner" ] && [ "$inner" -lt "$outer" ]; then
        pass "t14-isolate (inner pids $inner < host pids $outer)"
    else
        fail "t14-isolate (inner '$inner' host '$outer')"
    fi
    out=$("$TOOL" run --isolate -- /bin/sh -c 'echo hi > /tmp/confmask-isolation-probe; cat /tmp/confmask-isolation-probe' 2>/dev/null)
    if [ "$out" = "hi" ] && [ ! -e /tmp/confmask-isolation-probe ]; then
        pass t14-private-tmp
    else
        fail "t14-private-tmp (out '$out')"
    fi
fi

echo "== T15: the same guarantees without root =="
if [ "$(id -u)" != "0" ] || ! command -v setuidgid >/dev/null 2>&1; then
    skip "t15-unprivileged (needs root plus a setuidgid helper to drop accounts)"
else
    got=$(setuidgid 1500 "$TOOL" run --isolate -- /bin/sh -c 'id -u' 2>/dev/null)
    if [ "$got" = "0" ]; then
        pass t15-isolate-unprivileged
    else
        fail "t15-isolate-unprivileged (inner uid '$got')"
    fi
    MK=$(marker)
    setuidgid 1500 "$TOOL" run --label 'ci-runner' -- /bin/sh -c "sleep 5" "$MK" >/dev/null 2>&1 &
    UPID=$!
    sleep 0.9
    n=$(comm_count 'ci-runner')
    [ "$n" -ge 1 ] && pass t15-redact-unprivileged || fail "t15-redact-unprivileged ($n)"
    n=$(sightings "$MK")
    [ "$n" = "0" ] && pass t15-redact-unprivileged-cmdline || fail "t15-redact-unprivileged-cmdline ($n)"
    kill "$UPID" 2>/dev/null
    wait "$UPID" 2>/dev/null
fi

# ---------------------------------------------------------------- done ---
kill $DPID 2>/dev/null
wait $DPID 2>/dev/null

echo
if [ "$FAIL" = "0" ]; then
    echo "== VERDICT: ALL-PASS (skipped $SKIP) =="
else
    echo "== VERDICT: FAILURES (skipped $SKIP) =="
fi
exit $FAIL

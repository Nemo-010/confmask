#!/bin/sh
# ============================================================================
# confmask kernel audit suite -- the kernel itself must never receive the
# real argv of a masked exec.
#
# The observer is `testcases auditwatch`: a NETLINK_AUDIT client that logs
# every EXECVE, PROCTITLE and SYSCALL record for execve and execveat.
# Root only.  It needs CONFIG_AUDIT and CONFIG_AUDITSYSCALL.  One audit
# daemon can be registered at a time, so auditd must not run.
#
# Every confmask command line below passes the real program and arguments
# through --args-from-fd.  The exec of confmask itself is not masked, so a
# secret on its command line would show in the audit log and hide the
# result of the masked exec.  Assertions run only after the watcher stops,
# so the assertion commands do not enter the log.
#
#   A1  control: an unmasked exec shows its real argument in the log
#       (catches a blind observer, which would make every negative pass)
#   A2  masked ELF exec: label in the EXECVE record, secret nowhere
#       (catches an entry swap that stops hiding argv from the kernel)
#   A3  masked tree: no secret from any exec in the tree
#       (catches a swap that works for the first exec only)
#   A4  environment variable on the confmask exec: argv-only assertion
#   A5  script exec: INFO only, documents the limit
#   A6  watcher exits cleanly and removes its rule
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

require_bins || { echo "FATAL: binaries missing (build failed)"; exit 2; }

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
info() { echo "INFO $*"; }

verdict() {
    echo "== VERDICT: FAIL=$FAIL $* =="
}

if [ "$(id -u)" != 0 ]; then
    echo "SKIP audit (needs root)"
    verdict SKIP
    exit 0
fi

D=/tmp/confmask-audit.$$
mkdir -p "$D" || { echo "FATAL: cannot create $D"; exit 2; }
OUT="$D/audit.log"
WPID=""

# Audit rules live only while the watcher lives, so stopping the watcher
# removes them.  This runs on every exit path.
cleanup() {
    if [ -n "$WPID" ] && kill -0 "$WPID" 2>/dev/null; then
        : > "$OUT.stop"
        kill -TERM "$WPID" 2>/dev/null
        wait "$WPID" 2>/dev/null
    fi
    rm -rf "$D"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# mkargs FILE ARG...   NUL-separated vector for --args-from-fd
mkargs() {
    f="$1"; shift
    : > "$f"
    for a in "$@"; do
        printf '%s\0' "$a" >> "$f"
    done
}

# hexof STRING   uppercase hex, as the kernel writes it
hexof() {
    printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'
}

# seen STRING   true when STRING is in the log as text or as hex
seen() {
    grep -qF -- "$1" "$OUT" && return 0
    h=$(hexof "$1")
    grep -qi -- "$h" "$OUT"
}

# ------------------------------------------------------- start the watcher
"$CASES" auditwatch 120 "$OUT" 2>"$D/watch.err" &
WPID=$!

i=0
while [ ! -s "$OUT.ready" ] && [ "$i" -lt 100 ]; do
    kill -0 "$WPID" 2>/dev/null || break
    sleep 0.1 2>/dev/null || sleep 1
    i=$((i + 1))
done
READY=$(cat "$OUT.ready" 2>/dev/null || echo "no ready file")
case "$READY" in
    ok) ;;
    skip:*)
        echo "SKIP audit (${READY#skip: })"
        verdict SKIP
        exit 0
        ;;
    fail:*)
        fail "audit-daemon ${READY#fail: }"
        verdict
        exit 1
        ;;
    *)
        echo "SKIP audit (watcher did not start: $READY; $(tr '\n' ' ' < "$D/watch.err"))"
        verdict SKIP
        exit 0
        ;;
esac

# does this confmask build accept --args-from-fd?
mkargs "$D/probe.args" "$CASES" echoargs probe
if "$TOOL" -q -l probe --args-from-fd 3 3<"$D/probe.args" >/dev/null 2>&1; then
    HAVE_FD=1
else
    HAVE_FD=0
fi

# ------------------------------------------------------------ run the cases
SECRET_CTRL=MK-AUD-CTRL-SECRET
SECRET1=MK-AUD-SECRET1
SECRET2=MK-AUD-SECRET2
SECRET3=MK-AUD-SECRET3
SECRET_ENV=MK-AUD-ENVSECRET
SECRET_SCRIPT=MK-AUD-SCRIPT-ARG
LABEL=aud-label

# A1 run: no confmask.
"$CASES" echoargs "$SECRET_CTRL" >/dev/null 2>&1

if [ "$HAVE_FD" = 1 ]; then
    # A2 run: masked ELF exec.
    mkargs "$D/a2.args" "$CASES" echoargs "$SECRET1"
    "$TOOL" -q -l "$LABEL" --args-from-fd 3 3<"$D/a2.args" >/dev/null 2>&1

    # A3 run: masked tree with two children.
    mkargs "$D/a3.args" sh -c "$CASES echoargs $SECRET2; $CASES echoargs $SECRET3"
    "$TOOL" -q -l "$LABEL" --args-from-fd 3 3<"$D/a3.args" >/dev/null 2>&1

    # A4 run: the secret is an environment variable of the confmask exec.
    # A shell prefix assignment keeps it out of any argv.
    mkargs "$D/a4.args" "$CASES" echoargs env-case
    MK_AUD_ENV="$SECRET_ENV" "$TOOL" -q -l "$LABEL" --args-from-fd 3 3<"$D/a4.args" >/dev/null 2>&1

    # A5 run: shebang script.
    printf '#!/bin/sh\nexit 0\n' > "$D/script.sh"
    chmod 755 "$D/script.sh"
    mkargs "$D/a5.args" "$D/script.sh" "$SECRET_SCRIPT"
    "$TOOL" -q -l "$LABEL" --args-from-fd 3 3<"$D/a5.args" >/dev/null 2>&1
fi

# Let the kernel audit queue flush, then stop the watcher.
sleep 1
: > "$OUT.stop"
wait "$WPID"
WRC=$?
WPID=""

# ------------------------------------------------------------ assertions
# The kernel decides how much of an EXECVE record it sends.  On a kernel
# that truncates the record before the argument text (observed on Alpine
# linux-virt 6.12.114: the payload ends at `a0=`), this observer cannot
# see argv at all and every negative below would pass for free.  Detect
# that case and skip with the reason, rather than reporting a green run
# that proves nothing.
ARGV_RECORDS=$(grep -c 'type=EXECVE .*a0="[^"]' "$OUT" 2>/dev/null | tr -d '\n')
[ -n "$ARGV_RECORDS" ] || ARGV_RECORDS=0
info "audit: $ARGV_RECORDS EXECVE record(s) carry argument text"

# A1
if seen "$SECRET_CTRL"; then
    pass a1-control-observer-sees-real-argv
    CONTROL_OK=1
else
    # Without argument text in the record the observer is blind, and a
    # green negative would prove nothing.  This kernel truncates the
    # EXECVE record before the argument text (the payload ends at `a0=`),
    # so the suite skips and says why instead of claiming a result.
    sample=$(grep -m1 'type=EXECVE' "$OUT" | cut -c1-120)
    echo "SKIP audit (control secret not in the audit log after $(wc -l < "$OUT" | tr -d ' ') lines; sample record: $sample)"
    verdict SKIP
    exit 0
fi
if grep -q "^DECODED .*$SECRET_CTRL" "$OUT"; then
    info "a1 decoded PROCTITLE shows the control secret"
else
    info "a1 decoded PROCTITLE did not show the control secret (EXECVE record is the check)"
fi

# negative CASE-NAME SECRET...   all secrets absent from the whole log
negative() {
    name="$1"; shift
    if [ "$CONTROL_OK" != 1 ]; then
        fail "$name (control a1 failed, observer is blind)"
        return
    fi
    bad=""
    for s in "$@"; do
        if seen "$s"; then
            bad="$bad $s"
        fi
    done
    if [ -z "$bad" ]; then
        pass "$name"
    else
        fail "$name (kernel audit log shows:$bad)"
    fi
}

# label_count N   number of EXECVE records whose a0 is the label
label_count() {
    grep -cE "type=EXECVE .* a0=\"$LABEL\"" "$OUT" || true
}

if [ "$HAVE_FD" != 1 ]; then
    fail "a2-masked-elf (confmask lacks --args-from-fd)"
    fail "a3-masked-tree (confmask lacks --args-from-fd)"
    fail "a4-environ-run (confmask lacks --args-from-fd)"
else
    # A2
    negative a2-masked-elf-secret-absent "$SECRET1"
    n=$(label_count)
    if [ "$n" -ge 1 ]; then
        pass a2-masked-elf-label-in-execve
    else
        fail "a2-masked-elf-label-in-execve (no EXECVE record with a0=\"$LABEL\")"
    fi

    # A3: sh plus two children carry the label (3 records), A2 and A4 add one each.
    # A5 is not counted.
    negative a3-masked-tree-secrets-absent "$SECRET2" "$SECRET3"
    if [ "$n" -ge 5 ]; then
        pass a3-masked-tree-labels-in-execve
    else
        fail "a3-masked-tree-labels-in-execve ($n label records in total, want at least 5)"
    fi

    # A4: audit records hold argv only, so the assertion covers argv only.
    negative a4-env-secret-absent-from-argv-log "$SECRET_ENV"
fi

# A5: documents the limit, asserts nothing.
if [ "$HAVE_FD" = 1 ]; then
    if seen "$SECRET_SCRIPT"; then
        info "a5 script exec: audit log SHOWS the script argument (expected: the kernel copies real argv for scripts)"
    else
        info "a5 script exec: audit log does not show the script argument"
    fi
    if grep -qF "$D/script.sh" "$OUT"; then
        info "a5 script exec: audit log shows the script path or interpreter line"
    else
        info "a5 script exec: audit log does not show the script path"
    fi
fi

# A6
if [ "$WRC" = 0 ] && ! grep -qE "DEL_RULE failed|restore failed" "$D/watch.err"; then
    pass a6-watcher-clean-exit-rule-removed
else
    fail "a6-watcher-clean-exit (rc=$WRC; $(tr '\n' ' ' < "$D/watch.err"))"
fi

verdict
[ "$FAIL" = 0 ]

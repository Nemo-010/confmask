#!/bin/sh
# Full-suite orchestrator.
#
# Binaries (see refresh_bins in lib.sh):
#   TESTBIN_DIR=DIR   copy prebuilt binaries from DIR
#   cargo present     always `cargo build --release --bins`, then copy, and
#                     fail when a binary is older than any src/**/*.rs
#   no cargo          use the binaries already in tests/ (the VM case)
#
# Works on any Linux with ptrace allowed.  On ptrace-free hosts use
# vm/run.sh, which runs this script inside a QEMU micro-VM.
set -u
cd "$(dirname "$0")"
. ./lib.sh

refresh_bins || { echo "################ FINAL: FAILURES (binaries)"; exit 2; }
CONFMASK_BINS_READY=1
export CONFMASK_BINS_READY

FAIL=0
for suite in validate suite stress edge daemon daemon_neg options core audit; do
    if [ ! -f "$suite.sh" ]; then
        echo "SKIP $suite (absent)"
        continue
    fi
    echo "################ $suite.sh"
    sh "$suite.sh" || FAIL=1
done
echo "################ FINAL: $([ $FAIL = 0 ] && echo ALL-PASS || echo FAILURES)"
exit $FAIL

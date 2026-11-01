#!/bin/sh
# ============================================================================
# VM test harness: run the full ptrace test suites inside a minimal QEMU
# micro-VM, for hosts where ptrace itself is unavailable (locked-down
# containers, seccomp-sandboxed CI).  Self-contained and asserting.
#
#   vm/run.sh              boot the pinned 6.12 kernel, run tests/run.sh as
#                          root, then again as uid 1000.  Exit 0 only when
#                          both passes print "FINAL: ALL-PASS" (root result
#                          VM-HARNESS-RESULT:0 and non-root result
#                          VM-HARNESS-RESULT-NONROOT:0).
#   vm/run.sh --old-kernel boot only the pinned 5.15 kernel (x86_64) with
#                          the same initramfs and the same two passes.
#                          Not part of the default run.
#
# Environment: VM_TIMEOUT seconds per boot.
#
# Cached under vm/cache/: pinned Alpine apks (name and sha256 in
# common.sh), the unpacked kernel and busybox, the initramfs and the log.
# Everything runs under TCG (no KVM needed).
# ============================================================================
set -eu
. "$(dirname "$0")/common.sh"

OLD=0
case "${1:-}" in
    "") ;;
    --old-kernel) OLD=1 ;;
    -h|--help) sed -n '2,/^set -eu/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "usage: vm/run.sh [--old-kernel]" >&2; exit 2 ;;
esac

command -v "$QEMU" >/dev/null || { echo "missing: $QEMU"; exit 2; }
command -v cpio >/dev/null   || { echo "missing: cpio";   exit 2; }
command -v curl >/dev/null   || { echo "missing: curl";   exit 2; }
command -v rustup >/dev/null || { echo "missing: rustup (need the musl target)"; exit 2; }

# ------------------------------------------------------------- fetch parts
if [ "$OLD" = 1 ]; then
    vm_fetch_parts old || exit 2
    LOG="$CACHE/vm-output-old.log"
    echo "kernel: $OLD_KERNEL_APK_VERSION (pinned sha256 $OLD_KERNEL_SHA256)"
else
    vm_fetch_parts || exit 2
    LOG="$CACHE/vm-output.log"
    echo "kernel: $KERNEL_APK_VERSION (pinned sha256 $KERNEL_SHA256)"
fi

# ------------------------------------------------------------ build binary
rustup target list --installed | grep -q "^$MUSL_TARGET$" \
    || rustup target add "$MUSL_TARGET"

cd "$ROOT"
cargo build --release --target "$MUSL_TARGET" --bins

# The 32-bit probe for core.sh.  Non-fatal: a missing target or linker
# leaves tests/testcases32 absent and the 32-bit case reports it.
rm -f "$ROOT/tests/testcases32"
if [ "$ARCH" = x86_64 ]; then
    I686=i686-unknown-linux-musl
    if ! rustup target list --installed | grep -q "^$I686$"; then
        rustup target add "$I686" || echo "NOTE: cannot install target $I686"
    fi
    if cargo build --release --target "$I686" --bin confmask-testcases; then
        cp "${CARGO_TARGET_DIR:-$ROOT/target}/$I686/release/confmask-testcases" "$ROOT/tests/testcases32"
    else
        echo "NOTE: i686 build failed; tests/testcases32 not produced (32-bit case will not run)"
    fi
else
    echo "NOTE: no 32-bit probe build for $ARCH"
fi

# ------------------------------------------------------------- initramfs
# repack on every run: it takes well under a second and removes a whole
# class of stale-artifact failures
echo "packing initramfs"
STAGE="$CACHE/stage"
vm_stage "$STAGE"
cp "$HERE/init" "$STAGE/init"
chmod +x "$STAGE/init"
INITRD="$CACHE/initramfs.cpio.gz"
vm_pack "$STAGE" "$INITRD"

# ------------------------------------------------------------------- boot
echo "booting micro-VM ($QEMU, TCG, console $CONSOLE; output also in $LOG) ..."
vm_boot "$KERNEL_IMAGE" "$INITRD" "$LOG" "$VM_TIMEOUT"
QEMU_RC=$VM_QEMU_RC

# the patterns end at the colon so the two result lines never match each other
RESULT=$(grep -o 'VM-HARNESS-RESULT:[0-9]*' "$LOG" | tail -1 | cut -d: -f2 || true)
RESULT_NR=$(grep -o 'VM-HARNESS-RESULT-NONROOT:[0-9]*' "$LOG" | tail -1 | cut -d: -f2 || true)
echo
echo "================= VM HARNESS SUMMARY ================="
grep 'FINAL:' "$LOG" | tail -2 || true
if [ "${RESULT:-}" = "0" ] && [ "${RESULT_NR:-}" = "0" ]; then
    echo "VM-HARNESS: ALL-PASS (root and non-root; see $LOG)"
    exit 0
else
    echo "VM-HARNESS: FAILED (qemu_rc=$QEMU_RC root=${RESULT:-none} nonroot=${RESULT_NR:-none}, see $LOG)"
    exit 1
fi

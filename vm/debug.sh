#!/bin/sh
# VM debugging: boot the micro-VM and run ONE shell script inside it.
#   vm/debug.sh path/to/check.sh
# The script runs as root with PATH=/bin:/app:/app/tests after boot, on the
# host architecture (uname -m: x86_64 or aarch64).  The binaries come from
# target/<arch>-unknown-linux-musl/release, so run `cargo build --release
# --target <arch>-unknown-linux-musl --bins` first.
set -eu
. "$(dirname "$0")/common.sh"
SCRIPT="${1:?usage: vm/debug.sh SCRIPT.sh}"

command -v "$QEMU" >/dev/null || { echo "missing: $QEMU"; exit 2; }
command -v cpio >/dev/null   || { echo "missing: cpio";   exit 2; }

vm_fetch_parts || exit 2
cd "$ROOT"
STAGE="$CACHE/stage-debug"
vm_stage "$STAGE"
cp "$SCRIPT" "$STAGE/check.sh"
chmod +x "$STAGE/check.sh"
cat > "$STAGE/init" <<'INIT'
#!/bin/busybox sh
export PATH=/bin:/app:/app/tests
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
echo "=== VM ready, arch $(uname -m)"
sh /check.sh
echo "CHECK-RC=$?"
echo DONE-DEBUG
poweroff -f
while :; do sleep 1; done
INIT
chmod +x "$STAGE/init"
INITRD="$CACHE/initramfs-debug.cpio.gz"
vm_pack "$STAGE" "$INITRD"

LOG="$CACHE/vm-debug.log"
vm_boot "$KERNEL_IMAGE" "$INITRD" "$LOG" 180

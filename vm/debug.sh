#!/bin/sh
# Boot the micro-VM and run ONE shell script inside it.
#   vm/debug.sh vm/cases/whatever.sh
# The script runs with PATH=/bin:/app:/app/tests after boot.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
CACHE="$HERE/cache"
SCRIPT="${1:?usage: vm/debug.sh SCRIPT.sh}"
MUSL_TARGET=x86_64-unknown-linux-musl

[ -f "$CACHE/kernel/boot/vmlinuz-virt" ] || { echo "run vm/run.sh once first"; exit 2; }

cd "$ROOT"
STAGE="$CACHE/stage-debug"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/app/tests" "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/tmp"
cp "$CACHE/busybox/bin/busybox.static" "$STAGE/bin/busybox"
cp "target/$MUSL_TARGET/release/confmask" "$STAGE/app/tests/confmask"
cp tests/lib.sh tests/run.sh "$STAGE/app/tests/"
cp "$SCRIPT" "$STAGE/check.sh"
chmod +x "$STAGE/app/tests/"*.sh "$STAGE/app/tests/confmask" "$STAGE/check.sh"

cat > "$STAGE/init" <<'EOF'
#!/bin/busybox sh
export PATH=/bin:/app:/app/tests
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
echo "=== VM ready (kernel $(uname -r))"
sh /check.sh
echo "CHECK-RC=$?"
echo DONE-DEBUG
poweroff -f
while :; do sleep 1; done
EOF
chmod +x "$STAGE/init"

(cd "$STAGE" && find . | cpio -o -H newc --quiet) | gzip -1 > "$CACHE/initramfs-debug.cpio.gz"

timeout 300 qemu-system-x86_64 \
    -m 512M -smp 2 \
    -kernel "$CACHE/kernel/boot/vmlinuz-virt" \
    -initrd "$CACHE/initramfs-debug.cpio.gz" \
    -append "console=ttyS0 rdinit=/init quiet panic=-1" \
    -nographic -no-reboot -monitor none 2>&1 | grep -v APK

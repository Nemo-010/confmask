#!/bin/sh
# ============================================================================
# Micro-VM test harness.
#
# confmask's two strongest modes need kernel facilities that sandboxes
# routinely refuse: `ptrace` (banned by most seccomp profiles) and
# unprivileged user namespaces (disabled in many hardened images).  This
# script boots a real kernel under QEMU TCG and runs the whole suite inside
# it, so those paths are verified rather than skipped.
#
#   vm/run.sh            -> boots, runs tests/run.sh, exits 0 only on
#                           "VERDICT: ALL-PASS"
#
# Needs: qemu-system-x86_64, cpio, curl, rustup (for the musl target).
# No KVM, no root.
# ============================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
CACHE="$HERE/cache"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64)
        QEMU=qemu-system-x86_64
        KERNEL=boot/vmlinuz-virt
        ALPINE_ARCH=x86_64
        MUSL_TARGET=x86_64-unknown-linux-musl
        ;;
    *)
        echo "unsupported arch: $ARCH"; exit 2 ;;
esac

command -v "$QEMU" >/dev/null || { echo "missing: $QEMU"; exit 2; }
command -v cpio >/dev/null   || { echo "missing: cpio";   exit 2; }
CC="${CC:-cc}"
command -v "$CC" >/dev/null  || { echo "missing: $CC (for the test-only setuidgid helper)"; exit 2; }
command -v rustup >/dev/null || { echo "missing: rustup"; exit 2; }

mkdir -p "$CACHE"

fetch_apk() { # prefix, output-file
    p="$1"; out="$2"
    [ -s "$out" ] && return 0
    base="https://dl-cdn.alpinelinux.org/alpine/v3.22/main/$ALPINE_ARCH"
    name=$(curl -fsSL "$base/" | grep -o "href=\"$p-[0-9][0-9.]*-r[0-9]*\.apk\"" \
        | sed 's/href="//; s/"//' | sort -V | tail -1)
    [ -n "$name" ] || { echo "could not find $p apk"; return 1; }
    echo "fetching $name"
    curl -fsSL -o "$out" "$base/$name"
}

fetch_apk linux-virt     "$CACHE/linux-virt.apk"
fetch_apk busybox-static "$CACHE/busybox-static.apk"

mkdir -p "$CACHE/kernel" "$CACHE/busybox"
[ -f "$CACHE/kernel/$KERNEL" ] || tar -xzf "$CACHE/linux-virt.apk" -C "$CACHE/kernel" "$KERNEL" 2>/dev/null
[ -f "$CACHE/busybox/bin/busybox.static" ] \
    || tar -xzf "$CACHE/busybox-static.apk" -C "$CACHE/busybox" bin/busybox.static 2>/dev/null

rustup target list --installed | grep -q "^$MUSL_TARGET$" || rustup target add "$MUSL_TARGET"

cd "$ROOT"
cargo build --release --target "$MUSL_TARGET" --bin confmask

STAGE="$CACHE/stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/app/tests" "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/tmp"
cp "$CACHE/busybox/bin/busybox.static" "$STAGE/bin/busybox"
cp "target/$MUSL_TARGET/release/confmask" "$STAGE/app/tests/confmask"
cp tests/lib.sh tests/run.sh "$STAGE/app/tests/"
"$CC" -O1 -static -w -o "$STAGE/bin/setuidgid" vm/setuidgid.c
chmod +x "$STAGE/app/tests/"*.sh "$STAGE/app/tests/confmask" "$STAGE/bin/setuidgid"

cat > "$STAGE/init" <<'EOF'
#!/bin/busybox sh
export PATH=/bin:/app:/app/tests
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
# an unprivileged account, so the suites can prove the "no root" claim
echo 'cmtest:x:1500:1500:cmtest:/tmp:/bin/sh' >> /etc/passwd 2>/dev/null || true
echo "=== confmask VM: boot ok, kernel $(uname -r)"
cd /app/tests
sh run.sh 2>&1
rc=$?
echo "VM-HARNESS-RESULT:$rc"
sleep 1
poweroff -f
while :; do sleep 1; done
EOF
chmod +x "$STAGE/init"

INITRD="$CACHE/initramfs.cpio.gz"
(cd "$STAGE" && find . | cpio -o -H newc --quiet) | gzip -1 > "$INITRD"

LOG="$CACHE/vm-output.log"
: > "$LOG"
echo "booting micro-VM ($QEMU, TCG; output also in $LOG) ..."
set +e
tail -f "$LOG" &
TAIL_PID=$!
timeout 1200 "$QEMU" \
    -m 512M -smp 2 \
    -kernel "$CACHE/kernel/$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 rdinit=/init quiet panic=-1" \
    -nographic -no-reboot -monitor none >>"$LOG" 2>&1
QEMU_RC=$?
kill "$TAIL_PID" 2>/dev/null
set -e

RESULT=$(grep -o 'VM-HARNESS-RESULT:[0-9]*' "$LOG" | tail -1 | cut -d: -f2)
FINAL=$(grep 'VERDICT:' "$LOG" | tail -1)
echo
echo "================= VM HARNESS SUMMARY ================="
[ -n "$FINAL" ] && echo "$FINAL"
if [ "${RESULT:-}" = "0" ]; then
    echo "VM-HARNESS: ALL-PASS (see $LOG)"
    exit 0
else
    echo "VM-HARNESS: FAILED (qemu_rc=$QEMU_RC result=${RESULT:-none}, see $LOG)"
    exit 1
fi

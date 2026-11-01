#!/bin/sh
# Shared configuration and helpers for vm/run.sh and vm/debug.sh.
# Source this file; do not execute it.  POSIX sh: no brace expansion,
# no [[, no local.
#
# Every Alpine package is pinned by file name and sha256.  A download
# whose hash differs is refused and removed.

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
CACHE="$HERE/cache"
ARCH="$(uname -m)"
# Architecture to build and boot.  Defaults to this host.  Set
# CONFMASK_VM_ARCH=aarch64 on an x86_64 host to exercise the aarch64
# harness: it needs qemu-system-aarch64 and the aarch64 musl target.
# HERE, ROOT and CACHE come from $0, so source this file from vm/run.sh
# or vm/debug.sh, never from a script in another directory.
ARCH="${CONFMASK_VM_ARCH:-$ARCH}"
ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine"

# ------------------------------------------------------------ pinned parts
# repository branch, file names and sha256 of the packages in use.
BB_REPO="v3.22/main"
BB_APK_VERSION="busybox-static-1.37.0-r20.apk"
KERNEL_REPO="v3.22/main"
KERNEL_APK_VERSION="linux-virt-6.12.114-r0.apk"

# Old-kernel boot (x86_64 only): Alpine v3.17 ships linux-virt 5.15.x.
OLD_KERNEL_REPO="v3.17/main"
OLD_KERNEL_APK_VERSION="linux-virt-5.15.208-r0.apk"
OLD_KERNEL_SHA256="f7e694a9554276bbd4fdc2a3b542bbd2edfb10954b3e976e1c7129ca5c082c86"

case "$ARCH" in
    x86_64)
        QEMU=qemu-system-x86_64
        QEMU_MACHINE=""
        CONSOLE=ttyS0
        ALPINE_ARCH=x86_64
        MUSL_TARGET=x86_64-unknown-linux-musl
        KERNEL_SHA256="82b7fee968e553fb34df7102e9622c969872810b729068106ed49a03c0ba4b8a"
        BB_SHA256="488ad6efd04b5a722719e79f8e0dcc2c24afd6758867af3ce41b04839e60c74b"
        VM_TIMEOUT="${VM_TIMEOUT:-2400}"
        ;;
    aarch64)
        # Not run yet: the aarch64 harness has never booted.  The pins
        # were hashed from the Alpine v3.22 aarch64 repository.
        QEMU=qemu-system-aarch64
        QEMU_MACHINE="-machine virt -cpu cortex-a57"
        CONSOLE=ttyAMA0
        ALPINE_ARCH=aarch64
        MUSL_TARGET=aarch64-unknown-linux-musl
        KERNEL_SHA256="345b2d561443cd8c978cbcc0f36f2374b3ef702debb747221384b4ddc07d6a77"
        BB_SHA256="ee469aee2958feffd7f64dd96655704025ff60af614f77a1d7323dc237c34da2"
        VM_TIMEOUT="${VM_TIMEOUT:-7200}"
        ;;
    *)
        echo "unsupported arch: $ARCH" >&2
        exit 2
        ;;
esac

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# fetch_pinned REPO NAME SHA256 OUT [LEGACY-FILE]
# Leaves OUT in place only when its sha256 equals SHA256.
fetch_pinned() {
    fp_repo="$1"; fp_name="$2"; fp_want="$3"; fp_out="$4"; fp_legacy="${5:-}"
    if [ ! -s "$fp_out" ] && [ -n "$fp_legacy" ] && [ -s "$fp_legacy" ] \
        && [ "$(sha256_of "$fp_legacy")" = "$fp_want" ]; then
        mv "$fp_legacy" "$fp_out"
    fi
    if [ -s "$fp_out" ]; then
        fp_got="$(sha256_of "$fp_out")"
        [ "$fp_got" = "$fp_want" ] && return 0
        echo "cached $fp_out has sha256 $fp_got, want $fp_want: discarding" >&2
        rm -f "$fp_out"
    fi
    fp_url="$ALPINE_BASE/$fp_repo/$ALPINE_ARCH/$fp_name"
    echo "fetching $fp_url"
    if ! curl -fsSL -o "$fp_out.part" "$fp_url"; then
        rm -f "$fp_out.part"
        echo "download failed: $fp_url" >&2
        return 1
    fi
    fp_got="$(sha256_of "$fp_out.part")"
    if [ "$fp_got" != "$fp_want" ]; then
        rm -f "$fp_out.part"
        echo "REFUSING $fp_name: sha256 is $fp_got, pinned $fp_want" >&2
        return 1
    fi
    mv "$fp_out.part" "$fp_out"
}

# zboot_to_image IN OUT: unwrap an EFI zboot kernel (arm64 Alpine) to the
# raw Image that `qemu -kernel` loads.  The header holds the payload
# offset at byte 8 and the payload size at byte 12 (little-endian u32).
zboot_to_image() {
    zb_off="$(od -An -t u4 -j 8 -N 4 "$1" | tr -d ' ')"
    zb_size="$(od -An -t u4 -j 12 -N 4 "$1" | tr -d ' ')"
    tail -c "+$((zb_off + 1))" "$1" | head -c "$zb_size" | gzip -dc > "$2"
}

# vm_fetch_parts [old]
# Downloads and unpacks the pinned kernel and busybox.
# Sets KERNEL_IMAGE (what -kernel loads) and BUSYBOX_BIN.
vm_fetch_parts() {
    mkdir -p "$CACHE"
    if [ "${1:-}" = old ]; then
        [ "$ARCH" = x86_64 ] || { echo "no pinned old kernel for $ARCH" >&2; return 1; }
        kv_repo="$OLD_KERNEL_REPO"; kv_apk="$OLD_KERNEL_APK_VERSION"; kv_sha="$OLD_KERNEL_SHA256"
        kv_legacy=""
    else
        kv_repo="$KERNEL_REPO"; kv_apk="$KERNEL_APK_VERSION"; kv_sha="$KERNEL_SHA256"
        kv_legacy=""
        [ "$ARCH" = x86_64 ] && kv_legacy="$CACHE/linux-virt.apk"
    fi
    fetch_pinned "$kv_repo" "$kv_apk" "$kv_sha" "$CACHE/$ARCH-$kv_apk" "$kv_legacy" || return 1
    bb_legacy=""
    [ "$ARCH" = x86_64 ] && bb_legacy="$CACHE/busybox-static.apk"
    fetch_pinned "$BB_REPO" "$BB_APK_VERSION" "$BB_SHA256" "$CACHE/$ARCH-$BB_APK_VERSION" "$bb_legacy" || return 1

    kdir="$CACHE/kernel-$ARCH-${kv_apk%.apk}"
    mkdir -p "$kdir"
    [ -f "$kdir/boot/vmlinuz-virt" ] \
        || tar -xzf "$CACHE/$ARCH-$kv_apk" -C "$kdir" boot/vmlinuz-virt
    KERNEL_IMAGE="$kdir/boot/vmlinuz-virt"
    if [ "$ARCH" = aarch64 ]; then
        [ -s "$kdir/Image" ] || zboot_to_image "$kdir/boot/vmlinuz-virt" "$kdir/Image"
        KERNEL_IMAGE="$kdir/Image"
    fi

    bdir="$CACHE/busybox-$ARCH-${BB_APK_VERSION%.apk}"
    mkdir -p "$bdir"
    [ -f "$bdir/bin/busybox.static" ] \
        || tar -xzf "$CACHE/$ARCH-$BB_APK_VERSION" -C "$bdir" bin/busybox.static
    BUSYBOX_BIN="$bdir/bin/busybox.static"
}

# Suites copied into the initramfs, in run order.  A suite that does not
# exist yet is skipped by tests/run.sh and not copied here.
VM_SUITES="validate suite stress edge daemon daemon_neg options core audit"

# vm_stage STAGE-DIR
# Lays out the initramfs tree: busybox, binaries, suites.
vm_stage() {
    st="$1"
    rm -rf "$st"
    # explicit paths, not brace expansion: /bin/sh is dash on Debian/Ubuntu
    mkdir -p "$st/bin" "$st/app/tests" "$st/dev" "$st/proc" "$st/sys" "$st/tmp"
    cp "$BUSYBOX_BIN" "$st/bin/busybox"
    rel="$ROOT/target/$MUSL_TARGET/release"
    cp "$rel/confmask"           "$st/app/tests/confmask"
    cp "$rel/confmaskd"          "$st/app/tests/confmaskd"
    cp "$rel/confmask-testcases" "$st/app/tests/testcases"
    if [ -x "$rel/confmask-protocases" ]; then
        cp "$rel/confmask-protocases" "$st/app/tests/protocases"
    else
        echo "NOTE: confmask-protocases not built; daemon_neg will be missing it"
    fi
    if [ -x "$ROOT/tests/testcases32" ]; then
        cp "$ROOT/tests/testcases32" "$st/app/tests/testcases32"
    else
        echo "NOTE: tests/testcases32 absent; the 32-bit case in core.sh cannot run"
    fi
    cp "$ROOT/tests/lib.sh" "$ROOT/tests/run.sh" "$st/app/tests/"
    for s in $VM_SUITES; do
        if [ -f "$ROOT/tests/$s.sh" ]; then
            cp "$ROOT/tests/$s.sh" "$st/app/tests/"
        else
            echo "NOTE: tests/$s.sh absent, not copied"
        fi
    done
    chmod +x "$st"/app/tests/*
}

# vm_pack STAGE-DIR OUT.cpio.gz
vm_pack() {
    # -R 0:0: files are root-owned inside the VM whoever owns them here
    (cd "$1" && find . | cpio -o -H newc -R 0:0 --quiet) | gzip -1 > "$2"
}

# vm_boot KERNEL INITRD LOG TIMEOUT-SECONDS
# Runs QEMU under TCG; returns QEMU's exit status in VM_QEMU_RC.
vm_boot() {
    vb_kernel="$1"; vb_initrd="$2"; vb_log="$3"; vb_timeout="$4"
    : > "$vb_log"
    set +e
    tail -f "$vb_log" &
    vb_tail=$!
    # QEMU_MACHINE is deliberately unquoted: it holds several words
    # shellcheck disable=SC2086
    timeout "$vb_timeout" "$QEMU" $QEMU_MACHINE \
        -m 512M -smp 2 \
        -kernel "$vb_kernel" \
        -initrd "$vb_initrd" \
        -append "console=$CONSOLE rdinit=/init quiet panic=-1" \
        -nographic -no-reboot -monitor none >>"$vb_log" 2>&1
    VM_QEMU_RC=$?
    kill "$vb_tail" 2>/dev/null
    set -e
}

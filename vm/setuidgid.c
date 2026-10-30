/*
 * setuidgid UID CMD [ARGS...] -- test helper for vm/run.sh.
 *
 * Drops to a numeric uid/gid and execs, so the suites can check the
 * "works without root" claim from an unprivileged account.  Not part of
 * confmask; it exists because the initramfs busybox has no setuidgid.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: setuidgid UID CMD [ARGS...]\n");
        return 2;
    }
    uid_t u = (uid_t)strtoul(argv[1], NULL, 10);
    if (setgid((gid_t)u) != 0 || setuid(u) != 0) {
        perror("setuidgid");
        return 1;
    }
    execvp(argv[2], &argv[2]);
    perror("setuidgid: execvp");
    return 127;
}

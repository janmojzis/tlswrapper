/*
 * jail.c - privilege drop, chroot, and process hardening
 *
 * Provides the runtime jail used by the network-facing processes after
 * they finish privileged setup. The jail drops privileges to a target
 * account or a randomized numeric uid/gid, optionally chroots into an
 * empty directory, and applies conservative resource limits.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "log.h"
#include "randommod.h"
#include "jail.h"

/*
 * jail_limit_memory - best-effort cap of jailed process memory use
 *
 * @resource: RLIMIT_AS or RLIMIT_DATA selector
 * @name: resource name for logging
 * @limit: requested soft and hard cap in bytes
 *
 * Reads the current limit and lowers it to @limit when the inherited soft
 * limit is larger. Unsupported limits are ignored so the jail can still be
 * applied on platforms where the kernel advertises but does not enforce a
 * given resource.
 *
 * Returns 0 on success or when the limit is unsupported, and -1 on other
 * errors.
 */
static int jail_limit_memory(int resource, const char *name, rlim_t limit) {

    struct rlimit r;

    if (getrlimit(resource, &r) == -1) {
        if (errno == EINVAL) {
            log_t2("skipping unsupported ", name);
            return 0;
        }
        log_e2("unable to get ", name);
        return -1;
    }
    if (r.rlim_cur <= limit) return 0;
    r.rlim_cur = limit;
    if (r.rlim_max > limit) r.rlim_max = limit;
    if (setrlimit(resource, &r) == -1) {
        if (errno == EINVAL) {
            log_t2("skipping unsupported ", name);
            return 0;
        }
        log_e2("unable to set ", name);
        return -1;
    }

    log_t4("setrlimit ", name, " set to ", log_num(limit));
    return 0;
}

/*
 * jail - drop privileges and confine the current process
 *
 * @account: user name to switch to, or NULL to derive a randomized uid/gid
 * @dir: directory to chroot into, or NULL to skip chroot
 * @limits: non-zero to enable resource limits that forbid new files,
 *          processes, and core dumps
 *
 * Resolves the target uid/gid, switches the process credentials, and
 * updates supplementary groups. When @dir is set, the process changes
 * into that directory before chrooting to ".".
 *
 * When @account names a real system user, the function also exports the
 * standard HOME, SHELL, USER, and LOGNAME environment variables from the
 * passwd entry. With @limits enabled, the function applies restrictive
 * rlimits after privileged setup is complete.
 *
 * Security:
 *   - Drops gid before uid and initializes supplementary groups first.
 *   - Applies rlimits after chroot and credential changes where possible.
 *
 * Returns 0 on success and -1 on failure.
 */
int jail(const char *account, const char *dir, int limits) {

    int ret = -1;
    struct passwd *pw = 0;
    uid_t uid;
    gid_t gid;
    char *name = 0;
    char *shell = 0;
    char *home = 0;
#ifdef RLIM_INFINITY
    struct rlimit r;
    r.rlim_cur = 0;
    r.rlim_max = 0;
#endif

    if (!account) {
        gid = uid = 100000000 + 100000 * randommod(1000) + (getpid() % 100000);
    }
    else {
        pw = getpwnam(account);
        if (!pw) {
            log_e3("getpwnam for account '", account, "' failed");
            goto cleanup;
        }
        gid = pw->pw_gid;
        uid = pw->pw_uid;
        home = pw->pw_dir;
        name = pw->pw_name;
        shell = pw->pw_shell;
    }

    /* Switch the primary group before touching supplementary groups. */
    if (setgid(gid) == -1 || getgid() != gid) {
        log_e3("setgid(", log_num(gid), ") failed");
        goto cleanup;
    }

    /* Install supplementary groups for the target identity. */
    if (pw) {
        if (initgroups(name, gid) == -1) {
            log_e5("initgroups(", pw->pw_name, ", ", log_num(gid), ") failed");
            goto cleanup;
        }
    }
    else {
        if (setgroups(1, &gid) == -1) {
            log_e3("setgroups(1, [", log_num(gid), "]) failed");
            goto cleanup;
        }
    }

    /* Enter the caller-provided empty root, if requested. */
    if (dir) {
        if (chdir(dir) == -1) {
            log_e2("unable to change directory to ", dir);
            goto cleanup;
        }
        if (chroot(".") == -1) {
            log_e2("unable to chroot to ", dir);
            goto cleanup;
        }
        log_t2("chrooted into ", dir);
    }

    /* Drop the remaining user privileges after chroot setup. */
    if (setuid(uid) == -1 || getuid() != uid) {
        log_e3("setuid(", log_num(uid), ") failed");
        goto cleanup;
    }

    /*
     * Block creation of new descriptors after supplementary groups and
     * chroot are installed. initgroups() and chroot() may need to open
     * NSS databases or the new root directory, which requires a free FD
     * slot.
     */
#ifdef RLIMIT_NOFILE
    if (limits) {
        if (setrlimit(RLIMIT_NOFILE, &r) == -1) {
            log_e1("unable to set RLIMIT_NOFILE to 0");
            goto cleanup;
        }
    }
#endif

    if (pw) {
        if (setenv("HOME", home, 1) == -1) goto cleanup;
        if (setenv("SHELL", shell, 1) == -1) goto cleanup;
        if (setenv("USER", name, 1) == -1) goto cleanup;
        if (setenv("LOGNAME", name, 1) == -1) goto cleanup;
    }

    /* Prevent the jailed process from creating child processes. */
#ifdef RLIMIT_NPROC
    if (limits) {
        if (setrlimit(RLIMIT_NPROC, &r) == -1) {
            log_e1("unable to set RLIMIT_NPROC to 0");
            goto cleanup;
        }
    }
#endif

    /* Disable core dumps and mark the process as non-dumpable. */
#ifdef RLIMIT_CORE
    if (limits) {
        if (setrlimit(RLIMIT_CORE, &r) == -1) {
            log_e1("unable to set RLIMIT_CORE to 0");
            goto cleanup;
        }
    }
#endif
#ifdef PR_SET_DUMPABLE
    if (limits) {
        if (prctl(PR_SET_DUMPABLE, 0) == -1) {
            log_e1("unable to set prctl(PR_SET_DUMPABLE, 0)");
            goto cleanup;
        }
    }
#endif

    /* Cap the address space or data segment at 128 MiB when possible. */
#define DATAMAX 134217728
#ifdef RLIMIT_AS
    if (jail_limit_memory(RLIMIT_AS, "RLIMIT_AS", DATAMAX) == -1) {
        goto cleanup;
    }
#endif
#ifdef RLIMIT_DATA
    if (jail_limit_memory(RLIMIT_DATA, "RLIMIT_DATA", DATAMAX) == -1) {
        goto cleanup;
    }
#endif

    log_t4("running under uid = ", log_num(uid), ", gid = ", log_num(gid));

    ret = 0;

cleanup:

    log_t2("jail() = ", log_num(ret));

    return ret;
}

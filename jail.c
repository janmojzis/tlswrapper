/*
20201103
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "log.h"
#include "randommod.h"
#include "jail.h"

/*
The 'jail' function has 3 purposes:
1. drops root priviledges to unpriviledged uid/gid
  - if the 'account' is 0, then uid/gid is derived from process id and randomized.
  - if the 'account' is string and the account exist, then uid/gid
    is retrieved from the system user database.
2. chroots into an empty directory
3. sets resource limits
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

    log_t1("jail()");

    if (!account) {
        gid = uid = 100000000 + 100000 * randommod(1000) + (getpid() % 100000);
    }
    else {
        pw = getpwnam(account);
        if (!pw) {
            log_e3("getpwnam for account ", account, " failed");
            goto cleanup;
        }
        gid = pw->pw_gid;
        uid = pw->pw_uid;
        home = pw->pw_dir;
        name = pw->pw_name;
        shell = pw->pw_shell;
    }

/* prohibit new files, new sockets, etc. */
#ifdef RLIMIT_NOFILE
    if (limits) {
        if (setrlimit(RLIMIT_NOFILE, &r) == -1) {
            log_e1("unable to set RLIMIT_NOFILE to 0");
            goto cleanup;
        }
    }
#endif

    /* set gid */
    if (setgid(gid) == -1 || getgid() != gid) {
        log_e3("setgid(", lognum(gid),") failed");
        goto cleanup;
    }

    /* init groups */
    if (pw) {
        if (initgroups(name, gid) == -1) {
            log_e5("initgroups(", pw->pw_name, ", ", lognum(gid), ") failed");
            goto cleanup;
        }
    }
    else {
        if (setgroups(1, &gid) == -1) {
            log_e3("setgroups(1, [", lognum(gid), "]) failed");
            goto cleanup;
        }
    }

    /* chroot */
    if (dir) {
        if (chdir(dir) == -1) {
            log_e2("unable to change directory to ", dir);
            goto cleanup;
        }
        if (chroot(".") == -1) {
            log_e2("unable to chroot to ", dir);
            goto cleanup;
        }
        log_d2("chrooted into ", dir);
    }

    /* set uid */
    if (setuid(uid) == -1 || getuid() != uid) {
        log_e3("setuid(", lognum(uid), ") failed");
        goto cleanup;
    }

    if (pw) {
        if (setenv("HOME", home, 1) == -1) goto cleanup;
        if (setenv("SHELL", shell, 1) == -1) goto cleanup;
        if (setenv("USER", name, 1) == -1) goto cleanup;
        if (setenv("LOGNAME", name, 1) == -1) goto cleanup;
    }

/* prohibit fork */
#ifdef RLIMIT_NPROC
    if (limits) {
        if (setrlimit(RLIMIT_NPROC, &r) == -1) {
            log_e1("unable to set RLIMIT_NPROC to 0");
            goto cleanup;
        }
    }
#endif

/* prohibit core dumping */
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

    log_d4("running under uid = ", lognum(gid), ", gid = ", lognum(gid));

    ret = 0;

cleanup:

    log_t2("jail() = ", lognum(ret));

    return ret;
}

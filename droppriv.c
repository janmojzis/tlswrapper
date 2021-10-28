#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "droppriv.h"

int droppriv(const char *account) {

    struct passwd *pw;

    pw = getpwnam(account);
    if (!pw) { errno = ENOENT; return 0; }

    if (setgid(pw->pw_gid) == -1) return 0;
    if (getgid() != pw->pw_gid) { errno = EPERM; return 0; }
    if (initgroups(pw->pw_name, pw->pw_gid) == -1) return 0;
    if (setuid(pw->pw_uid) == -1) return 0;
    if (getuid() != pw->pw_uid) { errno = EPERM; return 0; }

    if (setenv("HOME", pw->pw_dir, 1) == -1) return 0;
    if (setenv("SHELL", pw->pw_shell, 1) == -1) return 0;
    if (setenv("USER", pw->pw_name, 1) == -1) return 0;
    if (setenv("LOGNAME", pw->pw_name, 1) == -1) return 0;

    return 1;
}

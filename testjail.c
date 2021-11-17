#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>
#include "log.h"
#include "jail.h"


static int run(void (*op)(void)) {
    pid_t pid;
    int status;

    pid = fork();
    if (pid == -1) return 222;
    if (pid == 0) {
        op();
    }
    while (waitpid(pid, &status, 0) != pid) {};
    if (!WIFEXITED(status)) return 222;
    return WEXITSTATUS(status);
}

void detectshortgroup(void) {
    short x[4];

    x[0] = x[1] = 1;
    if (getgroups(1, (gid_t *) x) == 0) if (setgroups(1, (gid_t *) x) == -1) _exit(1);

    if (getgroups(1, (gid_t *) x) == -1) _exit(1);
    if (x[1] != 1) _exit(1);
    x[1] = 2;
    if (getgroups(1, (gid_t *) x) == -1) _exit(1);
    if (x[1] != 2) _exit(1);
    _exit(0);
}

void testjail1(void) {

    if (geteuid() == 0) {
        if (jail(0, ".", 1) != 0) _exit(111);
    }
    _exit(0);
}

void testjail2(void) {

    if (geteuid() == 0) {
        if (jail("nobody", ".", 1) != 0) _exit(111);
    }
    _exit(0);
}


int main() {

    log_level(4);
    log_name("testjail");


    if (run(detectshortgroup) == 0) {
        log_w1("testjail1 skipped: shortgoup detected");
    }
    else {
        log_i1("testjail1");
        if (run(testjail1) != 0) return 111;
    }

    log_i1("testjail2");
    if (run(testjail2) != 0) return 111;

    _exit(0);

}

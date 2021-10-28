#include <sys/resource.h>
#include <unistd.h>
#include <sys/wait.h>
#include "alloc.h"
#include "log.h"


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

void alloc0(void) {
    unsigned char *x = alloc(0);
    if (!x) _exit(222);
    _exit(0);
}

void alloc1(void) {
    unsigned char *x = alloc(1);
    if (!x) _exit(222);
    _exit(0);
}

void allocmalloc(void) {
    unsigned char *x;
    x = alloc(alloc_STATICSPACE);
    if (!x) _exit(222);
    x = alloc(0);
    _exit(0);
}

void alloclimit(void) {
    unsigned char *x = alloc((unsigned long long) alloc_LIMIT + 1ULL);
    if (!x) _exit(222);
    _exit(0);
}

void alloc32bit(void) {
    unsigned char *x;

    if (sizeof(size_t) != 4) _exit(111);
    x = alloc(4294967295ULL + 1ULL);
    if (!x) _exit(222);
    _exit(0);
}

void alloclonglongoverflow(void) {
    unsigned char *x = alloc((unsigned long long)-1LL);
    if (!x) _exit(222);
    _exit(0);
}

void allocfree(void) {
    unsigned char *x;

    alloc_free(0);
    alloc_freeall();
    alloc_freeall();
    
    x = alloc(alloc_STATICSPACE);
    if (!x) _exit(222);
    alloc_free(x);
    x = alloc(1);
    if (!x) _exit(222);
    alloc_free(x);
    x = alloc(1);
    if (!x) _exit(222);

    alloc_freeall();
    alloc_freeall();

    _exit(0);
}


int main() {

    log_level(4);
    log_name("testalloc");

    log_i1("alloc0");
    if (run(alloc0) != 0) return 111;
    log_i1("alloc1");
    if (run(alloc1) != 0) return 111;
    log_i1("allocmalloc");
    if (run(allocmalloc) != 0) return 111;
    log_i1("alloclimit");
    if (run(alloclimit) != 111) return 111;
    log_i1("alloc32bit");
    if (run(alloc32bit) != 111) return 111;
    log_i1("alloclonglongoverflow");
    if (run(alloclonglongoverflow) != 111) return 111;
    log_i1("allocfree");
    if (run(allocfree) != 0) return 111;


    return 0;
}

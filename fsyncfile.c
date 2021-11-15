/*
20130115
Jan Mojzis
Public domain.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fsyncfile.h"

/*
The 'fsyncfile(fd)' calls fsync when file-descriptor is regular file.
*/
int fsyncfile(int fd) {

    struct stat st;

    if (fstat(fd, &st) == -1) return -1;
    if (!S_ISREG(st.st_mode)) return 0;
    return fsync(fd);
}
